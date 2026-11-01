//! The two MCP tools this plugin registers: `rx_data_find` and `rx_multi_find`.
//!
//! `rx_data_find` mirrors the Python plugin's `rex_data_find` contract exactly
//! (result shape, pagination, error codes) so the two can be benchmarked
//! head-to-head; only the scan itself is native Rust. `rx_multi_find` is the
//! new capability: many patterns in one pass over the bytes.

use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;

use binaryninja::binary_view::{BinaryView, BinaryViewBase};
use binaryninja::mcp::tool::{
    McpToolAnnotations, McpToolCall, McpToolError, McpToolInfo, McpToolResult, TypedMcpTool,
    register_typed_mcp_tool,
};

use crate::hexpattern::{HexPattern, MAX_PATTERN_CHARS, TRUNCATE_CHARS, truncate_echo};
use crate::multi::{MAX_MULTI_PATTERNS, MultiMatcher};
use crate::scan::{Pagination, RunningScan, scan_pattern};

/// `rex_data_find`'s limit cap.
const MAX_LIMIT: u64 = 500;

/// Window-read size cap, matching `_READ_CHUNK` in the Python plugin: reads
/// are chunked so no single read ever allocates the whole segment.
const READ_CHUNK: u64 = 4 * 1024 * 1024;

fn default_limit() -> u32 {
    50
}

/// Arguments of `rx_data_find`, mirroring `rex_data_find`.
///
/// No `binary` field: `binary` is a server-reserved argument for BinaryView-scoped
/// tools — `BNRegisterMcpTool` rejects a schema that declares it, and the server
/// strips it before invoking the handler (verified live). `require_binary_view`
/// resolves the view from the tool call itself.
#[derive(Deserialize, JsonSchema)]
pub struct DataFindArgs {
    /// Hex byte pattern, e.g. "48 8b ?? 05"; "??" matches any single byte.
    #[schemars(length(max = 8192))]
    pub pattern: String,
    /// Only search within this section.
    #[serde(default)]
    pub section: Option<String>,
    /// Maximum number of matches to return (0 to 500).
    #[serde(default = "default_limit")]
    #[schemars(range(min = 0, max = 500))]
    pub limit: u32,
    /// Number of matches to skip before collecting results (>= 0).
    #[serde(default)]
    #[schemars(range(min = 0))]
    pub offset: u64,
}

/// Arguments of `rx_multi_find`. No `binary` field — same server-reserved
/// argument rule as `DataFindArgs`.
#[derive(Deserialize, JsonSchema)]
pub struct MultiFindArgs {
    /// Hex byte patterns, e.g. ["48 8b ?? 05", "e8 ?? ?? ?? ??"]; "??" matches any single byte.
    #[schemars(length(min = 1, max = 64))]
    pub patterns: Vec<String>,
    /// Only search within this section.
    #[serde(default)]
    pub section: Option<String>,
    /// Maximum number of matches per pattern to return (0 to 500).
    #[serde(default = "default_limit")]
    #[schemars(range(min = 0, max = 500))]
    pub limit: u32,
    /// Number of matches to skip per pattern before collecting results (>= 0).
    #[serde(default)]
    #[schemars(range(min = 0))]
    pub offset: u64,
}

fn invalid_param(name: &str, requirement: &str) -> McpToolError {
    McpToolError::invalid_params(format!("Invalid integer parameter '{name}': {requirement}"))
}

/// Validate `limit`/`offset` like the Python plugin's `_validate_range`; the
/// schema already rejects these for typed calls, this keeps direct invocation
/// identical and covers the unsigned-unreachable lower bounds explicitly.
fn validate_pagination(limit: u32, offset: u64) -> Result<Pagination, McpToolError> {
    let limit = u64::from(limit);
    if limit > MAX_LIMIT {
        return Err(invalid_param(
            "limit",
            &format!("Must be at most {MAX_LIMIT}"),
        ));
    }
    Ok(Pagination { offset, limit })
}

fn parse_checked_pattern(pattern: &str) -> Result<HexPattern, McpToolError> {
    // Length in characters, matching the Python plugin's len() check.
    if pattern.chars().count() > MAX_PATTERN_CHARS {
        return Err(McpToolError::new(
            "pattern_too_large",
            format!("pattern exceeds {MAX_PATTERN_CHARS} characters"),
        ));
    }
    HexPattern::parse(pattern).map_err(|error| McpToolError::new("invalid_pattern", error.message))
}

/// Resolve the optional section name to inclusive-exclusive bounds, mirroring
/// the Python plugin's `_resolve_section` including its error text.
fn resolve_bounds(
    view: &BinaryView,
    section: &Option<String>,
) -> Result<Option<(u64, u64)>, McpToolError> {
    let Some(name) = section else {
        return Ok(None);
    };
    match view.section_by_name(name) {
        Some(section) => Ok(Some((section.start(), section.end()))),
        None => Err(section_not_found_error(name)),
    }
}

/// The `section_not_found` error with the Python plugin's exact text, echo
/// truncated like its `_truncate` does.
fn section_not_found_error(name: &str) -> McpToolError {
    McpToolError::new(
        "section_not_found",
        format!("no section named '{}'", truncate_echo(name, TRUNCATE_CHARS)),
    )
}

/// Clip a segment's address range to the optional section bounds; `None` when
/// nothing remains (the Python loop's `seg_start >= seg_end` skip).
fn clamp_to_bounds(range: (u64, u64), bounds: Option<(u64, u64)>) -> Option<(u64, u64)> {
    let (start, end) = match bounds {
        None => range,
        Some((low, high)) => (range.0.max(low), range.1.min(high)),
    };
    (start < end).then_some((start, end))
}

/// Walk `[start, end)` in overlapping read windows, mirroring the Python
/// plugin's chunked-read loop in `rex_data_find`
/// (src/binja_plugin/tools.py:279-296).
///
/// Invariant re-derived from that loop: window k reads
/// `[start + k*chunk, min(start + k*chunk + chunk + overlap, end))` and
/// `position` advances by `chunk` unconditionally — the windows depend only on
/// `(start, end, chunk, overlap)`, never on what the reads return. Consecutive
/// windows overlap by exactly `overlap` bytes, so every (`overlap + 1`)-byte
/// match whose start address lies in window k is fully visible in window k, and
/// every match start belongs to exactly one window: no match is missed and none
/// is reported twice. Advancing past short or empty reads (unreadable holes) is
/// what recovers matches located after the hole.
///
/// `overlap` is the scan's pattern length minus one (the longest pattern's, for
/// the multi-pattern scan). `window(position, read_size)` returns `false` to
/// stop the walk early.
fn for_each_window<F>(start: u64, end: u64, chunk: u64, overlap: u64, mut window: F) -> bool
where
    F: FnMut(u64, u64) -> bool,
{
    let mut position = start;
    while position < end {
        let read_size = (chunk + overlap).min(end - position);
        if !window(position, read_size) {
            return false;
        }
        position = match position.checked_add(chunk) {
            Some(next) => next,
            None => break,
        };
    }
    true
}

/// The view surface the chunked segment walk needs: mapped ranges plus bounded
/// reads. A local seam so tests can drive `for_each_segment` itself — the
/// `BinaryView` FFI cannot run outside the core, and a test-local copy of the
/// composition would drift from the wiring it claims to cover.
trait ChunkedReadView {
    /// Ascending, non-overlapping readable address ranges.
    fn segment_ranges(&self) -> Vec<(u64, u64)>;
    /// Fill `buffer` from `position`, returning the bytes actually read —
    /// fewer than requested (or none) at an unreadable hole.
    fn read_into(&self, buffer: &mut [u8], position: u64) -> usize;
}

impl ChunkedReadView for BinaryView {
    fn segment_ranges(&self) -> Vec<(u64, u64)> {
        self.segments()
            .iter()
            .map(|segment| {
                let range = segment.address_range();
                (range.start, range.end)
            })
            .collect()
    }

    fn read_into(&self, buffer: &mut [u8], position: u64) -> usize {
        BinaryViewBase::read(self, buffer, position)
    }
}

/// Read every mapped segment (clipped to `bounds`) through the chunked window
/// walk and run `step` over each window's bytes in address order. `step`
/// receives the window's base address and the bytes actually read, which may be
/// shorter than requested (or empty) when the core hits an unreadable hole.
fn for_each_segment<V: ChunkedReadView, F>(
    view: &V,
    chunk: u64,
    bounds: Option<(u64, u64)>,
    overlap: u64,
    mut step: F,
) -> bool
where
    F: FnMut(u64, &[u8]) -> bool,
{
    // One reusable buffer for the largest possible window, allocated once per
    // scan — never the whole segment (a multi-GB segment must not allocate).
    let mut buffer = vec![0u8; usize::try_from(chunk + overlap).unwrap_or(usize::MAX)];
    for (start, end) in view.segment_ranges() {
        let Some((start, end)) = clamp_to_bounds((start, end), bounds) else {
            continue;
        };
        let alive = for_each_window(start, end, chunk, overlap, |position, read_size| {
            let read_size = read_size as usize;
            let size = view.read_into(&mut buffer[..read_size], position);
            step(position, &buffer[..size])
        });
        if !alive {
            return false;
        }
    }
    true
}

fn matches_json(matches: &[u64]) -> serde_json::Value {
    json!(
        matches
            .iter()
            .map(|address| format!("{address:#x}"))
            .collect::<Vec<_>>()
    )
}

/// `rx_data_find`: same contract as the Python plugin's `rex_data_find`, with
/// the byte scan running in native Rust behind a SIMD memchr prefilter.
struct RxDataFind;

impl TypedMcpTool for RxDataFind {
    type Args = DataFindArgs;

    fn info(&self) -> McpToolInfo {
        McpToolInfo::new(
            "rx_data_find",
            "Find all occurrences of a hex byte pattern in mapped memory. \
             The scan runs in native Rust (SIMD prefilter + wildcard verification); \
             result shape and pagination match the Python plugin's rex_data_find.",
        )
        .with_annotations(McpToolAnnotations::READ_ONLY)
    }

    fn invoke(
        &self,
        call: &McpToolCall,
        args: DataFindArgs,
    ) -> Result<McpToolResult, McpToolError> {
        // View resolution first, matching the Python handler's order
        // (bv = call.binary_view before any validation).
        let view = call.require_binary_view()?;
        let pagination = validate_pagination(args.limit, args.offset)?;
        let pattern = parse_checked_pattern(&args.pattern)?;
        let bounds = resolve_bounds(&view, &args.section)?;
        let overlap = pattern.len().saturating_sub(1) as u64;
        let mut running = RunningScan::new();
        for_each_segment(&*view, READ_CHUNK, bounds, overlap, |base, data| {
            scan_pattern(data, base, &pattern, &pagination, &mut running)
        });
        Ok(McpToolResult::structured(json!({
            "total": running.total,
            "truncated": running.truncated,
            "matches": matches_json(&running.matches),
        })))
    }
}

/// `rx_multi_find`: many hex patterns in one pass over the bytes via a
/// multi-pattern automaton — the capability the Python plugin cannot offer.
struct RxMultiFind;

impl TypedMcpTool for RxMultiFind {
    type Args = MultiFindArgs;

    fn info(&self) -> McpToolInfo {
        McpToolInfo::new(
            "rx_multi_find",
            "Find occurrences of many hex byte patterns in one pass over mapped memory. \
             A single multi-pattern automaton scan replaces N sequential rex_data_find calls; \
             each pattern gets its own rex_data_find-style match list with the same \
             limit/offset pagination and truncated flag.",
        )
        .with_annotations(McpToolAnnotations::READ_ONLY)
    }

    fn invoke(
        &self,
        call: &McpToolCall,
        args: MultiFindArgs,
    ) -> Result<McpToolResult, McpToolError> {
        if args.patterns.is_empty() {
            return Err(McpToolError::invalid_params(
                "at least one pattern is required",
            ));
        }
        if args.patterns.len() > MAX_MULTI_PATTERNS {
            return Err(McpToolError::new(
                "too_many_patterns",
                format!("at most {MAX_MULTI_PATTERNS} patterns are allowed"),
            ));
        }
        let pagination = validate_pagination(args.limit, args.offset)?;
        let patterns = args
            .patterns
            .iter()
            .enumerate()
            .map(|(index, text)| {
                parse_checked_pattern(text).map_err(|error| prefix_pattern_error(index, error))
            })
            .collect::<Result<Vec<_>, McpToolError>>()?;
        let view = call.require_binary_view()?;
        let bounds = resolve_bounds(&view, &args.section)?;
        let matcher = MultiMatcher::new(&patterns);
        let mut buckets: Vec<RunningScan> =
            (0..patterns.len()).map(|_| RunningScan::new()).collect();
        // Windows must stay visible for the longest pattern: a shorter overlap
        // would drop that pattern's matches straddling a chunk edge.
        let longest = patterns
            .iter()
            .map(|pattern| pattern.len())
            .max()
            .unwrap_or(1);
        let overlap = longest.saturating_sub(1) as u64;
        for_each_segment(&*view, READ_CHUNK, bounds, overlap, |base, data| {
            matcher.scan_segment(data, base, &patterns, &mut buckets, &pagination)
        });
        let results = args
            .patterns
            .iter()
            .zip(buckets.iter())
            .map(|(text, bucket)| {
                json!({
                    "pattern": text,
                    "total": bucket.total,
                    "truncated": bucket.truncated,
                    "matches": matches_json(&bucket.matches),
                })
            })
            .collect::<Vec<_>>();
        Ok(McpToolResult::structured(json!({
            "total": buckets.iter().map(|bucket| bucket.total).sum::<u64>(),
            "truncated": buckets.iter().any(|bucket| bucket.truncated),
            "results": results,
        })))
    }
}

/// Multi-pattern parse failures name the offending entry.
fn prefix_pattern_error(index: usize, error: McpToolError) -> McpToolError {
    let (code, message) = (error.code, error.message);
    McpToolError::new(code, format!("pattern {index}: {message}"))
}

/// Register both tools; returns false when the core rejects a definition.
pub fn register() -> bool {
    register_typed_mcp_tool(RxDataFind).is_some() && register_typed_mcp_tool(RxMultiFind).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multi::MultiMatcher;

    #[test]
    fn pagination_rejects_over_limit() {
        let error = validate_pagination(501, 0).unwrap_err();
        assert_eq!(error.code, "invalid_params");
        assert_eq!(
            error.message,
            "Invalid integer parameter 'limit': Must be at most 500"
        );
        assert!(validate_pagination(500, 0).is_ok());
        assert!(validate_pagination(0, 0).is_ok());
    }

    #[test]
    fn pattern_size_and_parse_errors() {
        let long = "48 ".repeat(2731); // 8193 chars after trim
        let error = parse_checked_pattern(&long).unwrap_err();
        assert_eq!(error.code, "pattern_too_large");
        assert_eq!(error.message, "pattern exceeds 8192 characters");

        let error = parse_checked_pattern("48 zz").unwrap_err();
        assert_eq!(error.code, "invalid_pattern");
        assert_eq!(error.message, "invalid hex byte token 'zz'");

        let error = parse_checked_pattern("").unwrap_err();
        assert_eq!(error.code, "invalid_pattern");
        assert_eq!(error.message, "empty hex pattern");
    }

    #[test]
    fn multi_parse_errors_name_the_pattern_index() {
        let error = parse_checked_pattern("48 zz")
            .map_err(|e| prefix_pattern_error(2, e))
            .unwrap_err();
        assert_eq!(error.code, "invalid_pattern");
        assert_eq!(error.message, "pattern 2: invalid hex byte token 'zz'");
    }

    // --- segment iteration: FakeView standing in for the FFI view -----------

    /// A tiny stand-in for BinaryView: ascending, non-overlapping readable
    /// runs. A read returns the contiguous bytes available from `position`
    /// inside the run it starts in — the short or empty read an unreadable
    /// hole produces.
    struct FakeView {
        segments: Vec<(u64, u64)>,
        runs: Vec<(u64, Vec<u8>)>,
    }

    impl ChunkedReadView for FakeView {
        fn segment_ranges(&self) -> Vec<(u64, u64)> {
            self.segments.clone()
        }

        fn read_into(&self, buffer: &mut [u8], position: u64) -> usize {
            for (start, bytes) in &self.runs {
                let run_end = *start + bytes.len() as u64;
                if position >= *start && position < run_end {
                    let offset = (position - start) as usize;
                    let taken = bytes.len().min(offset + buffer.len());
                    let copied = taken - offset;
                    buffer[..copied].copy_from_slice(&bytes[offset..taken]);
                    return copied;
                }
            }
            0
        }
    }

    /// Drive the production `for_each_segment` — clamp_to_bounds +
    /// for_each_window + the reusable read buffer — with FakeView standing in
    /// for the BinaryView FFI, which cannot run in tests.
    fn scan_fake_view(
        view: &FakeView,
        chunk: u64,
        bounds: Option<(u64, u64)>,
        overlap: u64,
        pattern: &HexPattern,
        pagination: &Pagination,
    ) -> RunningScan {
        let mut running = RunningScan::new();
        for_each_segment(view, chunk, bounds, overlap, |base, data| {
            scan_pattern(data, base, pattern, pagination, &mut running)
        });
        running
    }

    #[test]
    fn windows_advance_by_chunk_with_overlap_tail() {
        let mut windows = Vec::new();
        assert!(for_each_window(
            0x1000,
            0x1008,
            4,
            1,
            |position, read_size| {
                windows.push((position, read_size));
                true
            }
        ));
        // Each window extends overlap bytes past its chunk; the walk ends when
        // position reaches the segment end.
        assert_eq!(windows, vec![(0x1000, 5), (0x1004, 4)]);

        let mut windows = Vec::new();
        assert!(for_each_window(
            0x1000,
            0x1008,
            4,
            0,
            |position, read_size| {
                windows.push((position, read_size));
                true
            }
        ));
        assert_eq!(windows, vec![(0x1000, 4), (0x1004, 4)]);
    }

    #[test]
    fn window_walk_stops_when_the_scan_is_exhausted() {
        let mut visited = Vec::new();
        assert!(!for_each_window(0, 100, 4, 0, |position, _| {
            visited.push(position);
            false
        }));
        assert_eq!(visited, vec![0]);
    }

    #[test]
    fn clamp_to_bounds_clamps_and_drops_empty_ranges() {
        assert_eq!(
            clamp_to_bounds((0x1000, 0x2000), None),
            Some((0x1000, 0x2000))
        );
        // Section strictly inside the segment: both sides clamp.
        assert_eq!(
            clamp_to_bounds((0x1000, 0x2000), Some((0x1002, 0x1006))),
            Some((0x1002, 0x1006))
        );
        // Section larger than the segment: the segment wins on both sides.
        assert_eq!(
            clamp_to_bounds((0x1000, 0x2000), Some((0, 0x10000))),
            Some((0x1000, 0x2000))
        );
        // Disjoint section and segment: nothing to scan.
        assert_eq!(
            clamp_to_bounds((0x1000, 0x2000), Some((0x3000, 0x4000))),
            None
        );
        // Section starting exactly at the segment end: empty.
        assert_eq!(
            clamp_to_bounds((0x1000, 0x2000), Some((0x2000, 0x3000))),
            None
        );
    }

    #[test]
    fn section_not_found_error_text_and_truncation() {
        let error = section_not_found_error(".text");
        assert_eq!(error.code, "section_not_found");
        assert_eq!(error.message, "no section named '.text'");

        let long = "a".repeat(600);
        let error = section_not_found_error(&long);
        assert_eq!(
            error.message,
            format!(
                "no section named '{}... [88 chars truncated]'",
                "a".repeat(512)
            )
        );
    }

    #[test]
    fn finds_matches_across_chunk_boundaries() {
        // Python test_data_find_finds_matches_across_chunk_boundaries analog.
        let view = FakeView {
            segments: vec![(0x1000, 0x1008)],
            runs: vec![(0x1000, b"\x00\x00\x33\xeb\x00\x00\x33\xeb".to_vec())],
        };
        let pattern = HexPattern::parse("33 eb").unwrap();
        let page = Pagination {
            offset: 0,
            limit: 50,
        };
        let running = scan_fake_view(&view, 4, None, 1, &pattern, &page);
        assert_eq!(running.total, 2);
        assert_eq!(running.matches, vec![0x1002, 0x1006]);
    }

    /// Python test_data_find_matches_straddling_chunk_boundaries analog: a
    /// match straddling the chunk edge is visible only because each window
    /// extends pattern_length - 1 bytes past the chunk, and a match starting
    /// exactly at the edge is reported once because every match start belongs
    /// to exactly one window.
    #[test]
    fn straddling_and_boundary_matches_are_found_exactly_once() {
        let pattern = HexPattern::parse("33 eb").unwrap();
        let page = Pagination {
            offset: 0,
            limit: 50,
        };
        let straddle = FakeView {
            segments: vec![(0x1000, 0x1008)],
            runs: vec![(0x1000, b"\x00\x00\x00\x33\xeb\x00\x00\x00".to_vec())],
        };
        let running = scan_fake_view(&straddle, 4, None, 1, &pattern, &page);
        assert_eq!(running.total, 1);
        assert_eq!(running.matches, vec![0x1003]);

        let boundary = FakeView {
            segments: vec![(0x1000, 0x1008)],
            runs: vec![(0x1000, b"\x00\x00\x00\x00\x33\xeb\x00\x00".to_vec())],
        };
        let running = scan_fake_view(&boundary, 4, None, 1, &pattern, &page);
        assert_eq!(running.total, 1);
        assert_eq!(running.matches, vec![0x1004]);
    }

    /// Short and empty window reads (unreadable holes) must not stall or
    /// misalign the walk: the position advances to the next chunk boundary
    /// regardless, so matches after the hole are recovered — the Python loop's
    /// behavior (tools.py:282-294), which the old whole-segment read dropped
    /// entirely.
    #[test]
    fn recovers_matches_after_short_and_empty_reads() {
        let view = FakeView {
            segments: vec![(0x2000, 0x2010)],
            runs: vec![
                (0x2000, b"\x90\x90".to_vec()), // short read: 2 of 5 requested
                (0x2008, b"\x33\xeb".to_vec()), // match after the hole
            ],
        };
        let pattern = HexPattern::parse("33 eb").unwrap();
        let page = Pagination {
            offset: 0,
            limit: 50,
        };
        let running = scan_fake_view(&view, 4, None, 1, &pattern, &page);
        assert_eq!(running.total, 1);
        assert_eq!(running.matches, vec![0x2008]);
    }

    /// The multi-pattern walk overlaps windows by the LONGEST pattern minus
    /// one: a per-pattern shorter overlap would drop the longer pattern's
    /// match straddling a chunk edge.
    #[test]
    fn multi_walk_overlaps_by_the_longest_pattern() {
        let patterns = vec![
            HexPattern::parse("33 eb").unwrap(),
            HexPattern::parse("33 eb 00").unwrap(),
        ];
        let matcher = MultiMatcher::new(&patterns);
        let mut buckets = vec![RunningScan::new(), RunningScan::new()];
        let view = FakeView {
            segments: vec![(0x1000, 0x1008)],
            runs: vec![(0x1000, b"\x00\x00\x00\x33\xeb\x00\x00\x00".to_vec())],
        };
        let page = Pagination {
            offset: 0,
            limit: 50,
        };
        let overlap = patterns.iter().map(|p| p.len()).max().unwrap_or(1) as u64 - 1;
        let alive = for_each_segment(&view, 4, None, overlap, |base, data| {
            matcher.scan_segment(data, base, &patterns, &mut buckets, &page)
        });
        assert!(alive);
        assert_eq!(buckets[0].matches, vec![0x1003]);
        assert_eq!(buckets[1].matches, vec![0x1003]);
    }

    /// The overlap that protects the longest pattern re-exposes the seam zone
    /// of every window in its successor: a shorter pattern's match starting
    /// there is fully visible in two consecutive windows and must still be
    /// counted once per bucket — the per-pattern `rex_data_find` contract the
    /// multi result promises. Regression: '33 eb' starting exactly at the
    /// 0x1004 seam was recorded in window 0 and again in window 1.
    #[test]
    fn multi_seam_matches_of_shorter_patterns_are_counted_once() {
        let patterns = vec![
            HexPattern::parse("33 eb").unwrap(),
            HexPattern::parse("33 eb 00").unwrap(),
        ];
        let matcher = MultiMatcher::new(&patterns);
        let mut buckets = vec![RunningScan::new(), RunningScan::new()];
        // Seam at 0x1004 (chunk 4, overlap longest-1 = 2): '33 eb' starts
        // exactly on it, so windows 0 and 1 both see it whole; 0x1009 is a
        // control that only window 2 covers. The 3-byte pattern's matches at
        // the same addresses fit one window each.
        let view = FakeView {
            segments: vec![(0x1000, 0x1010)],
            runs: vec![(
                0x1000,
                b"\x00\x00\x00\x00\x33\xeb\x00\x00\x00\x33\xeb\x00\x00\x00\x00\x00".to_vec(),
            )],
        };
        let page = Pagination {
            offset: 0,
            limit: 50,
        };
        let overlap = patterns.iter().map(|p| p.len()).max().unwrap_or(1) as u64 - 1;
        let alive = for_each_segment(&view, 4, None, overlap, |base, data| {
            matcher.scan_segment(data, base, &patterns, &mut buckets, &page)
        });
        assert!(alive);
        assert_eq!(buckets[0].matches, vec![0x1004, 0x1009]);
        assert_eq!(buckets[0].total, 2);
        assert!(!buckets[0].truncated);
        assert_eq!(buckets[1].matches, vec![0x1004, 0x1009]);
        assert_eq!(buckets[1].total, 2);
        assert!(!buckets[1].truncated);
    }

    #[test]
    fn pattern_of_exactly_the_cap_is_accepted() {
        // Python test_data_find_rejects_oversized_pattern boundary analog:
        // exactly 8192 characters pass, one more is rejected.
        let at_cap = "90".repeat(MAX_PATTERN_CHARS / 2);
        assert_eq!(at_cap.chars().count(), MAX_PATTERN_CHARS);
        let pattern = parse_checked_pattern(&at_cap).unwrap();
        assert_eq!(pattern.len(), MAX_PATTERN_CHARS / 2);

        let over = "90".repeat(MAX_PATTERN_CHARS / 2 + 1);
        let error = parse_checked_pattern(&over).unwrap_err();
        assert_eq!(error.code, "pattern_too_large");
        assert_eq!(error.message, "pattern exceeds 8192 characters");
    }

    #[test]
    fn limit_at_the_cap_through_the_scan_path() {
        // Python test_data_find_caps_limit analog: exactly at the cap the
        // limit is honored through the real chunked scan (production
        // READ_CHUNK), and the scan stops one match past the window.
        let view = FakeView {
            segments: vec![(0x1000, 0x1000 + 600)],
            runs: vec![(0x1000, vec![0x90; 600])],
        };
        let pattern = HexPattern::parse("90").unwrap();
        let page = Pagination {
            offset: 0,
            limit: 500,
        };
        let running = scan_fake_view(&view, READ_CHUNK, None, 0, &pattern, &page);
        assert_eq!(running.matches.len(), 500);
        assert_eq!(running.total, 501);
        assert!(running.truncated);
        assert_eq!(running.matches[0], 0x1000);
        assert_eq!(running.matches[499], 0x1000 + 499);
    }

    /// Python test_data_find_pages_tile_the_full_result analog (seeded LCG, no
    /// rand dependency): consecutive pages (limit 2, offset 0, 2, 4, ...)
    /// reproduce the full untruncated result with no gaps or duplicates, and
    /// every page carries the expected slice, total, and truncated flag.
    #[test]
    fn pages_tile_the_full_result() {
        let mut lcg: u64 = 0x7a11_1a11;
        let mut next = move || {
            lcg = lcg
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (lcg >> 33) as u32
        };
        for case in 0..32u32 {
            let blob_len = (next() % 48) as usize;
            let blob: Vec<u8> = (0..blob_len).map(|_| (next() % 4) as u8).collect();
            let segment = (0x2000, 0x2000 + (blob_len.max(1)) as u64);
            let view = FakeView {
                segments: vec![segment],
                runs: vec![(0x2000, blob)],
            };
            let pat_len = 1 + (next() % 3) as usize;
            let tokens: Vec<String> = (0..pat_len)
                .map(|_| {
                    if next() % 3 == 0 {
                        "??".to_string()
                    } else {
                        format!("{:02x}", next() % 4)
                    }
                })
                .collect();
            let pattern = HexPattern::parse(&tokens.join(" ")).unwrap();
            let overlap = (pattern.len() - 1) as u64;

            let full_page = Pagination {
                offset: 0,
                limit: 500,
            };
            let full = scan_fake_view(&view, 4, None, overlap, &pattern, &full_page);
            assert!(!full.truncated, "case {case}");
            assert_eq!(full.matches.len() as u64, full.total, "case {case}");
            let true_total = full.total;

            let mut tiled = Vec::new();
            for page_offset in (0..=true_total).step_by(2) {
                let page = scan_fake_view(
                    &view,
                    4,
                    None,
                    overlap,
                    &pattern,
                    &Pagination {
                        offset: page_offset,
                        limit: 2,
                    },
                );
                tiled.extend(page.matches);
            }
            assert_eq!(tiled, full.matches, "case {case}");

            // Every offset pages the exact expected slice.
            for page_offset in 0..=true_total {
                let page = scan_fake_view(
                    &view,
                    4,
                    None,
                    overlap,
                    &pattern,
                    &Pagination {
                        offset: page_offset,
                        limit: 2,
                    },
                );
                let expected: Vec<u64> = full
                    .matches
                    .iter()
                    .skip(page_offset as usize)
                    .take(2)
                    .copied()
                    .collect();
                assert_eq!(page.matches, expected, "case {case} offset {page_offset}");
                assert_eq!(
                    page.total,
                    true_total.min(page_offset.saturating_add(3)),
                    "case {case} offset {page_offset}"
                );
                assert_eq!(
                    page.truncated,
                    true_total > page_offset + 2,
                    "case {case} offset {page_offset}"
                );
            }

            // An arbitrary adversarial (but valid) limit/offset pair.
            let limit = (next() % 501) as u64;
            let offset = ((next() as u64) << 32) | next() as u64;
            let page = scan_fake_view(
                &view,
                4,
                None,
                overlap,
                &pattern,
                &Pagination { offset, limit },
            );
            let expected: Vec<u64> = full
                .matches
                .iter()
                .skip(offset as usize)
                .take(limit as usize)
                .copied()
                .collect();
            assert_eq!(page.matches, expected, "case {case}");
            assert_eq!(
                page.total,
                true_total.min(offset.saturating_add(limit).saturating_add(1)),
                "case {case}"
            );
            assert_eq!(
                page.truncated,
                true_total > offset.saturating_add(limit),
                "case {case}"
            );
        }
    }
}
