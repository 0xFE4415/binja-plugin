//! The two MCP tools this plugin registers: `rx_data_find` and `rx_multi_find`.
//!
//! `rx_data_find` mirrors the Python plugin's `rex_data_find` contract exactly
//! (result shape, pagination, error codes) so the two can be benchmarked
//! head-to-head; only the scan itself is native Rust. `rx_multi_find` is the
//! new capability: many patterns in one pass over the bytes.

use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;

use binaryninja::binary_view::BinaryView;
use binaryninja::mcp::tool::{
    McpToolAnnotations, McpToolCall, McpToolError, McpToolInfo, McpToolResult, TypedMcpTool,
    register_typed_mcp_tool,
};

use crate::hexpattern::{HexPattern, MAX_PATTERN_CHARS, TRUNCATE_CHARS, truncate_echo};
use crate::multi::{MAX_MULTI_PATTERNS, MultiMatcher};
use crate::scan::{Pagination, RunningScan, scan_pattern};

/// `rex_data_find`'s limit cap.
const MAX_LIMIT: u64 = 500;

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
        None => Err(McpToolError::new(
            "section_not_found",
            format!("no section named '{}'", truncate_echo(name, TRUNCATE_CHARS)),
        )),
    }
}

/// Read every mapped segment (clipped to `bounds`) and run `step` over its
/// bytes in segment order. `step(base_address, bytes)` returns `false` to stop
/// the walk early; the byte vector may be shorter than the segment range if the
/// core returns fewer bytes than requested.
fn for_each_segment<F>(view: &BinaryView, bounds: Option<(u64, u64)>, mut step: F) -> bool
where
    F: FnMut(u64, &[u8]) -> bool,
{
    for segment in &view.segments() {
        let range = segment.address_range();
        let (start, end) = match bounds {
            None => (range.start, range.end),
            Some((low, high)) => (range.start.max(low), range.end.min(high)),
        };
        if start >= end {
            continue;
        }
        let data = view.read_vec(start, usize::try_from(end - start).unwrap_or(usize::MAX));
        if !step(start, &data) {
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
        let pagination = validate_pagination(args.limit, args.offset)?;
        let pattern = parse_checked_pattern(&args.pattern)?;
        let view = call.require_binary_view()?;
        let bounds = resolve_bounds(&view, &args.section)?;
        let mut running = RunningScan::new();
        for_each_segment(&view, bounds, |base, data| {
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
        for_each_segment(&view, bounds, |base, data| {
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
}
