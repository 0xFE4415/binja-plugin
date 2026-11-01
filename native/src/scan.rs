//! In-memory single-pattern scan with the Python plugin's pagination contract.
//!
//! `rex_data_find` counts every occurrence (including overlapping ones), stops
//! scanning at the first match that falls outside the `[offset, offset+limit)`
//! window, and reports `total` as the count reached before stopping. `RunningScan`
//! reproduces that exactly; `scan_pattern` is the memchr-prefiltered scan itself.

use crate::hexpattern::{HexPattern, verify_at};
use memchr::memchr_iter;

/// Pagination arguments shared by both tools.
#[derive(Clone, Copy, Debug)]
pub struct Pagination {
    /// Number of matches to skip before collecting results.
    pub offset: u64,
    /// Maximum number of matches to collect after skipping.
    pub limit: u64,
}

/// Accumulated state of one pattern's result while scanning segment by segment.
///
/// The name mirrors the Python plugin's observable contract: once a match lands
/// past the window, `truncated` latches and scanning must stop everywhere.
#[derive(Debug, Default)]
pub struct RunningScan {
    /// Matches counted before the scan stopped.
    pub total: u64,
    /// True when at least one further match was proven to exist.
    pub truncated: bool,
    /// Absolute addresses inside the `[offset, offset+limit)` window, ascending.
    pub matches: Vec<u64>,
}

impl RunningScan {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a match at `addr`. Returns `false` when the scan window is now
    /// exhausted and the caller must stop scanning entirely.
    pub fn record(&mut self, pagination: &Pagination, addr: u64) -> bool {
        if self.truncated {
            return false;
        }
        self.total += 1;
        let window_end = pagination.offset.saturating_add(pagination.limit);
        if self.total > pagination.offset && self.total <= window_end {
            self.matches.push(addr);
            true
        } else if self.total > window_end {
            self.truncated = true;
            false
        } else {
            // Still before the window start: keep scanning.
            true
        }
    }

    pub fn is_done(&self) -> bool {
        self.truncated
    }
}

/// Scan one in-memory segment for `pattern`, recording into `running`.
///
/// `base` is the absolute address of `haystack[0]`. The scan prefilters with
/// SIMD `memchr` on the pattern's first concrete byte and verifies the full
/// pattern (wildcards included) at every candidate. Returns `false` when the
/// window is exhausted; the caller must stop scanning further segments.
///
/// Occurrences are reported in ascending address order and include overlapping
/// matches, matching the Python lookahead-regex behavior.
pub fn scan_pattern(
    haystack: &[u8],
    base: u64,
    pattern: &HexPattern,
    pagination: &Pagination,
    running: &mut RunningScan,
) -> bool {
    if pattern.is_empty() || running.is_done() {
        return !running.is_done();
    }
    let bytes = pattern.bytes();
    let pattern_len = bytes.len();
    if haystack.len() < pattern_len {
        return true;
    }
    let last_start = haystack.len() - pattern_len;
    if let Some((offset, anchor)) = pattern.first_concrete() {
        for hit in memchr_iter(anchor, haystack) {
            // The candidate match starts `offset` bytes before the anchor.
            let Some(candidate) = hit.checked_sub(offset) else {
                continue;
            };
            if candidate > last_start {
                // Anchors only move right, so no later candidate can fit.
                break;
            }
            if !verify_at(haystack, candidate, bytes) {
                continue;
            }
            if !running.record(pagination, base + candidate as u64) {
                return false;
            }
        }
    } else {
        // Every position matches an all-wildcard pattern.
        for candidate in 0..=last_start {
            if !running.record(pagination, base + candidate as u64) {
                return false;
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hexpattern::HexPattern;

    fn pattern(text: &str) -> HexPattern {
        HexPattern::parse(text).unwrap()
    }

    /// Naive reference: every position where the pattern matches, ascending.
    fn naive_matches(haystack: &[u8], pat: &[Option<u8>]) -> Vec<usize> {
        if haystack.len() < pat.len() {
            return Vec::new();
        }
        (0..=haystack.len() - pat.len())
            .filter(|pos| verify_at(haystack, *pos, pat))
            .collect()
    }

    /// Build a pattern through the public parser from random tokens.
    fn pattern_from_tokens(tokens: Vec<Option<u8>>) -> HexPattern {
        let text = tokens
            .iter()
            .map(|token| match token {
                Some(value) => format!("{value:02x}"),
                None => "??".to_string(),
            })
            .collect::<Vec<_>>()
            .join(" ");
        HexPattern::parse(&text).unwrap()
    }

    #[test]
    fn finds_overlapping_matches_in_order() {
        let hay = b"ababab";
        let pat = pattern("61 62"); // "ab"
        let mut running = RunningScan::new();
        let page = Pagination {
            offset: 0,
            limit: 50,
        };
        assert!(scan_pattern(hay, 0x1000, &pat, &page, &mut running));
        assert_eq!(running.matches, vec![0x1000, 0x1002, 0x1004]);
        assert_eq!(running.total, 3);
        assert!(!running.truncated);
    }

    #[test]
    fn self_overlapping_pattern_counts_each_position() {
        let hay = b"aaaa";
        let pat = pattern("61 61"); // "aa"
        let mut running = RunningScan::new();
        let page = Pagination {
            offset: 0,
            limit: 50,
        };
        assert!(scan_pattern(hay, 0, &pat, &page, &mut running));
        assert_eq!(running.matches, vec![0, 1, 2]);
    }

    #[test]
    fn window_skips_and_limits() {
        let hay = b"abababab";
        let pat = pattern("61 62");
        // Occurrences at 0, 2, 4, 6. Skip 3, collect 2: only occurrence 4 is
        // inside the window; the scan completes without truncation.
        let mut running = RunningScan::new();
        let page = Pagination {
            offset: 3,
            limit: 2,
        };
        assert!(scan_pattern(hay, 0, &pat, &page, &mut running));
        assert_eq!(running.matches, vec![6]);
        assert_eq!(running.total, 4);
        assert!(!running.truncated);
        // Skip 1, collect 2: occurrences 2 and 3 fill the window, occurrence 4
        // lands past it and proves truncation.
        let mut running = RunningScan::new();
        let page = Pagination {
            offset: 1,
            limit: 2,
        };
        assert!(!scan_pattern(hay, 0, &pat, &page, &mut running));
        assert_eq!(running.matches, vec![2, 4]);
        assert_eq!(running.total, 4);
        assert!(running.truncated);
        // A window that exactly covers the remaining occurrences does not
        // truncate: skip 1 of 2, take the other.
        let hay = b"abab";
        let mut running = RunningScan::new();
        let page = Pagination {
            offset: 1,
            limit: 2,
        };
        assert!(scan_pattern(hay, 0, &pat, &page, &mut running));
        assert_eq!(running.matches, vec![2]);
        assert_eq!(running.total, 2);
        assert!(!running.truncated);
    }

    #[test]
    fn truncates_at_window_end_and_stops() {
        let hay = b"abababab";
        let pat = pattern("61 62");
        let mut running = RunningScan::new();
        let page = Pagination {
            offset: 0,
            limit: 2,
        };
        assert!(!scan_pattern(hay, 0, &pat, &page, &mut running));
        assert_eq!(running.matches, vec![0, 2]);
        assert_eq!(running.total, 3); // one past the window proves truncation
        assert!(running.truncated);
    }

    #[test]
    fn zero_limit_truncates_on_first_match() {
        let hay = b"ab";
        let pat = pattern("61");
        let mut running = RunningScan::new();
        let page = Pagination {
            offset: 0,
            limit: 0,
        };
        assert!(!scan_pattern(hay, 0, &pat, &page, &mut running));
        assert!(running.matches.is_empty());
        assert_eq!(running.total, 1);
        assert!(running.truncated);
    }

    #[test]
    fn offset_beyond_match_count_is_not_truncated() {
        let hay = b"ab";
        let pat = pattern("61");
        let mut running = RunningScan::new();
        let page = Pagination {
            offset: 10,
            limit: 5,
        };
        assert!(scan_pattern(hay, 0, &pat, &page, &mut running));
        assert!(running.matches.is_empty());
        assert_eq!(running.total, 1);
        assert!(!running.truncated);
    }

    #[test]
    fn all_wildcard_matches_every_position() {
        let hay = [7u8, 8, 9];
        let pat = pattern("?? ??");
        let mut running = RunningScan::new();
        let page = Pagination {
            offset: 0,
            limit: 50,
        };
        assert!(scan_pattern(&hay, 0x10, &pat, &page, &mut running));
        assert_eq!(running.matches, vec![0x10, 0x11]);
    }

    #[test]
    fn pattern_longer_than_haystack_matches_nothing() {
        let hay = b"a";
        let pat = pattern("61 62");
        let mut running = RunningScan::new();
        let page = Pagination {
            offset: 0,
            limit: 50,
        };
        assert!(scan_pattern(hay, 0, &pat, &page, &mut running));
        assert_eq!(running.total, 0);
    }

    /// Differential test: the prefiltered scanner must agree with a naive
    /// reference matcher on pseudo-random inputs (fixed LCG seed, no rand dep).
    #[test]
    fn agrees_with_naive_reference_on_random_inputs() {
        let mut lcg: u64 = 0x5145_5145;
        let mut next = move || {
            lcg = lcg
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (lcg >> 33) as u32
        };
        for case in 0..200u32 {
            let hay_len = (next() % 64) as usize;
            let hay: Vec<u8> = (0..hay_len)
                .map(|_| {
                    // Small alphabet forces plenty of near-matches and overlaps.
                    (next() % 4) as u8
                })
                .collect();
            let pat_len = 1 + (next() % 5) as usize;
            let tokens: Vec<Option<u8>> = (0..pat_len)
                .map(|_| {
                    if next() % 3 == 0 {
                        None
                    } else {
                        Some((next() % 4) as u8)
                    }
                })
                .collect();
            let pat = pattern_from_tokens(tokens);
            let naive = naive_matches(&hay, pat.bytes());
            for offset in [0u64, 1, 3] {
                for limit in [0u64, 1, 5, 100] {
                    let mut running = RunningScan::new();
                    let page = Pagination { offset, limit };
                    let keep_going = scan_pattern(&hay, 0, &pat, &page, &mut running);
                    // Reference transcription of the Python counting contract.
                    let window_end = offset.saturating_add(limit);
                    let mut expected_total = 0u64;
                    let mut truncated = false;
                    let mut expected = Vec::new();
                    for pos in &naive {
                        expected_total += 1;
                        if expected_total > offset && expected_total <= window_end {
                            expected.push(*pos as u64);
                        }
                        if expected_total > window_end {
                            truncated = true;
                            break;
                        }
                    }
                    assert_eq!(
                        running.total, expected_total,
                        "case {case} offset {offset} limit {limit}"
                    );
                    assert_eq!(running.truncated, truncated, "case {case}");
                    assert_eq!(running.matches, expected, "case {case}");
                    assert_eq!(keep_going, !truncated, "case {case}");
                }
            }
        }
    }
}
