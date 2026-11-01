//! One-pass multi-pattern scan: an Aho-Corasick automaton over each pattern's
//! first concrete byte run, with wildcard verification at every candidate hit.
//!
//! This is the capability the Python plugin cannot offer: `N` hex patterns in a
//! single pass over the bytes instead of `N` serial `rex_data_find` calls.
//!
//! Why this decomposition: hex patterns with `??` wildcards are not literals, so
//! they cannot go into an Aho-Corasick automaton directly. But every occurrence
//! of a pattern contains its first concrete run at a fixed offset, so:
//!
//! 1. all patterns' concrete runs go into one automaton,
//! 2. `find_overlapping_iter` yields every run hit (overlaps included, which is
//!    what keeps self-overlapping patterns correct),
//! 3. each hit is verified against its full pattern, wildcards and all.
//!
//! Every pattern occurrence therefore produces at least one automaton hit, and
//! verification discards false hits, so the result equals the naive scan.

use std::collections::HashMap;

use aho_corasick::{AhoCorasick, MatchKind};

use crate::hexpattern::{HexPattern, verify_at};
use crate::scan::{Pagination, RunningScan};

/// Cap on the number of patterns one `rx_multi_find` call accepts. The
/// automaton and per-pattern buckets are linear in this; 64 keeps one call
/// small while covering realistic signature-set slices.
pub const MAX_MULTI_PATTERNS: usize = 64;

/// The owner of one automaton needle: the pattern it prefilters and the offset
/// of the needle inside that pattern.
struct NeedleOwner {
    pattern_index: usize,
    needle_offset: usize,
}

/// The compiled multi-pattern matcher for one `rx_multi_find` call.
pub struct MultiMatcher {
    automaton: AhoCorasick,
    /// Owners per automaton pattern id; several owners may share one needle
    /// when different patterns start with the same concrete run.
    owners: Vec<Vec<NeedleOwner>>,
    /// Indices of patterns with no concrete byte at all; they match at every
    /// position and are scanned directly instead of through the automaton.
    wildcard_only: Vec<usize>,
}

impl MultiMatcher {
    /// Compile one automaton covering every pattern that has a concrete run.
    pub fn new(patterns: &[HexPattern]) -> Self {
        let mut needle_ids: HashMap<Vec<u8>, usize> = HashMap::new();
        let mut needles: Vec<Vec<u8>> = Vec::new();
        let mut owners: Vec<Vec<NeedleOwner>> = Vec::new();
        let mut wildcard_only = Vec::new();
        for (pattern_index, pattern) in patterns.iter().enumerate() {
            let Some((needle_offset, run)) = pattern.first_concrete_run() else {
                wildcard_only.push(pattern_index);
                continue;
            };
            let id = match needle_ids.get(&run) {
                Some(id) => *id,
                None => {
                    let id = needles.len();
                    needles.push(run.clone());
                    needle_ids.insert(run, id);
                    id
                }
            };
            if owners.len() <= id {
                owners.resize_with(id + 1, Vec::new);
            }
            owners[id].push(NeedleOwner {
                pattern_index,
                needle_offset,
            });
        }
        let automaton = AhoCorasick::builder()
            // Standard semantics report every hit as soon as it is seen, which
            // is what find_overlapping_iter needs for overlapping occurrences.
            .match_kind(MatchKind::Standard)
            .build(&needles)
            .expect("aho-corasick build of concrete byte runs");
        Self {
            automaton,
            owners,
            wildcard_only,
        }
    }

    /// Scan one in-memory segment for every pattern, updating per-pattern
    /// buckets. `base` is the absolute address of `haystack[0]`.
    ///
    /// Returns `false` when every bucket's window is exhausted; the caller must
    /// stop scanning further segments.
    pub fn scan_segment(
        &self,
        haystack: &[u8],
        base: u64,
        patterns: &[HexPattern],
        buckets: &mut [RunningScan],
        pagination: &Pagination,
    ) -> bool {
        let mut done = buckets.iter().filter(|bucket| bucket.is_done()).count();
        for hit in self.automaton.find_overlapping_iter(haystack) {
            for owner in &self.owners[hit.pattern().as_usize()] {
                let bucket = &mut buckets[owner.pattern_index];
                if bucket.is_done() {
                    continue;
                }
                let pattern = &patterns[owner.pattern_index];
                let Some(candidate) = hit.start().checked_sub(owner.needle_offset) else {
                    continue;
                };
                if !verify_at(haystack, candidate, pattern.bytes()) {
                    continue;
                }
                if !bucket.record(pagination, base + candidate as u64) {
                    done += 1;
                    if done == buckets.len() {
                        return false;
                    }
                }
            }
        }
        // All-wildcard patterns match at every position; scan them directly so
        // each bucket's own address order stays ascending.
        for &pattern_index in &self.wildcard_only {
            let bucket = &mut buckets[pattern_index];
            if bucket.is_done() {
                continue;
            }
            let pattern = &patterns[pattern_index];
            if haystack.len() < pattern.len() {
                continue;
            }
            for candidate in 0..=haystack.len() - pattern.len() {
                // An all-wildcard pattern matches unconditionally.
                if !bucket.record(pagination, base + candidate as u64) {
                    done += 1;
                    break;
                }
            }
        }
        done < buckets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_all<S: AsRef<str>>(patterns: &[S]) -> Vec<HexPattern> {
        patterns
            .iter()
            .map(|text| HexPattern::parse(text.as_ref()).unwrap())
            .collect()
    }

    fn scan_all(
        haystack: &[u8],
        base: u64,
        pattern_texts: &[&str],
        offset: u64,
        limit: u64,
    ) -> Vec<RunningScan> {
        let patterns = parse_all(pattern_texts);
        let matcher = MultiMatcher::new(&patterns);
        let mut buckets: Vec<RunningScan> =
            (0..patterns.len()).map(|_| RunningScan::new()).collect();
        let pagination = Pagination { offset, limit };
        matcher.scan_segment(haystack, base, &patterns, &mut buckets, &pagination);
        buckets
    }

    /// Known-answer test for the crate behavior this design rests on:
    /// find_overlapping_iter must report self-overlapping occurrences.
    #[test]
    fn aho_corasick_reports_overlapping_hits() {
        let patterns = parse_all(&["61 61"]); // "aa"
        let matcher = MultiMatcher::new(&patterns);
        let hits: Vec<usize> = matcher
            .automaton
            .find_overlapping_iter(b"aaaa".as_slice())
            .map(|hit| hit.start())
            .collect();
        assert_eq!(hits, vec![0, 1, 2]);
    }

    #[test]
    fn finds_overlapping_matches_per_pattern() {
        let buckets = scan_all(b"ababab", 0x1000, &["61 62"], 0, 50);
        assert_eq!(buckets[0].matches, vec![0x1000, 0x1002, 0x1004]);
        assert_eq!(buckets[0].total, 3);
        assert!(!buckets[0].truncated);
    }

    #[test]
    fn two_patterns_route_to_their_own_buckets() {
        let buckets = scan_all(b"xy ab ab zz", 0, &["61 62", "78 79"], 0, 50);
        assert_eq!(buckets[0].matches, vec![3, 6]);
        assert_eq!(buckets[1].matches, vec![0]);
        assert_eq!(buckets[1].total, 1);
    }

    #[test]
    fn shared_prefix_runs_disambiguate_by_verification() {
        // Both patterns share the run "48 8b"; verification tells them apart.
        let buckets = scan_all(
            &[0x48, 0x8b, 0x05, 0x48, 0x8b, 0xff, 0x48, 0x8b],
            0,
            &["48 8b 05", "48 8b ff"],
            0,
            50,
        );
        assert_eq!(buckets[0].matches, vec![0]);
        assert_eq!(buckets[1].matches, vec![3]);
        assert_eq!(buckets[0].total, 1);
        assert_eq!(buckets[1].total, 1);
    }

    #[test]
    fn window_skips_collects_and_truncates() {
        // "ab" occurs at 0, 2, 4, 6. Window [1, 3): occurrence 1 is skipped,
        // occurrences 2 and 3 are collected, occurrence 4 proves truncation.
        let buckets = scan_all(b"abababab", 0, &["61 62"], 1, 2);
        assert_eq!(buckets[0].matches, vec![2, 4]);
        assert_eq!(buckets[0].total, 4);
        assert!(buckets[0].truncated);
    }

    #[test]
    fn wildcard_only_pattern_matches_every_position() {
        let buckets = scan_all(&[1u8, 2, 3], 0x10, &["?? ??"], 0, 50);
        assert_eq!(buckets[0].matches, vec![0x10, 0x11]);
        assert!(!buckets[0].truncated);
    }

    #[test]
    fn wildcard_only_bucket_truncates() {
        let buckets = scan_all(&[1u8, 2, 3, 4], 0, &["?? ??"], 0, 1);
        assert_eq!(buckets[0].matches, vec![0]);
        assert_eq!(buckets[0].total, 2);
        assert!(buckets[0].truncated);
    }

    #[test]
    fn exhausted_bucket_does_not_collect_more() {
        let patterns = parse_all(&["61 62", "78 79"]);
        let matcher = MultiMatcher::new(&patterns);
        let mut buckets: Vec<RunningScan> =
            (0..patterns.len()).map(|_| RunningScan::new()).collect();
        let pagination = Pagination {
            offset: 0,
            limit: 1,
        };
        // Hits arrive in haystack order ("xy" first). After "ab"'s bucket
        // truncates on its second hit, the "xy" bucket must already be filled.
        let alive = matcher.scan_segment(b"xy ab ab", 0, &patterns, &mut buckets, &pagination);
        assert!(alive);
        assert_eq!(buckets[0].matches, vec![3]);
        assert!(buckets[0].truncated);
        assert_eq!(buckets[1].matches, vec![0]);
        assert!(!buckets[1].truncated);
    }

    #[test]
    fn all_buckets_exhausted_stops_the_scan() {
        let patterns = parse_all(&["61 62"]);
        let matcher = MultiMatcher::new(&patterns);
        let mut buckets: Vec<RunningScan> = vec![RunningScan::new()];
        let pagination = Pagination {
            offset: 0,
            limit: 1,
        };
        let alive = matcher.scan_segment(b"ab ab ab", 0, &patterns, &mut buckets, &pagination);
        assert!(!alive);
        assert!(buckets[0].truncated);
    }

    #[test]
    fn multi_segment_accumulation_across_calls() {
        let patterns = parse_all(&["61 62"]);
        let matcher = MultiMatcher::new(&patterns);
        let mut buckets: Vec<RunningScan> = vec![RunningScan::new()];
        let pagination = Pagination {
            offset: 0,
            limit: 50,
        };
        assert!(matcher.scan_segment(b"ab", 0x10, &patterns, &mut buckets, &pagination));
        assert!(matcher.scan_segment(b"ab ab", 0x20, &patterns, &mut buckets, &pagination));
        assert_eq!(buckets[0].matches, vec![0x10, 0x20, 0x23]);
        assert_eq!(buckets[0].total, 3);
    }

    /// Differential test against a naive reference on pseudo-random inputs.
    #[test]
    fn agrees_with_naive_reference_on_random_inputs() {
        let mut lcg: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = move || {
            lcg = lcg
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (lcg >> 33) as u32
        };
        for case in 0..300u32 {
            let hay_len = (next() % 48) as usize;
            let haystack: Vec<u8> = (0..hay_len).map(|_| (next() % 4) as u8).collect();
            let pattern_count = 1 + (next() % 5) as usize;
            let mut pattern_texts = Vec::new();
            for _ in 0..pattern_count {
                let pat_len = 1 + (next() % 4) as usize;
                let tokens: Vec<String> = (0..pat_len)
                    .map(|_| {
                        if next() % 3 == 0 {
                            "??".to_string()
                        } else {
                            format!("{:02x}", next() % 4)
                        }
                    })
                    .collect();
                pattern_texts.push(tokens.join(" "));
            }
            let patterns = parse_all(&pattern_texts);
            let naive: Vec<Vec<usize>> = patterns
                .iter()
                .map(|pattern| {
                    if haystack.len() < pattern.len() {
                        Vec::new()
                    } else {
                        (0..=haystack.len() - pattern.len())
                            .filter(|pos| verify_at(&haystack, *pos, pattern.bytes()))
                            .collect()
                    }
                })
                .collect();
            for offset in [0u64, 2] {
                for limit in [0u64, 1, 100] {
                    let matcher = MultiMatcher::new(&patterns);
                    let mut buckets: Vec<RunningScan> =
                        (0..patterns.len()).map(|_| RunningScan::new()).collect();
                    let pagination = Pagination { offset, limit };
                    let alive =
                        matcher.scan_segment(&haystack, 0, &patterns, &mut buckets, &pagination);
                    for (index, bucket) in buckets.iter().enumerate() {
                        let window_end = offset.saturating_add(limit);
                        let mut expected_total = 0u64;
                        let mut truncated = false;
                        let mut expected = Vec::new();
                        for pos in &naive[index] {
                            expected_total += 1;
                            if expected_total > offset && expected_total <= window_end {
                                expected.push(*pos as u64);
                            }
                            if expected_total > window_end {
                                truncated = true;
                                break;
                            }
                        }
                        assert_eq!(bucket.total, expected_total, "case {case} pattern {index}");
                        assert_eq!(bucket.truncated, truncated, "case {case} pattern {index}");
                        assert_eq!(bucket.matches, expected, "case {case} pattern {index}");
                    }
                    let all_done = buckets.iter().all(|bucket| bucket.is_done());
                    assert_eq!(
                        !alive, all_done,
                        "case {case} offset {offset} limit {limit}"
                    );
                }
            }
        }
    }
}
