use std::collections::HashMap;

use keepass::db::{EntryId, EntryRef, GroupId};
use nucleo_matcher::Matcher;
use nucleo_matcher::pattern::{AtomKind, CaseMatching, Normalization, Pattern};
use nucleo_matcher::{Utf32Str};

use crate::vault::Vault;

/* What an entry answers to. Notes are deliberately left out: they are long
   free text that matches almost any needle and floods the list with hits the
   user did not mean. Title, user, url and the group path are the fields a
   person reaches for when looking for an entry. If notes search is ever
   wanted, it becomes an opt-in toggle, not a default. */
/* Test-only since `haystacks` took over the whole-vault pass, which resolves
   each group path once instead of per entry. Kept because it is the one place
   the join is stated for a single entry, and the tests pin it. */
#[allow(dead_code)]
pub fn haystack(vault: &Vault, id: &EntryId) -> String {
    let Some(entry) = vault.get_entry(id) else {
        return String::new();
    };
    let group = vault
        .parent_group_of_entry(id)
        .map(|g| vault.group_path(&g).join("/"))
        .unwrap_or_default();
    haystack_from(&entry, &group)
}

/* The needle, parsed once for a whole pass over the vault. It used to be
   rebuilt inside the per-entry rank, so a keystroke in the band parsed the
   same needle into the same atoms once per entry — thousands of times, for an
   answer that cannot change between two entries. */
pub fn pattern(needle: &str) -> Pattern {
    Pattern::new(needle, CaseMatching::Smart, Normalization::Smart, AtomKind::Fuzzy)
}

/* What each of `ids` answers to, in the same order, with every group path
   resolved once. The path is a walk to the root and a `join`, and a vault
   keeps far fewer folders than entries — so the entries in one folder used to
   pay for the same walk over and over, per keystroke. */
pub fn haystacks(vault: &Vault, ids: &[EntryId]) -> Vec<String> {
    let mut paths: HashMap<GroupId, String> = HashMap::new();
    ids.iter()
        .map(|id| {
            let Some(entry) = vault.get_entry(id) else {
                return String::new();
            };
            let group = match vault.parent_group_of_entry(id) {
                Some(at) => paths
                    .entry(at)
                    .or_insert_with(|| vault.group_path(&at).join("/"))
                    .clone(),
                None => String::new(),
            };
            haystack_from(&entry, &group)
        })
        .collect()
}

/// Split from `haystack` for tests: the same join without needing the vault.
fn haystack_from(entry: &EntryRef<'_>, group_path: &str) -> String {
    [
        crate::vault::EntryExt::title(entry),
        crate::vault::EntryExt::username(entry),
        crate::vault::EntryExt::url(entry),
        group_path,
    ]
    .join(" ")
}

/* A matcher plus the scratch buffers fuzzy_match wants. Buffers live here so
   repeated ranks reuse their allocations instead of growing fresh vecs every
   keypress — the band re-ranks the whole vault on each typed character. */
pub struct Searcher {
    matcher: Matcher,
    /// Scratch the haystack is decoded into, kept so a whole-vault pass reuses
    /// one allocation instead of growing a fresh vec per entry.
    hay_chars: Vec<char>,
    /* Owned by `rank` (test-only, see there); kept here so the buffer stays
       allocated rather than rebuilt per call. */
    #[allow(dead_code)]
    needle_chars: Vec<char>,
}

impl Searcher {
    pub fn new() -> Self {
        Searcher {
            matcher: Matcher::new(nucleo_matcher::Config::DEFAULT),
            hay_chars: Vec::new(),
            needle_chars: Vec::new(),
        }
    }

    /// One haystack against a needle parsed by `pattern`. Pattern scores u32
    /// and never returns Some(0) for a real hit below 1, so the cast stays
    /// lossless in practice; clamp keeps the u16 ceiling honest.
    pub fn score(&mut self, pattern: &Pattern, hay: &str) -> Option<u16> {
        /* Destructured so the scratch buffer and the matcher are two borrows
           of two fields rather than one of the whole Searcher. */
        let Searcher { matcher, hay_chars, .. } = self;
        let hay = Utf32Str::new(hay, hay_chars);
        pattern.score(hay, matcher).map(|s| s.min(u16::MAX as u32) as u16)
    }

    /// None means "no match": the row is filtered out. An empty needle
    /// matches everything (score 0), which is exactly what an empty band
    /// should do — show all rows.
    /* Test-only in practice: prod rows go through rank_entry (multi-atom
       Pattern). Kept because tests pin raw score semantics, and any future
       score-based ordering needs it. */
    #[allow(dead_code)]
    pub fn rank(&mut self, needle: &str, hay: &str) -> Option<u16> {
        let Searcher { matcher, hay_chars, needle_chars } = self;
        let needle = Utf32Str::new(needle, needle_chars);
        let hay = Utf32Str::new(hay, hay_chars);
        matcher.fuzzy_match(hay, needle)
    }

    /// Which characters of `text` the needle matched, as char indices. The
    /// entries pane bolds them: a list that is merely sorted by relevance
    /// makes the reader find the reason themselves.
    pub fn indices(&mut self, needle: &str, text: &str) -> Vec<u32> {
        if needle.is_empty() {
            return Vec::new();
        }
        let pattern = Pattern::parse(needle, CaseMatching::Smart, Normalization::Smart);
        let Searcher { matcher, hay_chars, .. } = self;
        let hay = Utf32Str::new(text, hay_chars);
        let mut out = Vec::new();
        pattern.indices(hay, matcher, &mut out);
        out.sort_unstable();
        out.dedup();
        out
    }

    /// One entry, needle and all, for a caller with a single id to rank.
    /* Test-only in practice: prod passes go through `pattern` + `haystacks` +
       `score`, which build both once for the vault rather than once per
       entry. Kept because the tests pin what ranking one entry means. */
    #[allow(dead_code)]
    /* Pattern (not raw fuzzy_match) so multi-word needles like "git octo"
       require both atoms, and Smart casing/normalisation come along for free.
       A pass over the whole vault builds the pattern and the haystacks once
       and calls `score` instead — this is the convenience, not the hot
       path. */
    pub fn rank_entry(&mut self, needle: &str, vault: &Vault, id: &EntryId) -> Option<u16> {
        self.score(&pattern(needle), &haystack(vault, id))
    }
}

impl Default for Searcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault_with(title: &str, user: &str, url: &str, group: &str) -> (Vault, EntryId) {
        let mut vault = Vault::new();
        let root = vault.root_id();
        let g = vault.create_group(&root, group).unwrap();
        let id = vault.create_entry(&g, title, user, "pw", url, "").unwrap();
        (vault, id)
    }

    #[test]
    fn a_subsequence_matches() {
        let mut s = Searcher::new();
        assert!(s.rank("gith", "github").is_some());
    }

    #[test]
    fn casing_does_not_matter_for_lowercase_needles() {
        let mut s = Searcher::new();
        assert!(s.rank("git", "GitHub").is_some());
    }

    #[test]
    fn a_miss_is_none() {
        let mut s = Searcher::new();
        assert!(s.rank("zzz", "github").is_none());
    }

    /* Empty band shows everything: an empty needle scores 0 on any haystack
       rather than filtering the list to nothing. */
    #[test]
    fn an_empty_needle_matches_everything() {
        let mut s = Searcher::new();
        assert_eq!(s.rank("", "anything"), Some(0));
    }

    /* nucleo normalises latin accents itself (Smart normalisation), so a
       needle typed without accents still finds accented titles. */
    #[test]
    fn accents_normalise() {
        let mut s = Searcher::new();
        assert!(s.rank("cafe", "café").is_some());
    }

    #[test]
    fn the_haystack_covers_title_user_url_and_group() {
        let (vault, id) = vault_with("Inbox Zero", "octo", "https://mail.example", "Mail");
        let hay = haystack(&vault, &id);
        for part in ["Inbox", "octo", "mail.example", "Mail"] {
            assert!(hay.contains(part), "{hay}");
        }
    }

    #[test]
    fn ranking_finds_through_the_haystack() {
        let (vault, id) = vault_with("Inbox Zero", "octo", "https://mail.example", "Mail");
        let mut s = Searcher::new();
        assert!(s.rank_entry("mail octo", &vault, &id).is_some());
        assert!(s.rank_entry("zzz", &vault, &id).is_none());
    }

    /* The group path is searchable: "bank" should find entries filed under
       Banks even when the title says nothing about banking. */
    #[test]
    fn the_group_path_is_searchable() {
        let (vault, id) = vault_with("checking", "u", "", "Banks");
        let mut s = Searcher::new();
        assert!(s.rank_entry("bank", &vault, &id).is_some());
    }
}
