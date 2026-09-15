use keepass::db::{EntryId, EntryRef};
use nucleo_matcher::Matcher;
use nucleo_matcher::pattern::{AtomKind, CaseMatching, Normalization, Pattern};
use nucleo_matcher::{Utf32Str, Utf32String};

use crate::vault::Vault;

/* What an entry answers to. Notes are deliberately left out: they are long
   free text that matches almost any needle and floods the list with hits the
   user did not mean. Title, user, url and the group path are the fields a
   person reaches for when looking for an entry. If notes search is ever
   wanted, it becomes an opt-in toggle, not a default. */
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
    /* Owned by `rank` (test-only, see there); kept together so the buffers
       stay allocated rather than rebuilt per call. */
    #[allow(dead_code)]
    hay_chars: Vec<char>,
    #[allow(dead_code)]
    needle_chars: Vec<char>,
    /// Scratch for owned haystacks: rank_entry builds a String then borrows
    /// it, and Utf32Str wants a char buffer to fill.
    hay_buf: Utf32String,
}

impl Searcher {
    pub fn new() -> Self {
        Searcher {
            matcher: Matcher::new(nucleo_matcher::Config::DEFAULT),
            hay_chars: Vec::new(),
            needle_chars: Vec::new(),
            hay_buf: Utf32String::default(),
        }
    }

    /// None means "no match": the row is filtered out. An empty needle
    /// matches everything (score 0), which is exactly what an empty band
    /// should do — show all rows.
    /* Test-only in practice: prod rows go through rank_entry (multi-atom
       Pattern). Kept because tests pin raw score semantics, and any future
       score-based ordering needs it. */
    #[allow(dead_code)]
    pub fn rank(&mut self, needle: &str, hay: &str) -> Option<u16> {
        let needle = Utf32Str::new(needle, &mut self.needle_chars);
        let hay = Utf32Str::new(hay, &mut self.hay_chars);
        self.matcher.fuzzy_match(hay, needle)
    }

    /// Whole-vault convenience: rank one entry's haystack. Pattern (not raw
    /// fuzzy_match) so multi-word needles like "git octo" require both atoms,
    /// and Smart casing/normalisation come along for free. Pattern scores
    /// u32 and never returns Some(0) for a real hit below 1, so the cast
    /// stays lossless in practice; clamp keeps the u16 ceiling honest.
    pub fn rank_entry(&mut self, needle: &str, vault: &Vault, id: &EntryId) -> Option<u16> {
        let pattern = Pattern::new(
            needle,
            CaseMatching::Smart,
            Normalization::Smart,
            AtomKind::Fuzzy,
        );
        let hay = haystack(vault, id);
        self.hay_buf = hay.into();
        let hay = self.hay_buf.slice(..);
        pattern.score(hay, &mut self.matcher).map(|s| s.min(u16::MAX as u32) as u16)
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
