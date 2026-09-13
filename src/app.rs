use std::collections::VecDeque;
use std::time::{Duration, Instant};

use keepass_rs::{Entry, Group, NodeId};

use crate::vault::Vault;

/* Which screen owns the keys. Unlock gates everything: with no open vault
   the browser has nothing to act on, so it is a screen and not a prompt. */
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum View {
    Unlock,
    /* Constructed from Wave 1 on, once a vault is open. Kept here so the
       key-dispatch shape in main.rs is final from the start. */
    Browser,
}

/* Which pane has the keys. The panes move different cursors over different
   lists, so a key live on the wrong one acts on a row that is not there. */
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Pane {
    #[default]
    Groups,
    Entries,
}

/* A question the UI asks on its own account. Nothing is blocked on the
   answer, so it carries no reply channel: the session carries on behind it. */
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Confirm {
    Quit,
}

/* A flash is timed by its length: four fixed seconds fits "saved" and not a
   wrapped clipboard error, so the floor plus reading time travels with the
   message instead of one number for all of them. */
const FLASH: Duration = Duration::from_secs(2);
const PER_CHAR: Duration = Duration::from_millis(50);
const FLASH_MAX: Duration = Duration::from_secs(8);
/* Deep enough for two quick copies in a row, shallow enough that a backlog
   nobody is still reading cannot build up behind one flash. */
const QUEUE: usize = 3;

/* Rows of context kept either side of the cursor. `ListState` is built fresh
   every frame, so with no offset of our own ratatui scrolls the least it can
   to make the selection visible: past the first screenful the cursor sits on
   the last row for the rest of the list. */
pub const SCROLLOFF: usize = 2;

/// Where the list starts drawing from, given where it started last frame.
/// Only moves when the cursor comes within `SCROLLOFF` of an edge, so the
/// rows stay put while the cursor crosses the middle of the pane.
pub fn scroll_to(offset: usize, at: usize, len: usize, height: usize) -> usize {
    if height == 0 || len <= height {
        return 0;
    }
    // Halved on a short pane, where the cursor cannot clear both edges.
    let pad = SCROLLOFF.min((height - 1) / 2);
    let last = len - height;
    let highest = at.saturating_sub(pad).min(last);
    let lowest = (at + pad + 1).saturating_sub(height).min(last);
    offset.clamp(lowest, highest)
}

pub struct App {
    pub tick: usize,
    pub view: View,
    pub show_help: bool,
    pub stage: String,
    /// What the header goes back to once a flash expires.
    resting: String,
    flash_until: Option<Instant>,
    /// Messages that arrived while one was still being read.
    waiting: VecDeque<String>,
    /// A question the UI raised itself, waiting on y or n.
    pub confirm: Option<Confirm>,
    pub quit: bool,
    /* Selection state. Cursors hold NodeIds, never row positions: rows shift
       under every mutation and under the Wave 5/6 sort and filter views, while
       an id still names the same group or entry. */
    /// The open vault. None while locked; Wave 2 opens real KDBX files here.
    pub vault: Option<Vault>,
    /// Selected group. Always valid once a vault is open (`snap` keeps it so).
    pub group_cursor: Option<NodeId>,
    /// Selected entry within the cursor group. None when the group is empty.
    pub entry_cursor: Option<NodeId>,
    pub active_pane: Pane,
    /// Per-pane list offsets, carried across frames (see `scroll_to`).
    pub group_scroll: usize,
    pub entry_scroll: usize,
}

impl App {
    pub fn new() -> Self {
        App {
            tick: 0,
            view: View::Unlock,
            show_help: false,
            stage: "locked".into(),
            resting: "locked".into(),
            flash_until: None,
            waiting: VecDeque::new(),
            confirm: None,
            quit: false,
            vault: None,
            group_cursor: None,
            entry_cursor: None,
            active_pane: Pane::Groups,
            group_scroll: 0,
            entry_scroll: 0,
        }
    }

    /// Something the UI itself has to say, where no vault or worker is
    /// involved. A key that deliberately does nothing has to report that, or
    /// it reads as a key that is broken.
    pub fn say(&mut self, text: impl Into<String>) {
        let text = text.into();
        /* A second message used to overwrite the first, so two quick copies
           arrived and left inside one blink and only the last was ever
           readable. */
        if self.flash_until.is_some() {
            if self.waiting.len() < QUEUE {
                self.waiting.push_back(text);
            }
            return;
        }
        self.show_flash(text);
    }

    fn show_flash(&mut self, text: String) {
        let reading = PER_CHAR * text.chars().count() as u32;
        self.flash_until = Some(Instant::now() + (FLASH + reading).min(FLASH_MAX));
        self.stage = text;
    }

    /// Called every frame: a flash has to expire on its own, since the thing
    /// that set it has already finished and will not send anything else.
    pub fn expire_flash(&mut self) {
        if !self.flash_until.is_some_and(|at| Instant::now() >= at) {
            return;
        }
        self.flash_until = None;
        match self.waiting.pop_front() {
            Some(next) => self.show_flash(next),
            None => self.stage = self.resting.clone(),
        }
    }

    /* `q` is the deliberate way out and stays one key everywhere nothing is
       running. Wave 2 arms the dirty guard behind `working()`; until then
       quitting costs nothing and asks nothing. */
    pub fn ask_quit(&mut self) {
        if self.working() {
            self.confirm = Some(Confirm::Quit);
        } else {
            self.quit = true;
        }
    }

    /// Whether anything is in flight that quitting would lose. One predicate
    /// for the guard, so the safe key is safe on the same set of screens that
    /// ask about it. False until Wave 2 tracks dirty vault state.
    pub fn working(&self) -> bool {
        false
    }

    /// Opens a vault into the browser: cursor on the root, first entry (if
    /// any) selected, groups pane active. The single entry point so Wave 2's
    /// unlock path cannot leave half-initialised selection behind.
    pub fn open_vault(&mut self, vault: Vault) {
        let root = vault.root_id();
        self.group_cursor = Some(root);
        self.entry_cursor = vault.entries_in(&root).first().map(|e| e.id);
        self.active_pane = Pane::Groups;
        self.group_scroll = 0;
        self.entry_scroll = 0;
        self.vault = Some(vault);
        self.view = View::Browser;
    }

    /* Pre-order walk of the whole tree as (id, depth) pairs. The groups pane
       reads this, not the raw child lists: one flat list means one cursor and
       one scroll, and collapse (Wave 5) prunes it without touching the vault.
       Root is always first, so an empty tree still shows one row. */
    pub fn group_tree(&self) -> Vec<(NodeId, usize)> {
        let Some(vault) = &self.vault else {
            return Vec::new();
        };
        let mut out = Vec::new();
        let mut stack = vec![(vault.root_id(), 0)];
        while let Some((id, depth)) = stack.pop() {
            out.push((id, depth));
            /* Reversed so the first child pops first and order matches the
               stored child list. */
            for child in vault.groups_in(&id).iter().rev() {
                stack.push((child.id, depth + 1));
            }
        }
        out
    }

    /// Entry ids of the cursor group in stored order. Positions, like the
    /// group tree above: the cursor holds the id, the list is rebuilt per
    /// frame, and the two meet in `snap`.
    pub fn entry_rows(&self) -> Vec<NodeId> {
        match (&self.vault, self.group_cursor) {
            (Some(vault), Some(group)) => {
                vault.entries_in(&group).iter().map(|e| e.id).collect()
            }
            _ => Vec::new(),
        }
    }

    pub fn selected_group(&self) -> Option<&Group> {
        let (vault, id) = (self.vault.as_ref()?, self.group_cursor?);
        vault.get_group(&id)
    }

    /* Filtered out means not selected: the entry cursor may name an entry of
       another group after the group cursor moved, and acting on it would edit
       a row that is not on screen. */
    pub fn selected_entry(&self) -> Option<&Entry> {
        let (vault, group, id) = (self.vault.as_ref()?, self.group_cursor?, self.entry_cursor?);
        vault
            .get_entry(&id)
            .filter(|_| vault.parent_group_of_entry(&id) == Some(group))
    }

    /* Puts both cursors back on rows that exist. Called after every mutation
       and every cursor move across groups: a cursor on a deleted group or an
       entry of another group is a selection nobody can see, and every command
       reads as dead until the next keypress moves it. */
    pub fn snap(&mut self) {
        let Some(vault) = &self.vault else {
            self.group_cursor = None;
            self.entry_cursor = None;
            return;
        };
        let tree = self.group_tree();
        if self.group_cursor.is_none_or(|id| vault.get_group(&id).is_none()) {
            self.group_cursor = tree.first().map(|(id, _)| *id);
        }
        let rows = self.entry_rows();
        if self.entry_cursor.is_none_or(|id| !rows.contains(&id)) {
            self.entry_cursor = rows.first().copied();
        }
    }

    /// Step the group cursor down (`true`) or up over the visible tree.
    pub fn step_group(&mut self, down: bool) {
        let tree = self.group_tree();
        let Some(at) = self.group_cursor.and_then(|id| tree.iter().position(|(g, _)| *g == id))
        else {
            self.snap();
            return;
        };
        let next = if down {
            (at + 1).min(tree.len().saturating_sub(1))
        } else {
            at.saturating_sub(1)
        };
        self.group_cursor = Some(tree[next].0);
        /* A new group brings its own entries: keeping the old entry cursor
           would point at another group's row, which `selected_entry` hides
           but which still reads as a stuck highlight. */
        self.entry_cursor = None;
        self.entry_scroll = 0;
        self.snap();
    }

    /// Step the entry cursor within the cursor group. Clamps at the ends:
    /// a jump that quietly wraps reads as a key that did nothing.
    pub fn step_entry(&mut self, down: bool) {
        let rows = self.entry_rows();
        if rows.is_empty() {
            self.entry_cursor = None;
            return;
        }
        let at = self
            .entry_cursor
            .and_then(|id| rows.iter().position(|e| *e == id))
            .unwrap_or(0);
        let next = if down {
            (at + 1).min(rows.len() - 1)
        } else {
            at.saturating_sub(1)
        };
        self.entry_cursor = Some(rows[next]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /* Carried across frames, or ratatui recomputes the least scroll that
       makes the selection visible and pins the cursor to the last row. */
    #[test]
    fn scroll_holds_until_the_cursor_nears_an_edge() {
        // Fits: no scroll whatever the cursor does.
        assert_eq!(scroll_to(0, 9, 10, 10), 0);
        // Mid-list: the offset stays where it was.
        assert_eq!(scroll_to(0, 4, 40, 10), 0);
        // Within SCROLLOFF of the bottom edge: follows.
        assert_eq!(scroll_to(0, 9, 40, 10), 2);
        // Never past the last page.
        assert_eq!(scroll_to(0, 39, 40, 10), 30);
    }

    fn open_app() -> App {
        let mut vault = Vault::new();
        let root = vault.root_id();
        let banks = vault.create_group(&root, "Banks").unwrap();
        vault.create_entry(&banks, "checking", "u", "p", "", "").unwrap();
        let mut app = App::new();
        app.open_vault(vault);
        app
    }

    /* Opening lands on the root with a valid selection, or the first keypress
       acts on nothing and reads as broken. */
    #[test]
    fn opening_a_vault_selects_root_and_snaps() {
        let app = open_app();
        let vault = app.vault.as_ref().unwrap();
        assert_eq!(app.group_cursor, Some(vault.root_id()));
        assert_eq!(app.view, View::Browser);
        assert!(app.selected_group().is_some());
    }

    /* The tree is pre-order with depths: the groups pane draws straight from
       this, indent included. */
    #[test]
    fn the_group_tree_walks_pre_order_with_depths() {
        let app = open_app();
        let vault = app.vault.as_ref().unwrap();
        let root = vault.root_id();
        let names: Vec<(String, usize)> = app
            .group_tree()
            .iter()
            .map(|(id, d)| (vault.get_group(id).unwrap().title.clone(), *d))
            .collect();
        assert_eq!(names, vec![
            ("Root".to_string(), 0),
            ("Banks".to_string(), 1)
        ]);
        assert_eq!(app.group_cursor, Some(root));
    }

    /* Deleting the selected group must not strand the cursor: snap falls back
       to the root, which always exists. */
    #[test]
    fn snap_recovers_the_group_cursor_after_a_delete() {
        let mut app = open_app();
        let banks = app.group_tree()[1].0;
        app.group_cursor = Some(banks);
        app.vault.as_mut().unwrap().delete_group(&banks).unwrap_err();
        // Non-empty: refused. Empty it, then delete for real.
        let e = app.entry_rows();
        assert!(!e.is_empty());
        app.vault.as_mut().unwrap().delete_entry(&e[0]).unwrap();
        app.vault.as_mut().unwrap().delete_group(&banks).unwrap();
        app.snap();
        let root = app.vault.as_ref().unwrap().root_id();
        assert_eq!(app.group_cursor, Some(root));
        assert!(app.selected_group().is_some());
    }

    /* Moving across groups drops the entry cursor onto the new group's first
       entry: the old id names another group's row. */
    #[test]
    fn stepping_groups_reselects_entries_in_the_new_group() {
        let mut app = open_app();
        assert_eq!(app.entry_rows().len(), 0, "root holds no entries");
        assert_eq!(app.entry_cursor, None);
        app.step_group(true);
        let banks = app.group_cursor.unwrap();
        assert_eq!(
            app.vault.as_ref().unwrap().get_group(&banks).unwrap().title,
            "Banks"
        );
        assert!(app.selected_entry().is_some());
        // Stepping past the last row clamps instead of wrapping.
        app.step_entry(true);
        let first = app.entry_cursor;
        app.step_entry(true);
        assert_eq!(app.entry_cursor, first);
    }

    /* An entry cursor from another group selects nothing: otherwise `e` would
       edit a row that is not on screen. */
    #[test]
    fn an_entry_of_another_group_is_not_selected() {
        let mut app = open_app();
        let banks = app.group_tree()[1].0;
        let eid = app.vault.as_ref().unwrap().entries_in(&banks)[0].id;
        // Still on root: the Banks entry must not resolve.
        app.entry_cursor = Some(eid);
        assert!(app.selected_entry().is_none());
        app.snap();
        assert_eq!(app.entry_cursor, None, "root is empty");
    }
}
