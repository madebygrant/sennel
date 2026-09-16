use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Clear, List, ListItem, ListState, Paragraph, Scrollbar,
    ScrollbarOrientation, ScrollbarState,
};
use chrono::TimeZone;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::app::{self, App, Confirm, FormField, FormKind, GroupPromptKind, Level, Pane, View, char_index_to_byte};
use crate::vault::EntryExt;
use crate::theme::{self, Palette};

/* Columns, not characters. A CJK glyph takes two cells and a combining mark
   takes none, so a column padded to a character count steps out of line by
   the width of whatever is in it. */
fn cols(text: &str) -> usize {
    UnicodeWidthStr::width(text)
}

impl Palette {
    /// Secondary text: usernames, urls, hints — the app's most-used span.
    fn faint(&self, text: impl Into<String>) -> Span<'static> {
        Span::styled(text.into(), Style::new().fg(self.muted))
    }

    /// The cursor colour, for the marks and matches that say "here".
    fn lit(&self, text: impl Into<String>) -> Span<'static> {
        Span::styled(text.into(), Style::new().fg(self.cursor))
    }

    /* The row under the cursor is what the next key acts on, so its name is
       bold as well as marked. Bold is safe here because every colour is RGB:
       a terminal cannot swap it for a bright ANSI variant. */
    fn row(&self, selected: bool) -> Style {
        let style = Style::new().fg(self.text);
        if selected {
            style.add_modifier(Modifier::BOLD)
        } else {
            style
        }
    }

    /* Which row, and which pane owns the keys. Two glyphs, not two colours:
       with NO_COLOR every colour collapses to the terminal's own, and focus
       was then invisible — both panes drew the same bar. */
    fn mark(&self, selected: bool, live: bool) -> Span<'static> {
        match (selected, live) {
            (true, true) => self.lit("▌"),
            (true, false) => self.faint("│"),
            _ => Span::raw(" "),
        }
    }
}

pub fn draw(frame: &mut Frame, app: &mut App) {
    let p = app.theme;
    /* The band squeezes the body from below only while it is open: a fixed
       row the rest of the time would leave a hole where search should be. */
    let band = if app.search.is_some() {
        1
    } else {
        0
    };
    let [header, rule, body, band_area, footrule, status] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(band),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(frame.area());

    draw_background(frame, &p);
    draw_header(frame, app, header);
    draw_rule(frame, rule, &p);
    draw_body(frame, app, body);
    if app.search.is_some() {
        draw_search(frame, app, band_area);
    }
    draw_rule(frame, footrule, &p);
    draw_status(frame, app, status);

    if app.detail {
        draw_detail_popup(frame, app);
    }
    if app.show_help {
        draw_help(frame, app);
    }
    if let Some(what) = &app.confirm {
        draw_confirm(frame, app, what);
    }
    if app.form.is_some() {
        draw_form(frame, app);
    }
    if app.group_prompt.is_some() {
        draw_group_prompt(frame, app);
    }
    if app.rekey.is_some() {
        draw_rekey(frame, app);
    }
    if app.browse.is_some() {
        draw_browse(frame, app);
    }
    recolour(frame);
}

/* One pass over the finished buffer rather than three palettes: every colour
   in `theme` stays one set of numbers, and a terminal that cannot render them
   gets the nearest thing it has. Costs a walk of the cells already drawn. */
fn recolour(frame: &mut Frame) {
    if theme::depth() == theme::Depth::Full {
        return;
    }
    let area = frame.area();
    let buffer = frame.buffer_mut();
    for y in area.top()..area.bottom() {
        for x in area.left()..area.right() {
            let cell = &mut buffer[(x, y)];
            let (fg, bg) = (theme::shade(cell.fg), theme::shade(cell.bg));
            cell.set_fg(fg);
            cell.set_bg(bg);
        }
    }
}

/* Painted before anything else: every other widget styles only its
   foreground, so the gradient survives underneath them. */
fn draw_background(frame: &mut Frame, p: &Palette) {
    if theme::plain() {
        return;
    }
    let area = frame.area();
    let buffer = frame.buffer_mut();
    for y in area.top()..area.bottom() {
        for x in area.left()..area.right() {
            let bg = p.background(x - area.left(), y - area.top(), area.width, area.height);
            buffer[(x, y)].set_bg(bg);
        }
    }
}

fn draw_rule(frame: &mut Frame, area: Rect, p: &Palette) {
    frame.render_widget(
        Paragraph::new(Span::styled(
            "─".repeat(area.width as usize),
            Style::new().fg(p.rule),
        )),
        area,
    );
}

/* The flash carries its own colour: a failure that renders the same cream as
   "unlocked 42 entries" is a failure nobody sees. Truncated to the row, since
   an error message is the longest thing the header ever holds. */
fn draw_header(frame: &mut Frame, app: &App, area: Rect) {
    let p = app.theme;
    let ink = match app.level {
        Level::Info => p.text,
        Level::Warn => p.warn,
        Level::Error => p.error,
    };
    /* Colour is not the only channel: under NO_COLOR every shade collapses to
       the terminal's own, and a failure then read exactly like a success. */
    let badge = match app.level {
        Level::Info => "",
        Level::Warn => "! ",
        Level::Error => "× ",
    };
    /* The vault keeps the right-hand end, so a flash no longer costs the one
       line that says which vault is open. */
    let name = app.vault_name();
    let width = area.width as usize;
    let lead = cols(" Sennel  ·  ");
    let tail = if name.is_empty() || width < lead + cols(&name) + 12 {
        String::new()
    } else {
        name
    };
    let room = width.saturating_sub(lead + cols(&tail) + 2);
    let stage = truncate(&format!("{badge}{}", app.stage), room);
    let gap = width
        .saturating_sub(lead + cols(&stage) + cols(&tail) + 1)
        .max(1);
    let spans = vec![
        Span::styled(" Sennel", Style::new().fg(p.accent)),
        p.faint("  ·  "),
        Span::styled(stage, Style::new().fg(ink)),
        Span::raw(" ".repeat(gap)),
        p.faint(tail),
    ];
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

/* The lock is a popup over the frame, not a line in the body: it is the only
   thing on screen and should read as one question. The body behind it stays
   empty — nothing is open yet. */
fn draw_body(frame: &mut Frame, app: &mut App, area: Rect) {
    match app.view {
        View::Unlock => draw_unlock(frame, app),
        View::Browser => draw_browser(frame, app, area),
    }
}

/* Groups left, entries middle, detail right past PREVIEW_FROM: the row keeps
   its title and user, so the pane only appears where all three fit without
   squeezing names down to nothing. Below that it is simply absent. */
const PREVIEW_FROM: u16 = 100;

fn draw_browser(frame: &mut Frame, app: &mut App, area: Rect) {
    let p = app.theme;
    if app.vault.is_none() {
        frame.render_widget(Paragraph::new(Line::from(p.faint(" no vault open"))), area);
        return;
    }
    /* Headers cost a row and answer the question three unlabelled columns
       could not: which pane is this, which folder am I in, and how the
       entries are ordered. Skipped on a short window, where a row of chrome
       is a row of list. */
    let heads = area.height > 6;
    app.heads = heads;
    if area.width >= PREVIEW_FROM {
        /* u32: the product overflows u16 past 32767 columns. */
        let detail = (u32::from(area.width) * 2 / 5).min(46) as u16;
        let [groups, entries, detail] = Layout::horizontal([
            Constraint::Percentage(25),
            Constraint::Min(1),
            Constraint::Length(detail),
        ])
        .areas(area);
        let (groups, entries, detail) = (
            head(frame, app, groups, Head::Groups, heads),
            head(frame, app, entries, Head::Entries, heads),
            head(frame, app, detail, Head::Detail, heads),
        );
        app.group_area = groups;
        app.entry_area = entries;
        draw_groups(frame, app, groups);
        draw_entries(frame, app, entries);
        draw_detail(frame, app, detail);
        app.viewport = (groups.height as usize).min(entries.height as usize).max(1);
        app.wide = true;
    } else {
        let [groups, entries] =
            Layout::horizontal([Constraint::Percentage(35), Constraint::Min(1)]).areas(area);
        let groups = head(frame, app, groups, Head::Groups, heads);
        let entries = head(frame, app, entries, Head::Entries, heads);
        /* What a page key moves by, which only the layout knows. The lower
           of the two, so a page never overshoots whichever pane is live. */
        app.viewport = (groups.height as usize).min(entries.height as usize).max(1);
        app.wide = false;
        app.group_area = groups;
        app.entry_area = entries;
        draw_groups(frame, app, groups);
        draw_entries(frame, app, entries);
    }
}

/// Joins as many leading segments as fit, so a narrow header drops the tail
/// rather than cutting every part of itself down to an ellipsis.
fn segments(width: usize, parts: &[String]) -> String {
    let mut out = String::new();
    for part in parts {
        let candidate = if out.is_empty() {
            format!(" {part}")
        } else {
            format!("{out} · {part}")
        };
        if cols(&candidate) > width {
            break;
        }
        out = candidate;
    }
    if out.is_empty() {
        out = truncate(&format!(" {}", parts[0]), width);
    }
    out
}

/// Which pane a header belongs to. `Detail` is not a focusable pane — it is
/// here so the third column gets a name like the other two.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Head {
    Groups,
    Entries,
    Detail,
}

/* Draws the pane's header row and hands back what is left for the list. The
   live pane's header is `text`, the others `muted`: focus then has a word as
   well as a marker, which is the only channel left when colour is off. */
fn head(frame: &mut Frame, app: &mut App, area: Rect, which: Head, on: bool) -> Rect {
    let p = app.theme;
    if !on || area.height < 2 {
        return area;
    }
    let [row, rest] = Layout::vertical([Constraint::Length(1), Constraint::Min(1)]).areas(area);
    let live = match which {
        Head::Groups => app.active_pane == Pane::Groups,
        Head::Entries => app.active_pane == Pane::Entries,
        Head::Detail => false,
    };
    let text = match which {
        Head::Groups => " groups".to_string(),
        Head::Detail => " detail".to_string(),
        /* The breadcrumb the panes could not answer: a tree that truncates
           names to `Clients and contrac…` cannot say where you are, and the
           order is invisible the moment `o`'s flash expires. */
        Head::Entries => {
            let searching = app.search.as_deref().is_some_and(|n| !n.is_empty());
            if searching {
                let (shown, total) = (app.entry_matches(), app.entry_total());
                let scope = if app.search_global {
                    "whole vault".to_string()
                } else {
                    app.here()
                };
                format!(" {scope} · {shown} of {total}")
            } else {
                let n = app.entry_rows().len();
                let plural = if n == 1 { "entry" } else { "entries" };
                /* Most to least useful, and the narrow pane keeps the front
                   of the list: a header truncated to "…stored…" has told
                   nobody anything. */
                segments(
                    area.width as usize,
                    &[
                        app.here(),
                        format!("{n} {plural}"),
                        format!("sort: {}", app.order.short()),
                    ],
                )
            }
        }
    };
    let style = if live {
        Style::new().fg(p.text).add_modifier(Modifier::BOLD)
    } else {
        Style::new().fg(p.muted)
    };
    let text = truncate(&text, area.width as usize);
    frame.render_widget(Paragraph::new(Line::from(Span::styled(text, style))), row);
    rest
}

/* Columns, not characters, and never straddling the edge: a width of one
   against a two-column glyph would otherwise take nothing and spill into the
   next field. Callers pad to the column count, which absorbs coming back
   short. A cut ends in `…` — without it `Root/Bankin` reads as a group
   somebody named Bankin. */
fn truncate(text: &str, width: usize) -> String {
    if cols(text) <= width {
        return text.to_string();
    }
    // One column is the ellipsis itself; none is nothing to say it in.
    let room = width.saturating_sub(1);
    let mut out = String::new();
    let mut used = 0;
    for c in text.chars() {
        let w = UnicodeWidthChar::width(c).unwrap_or(0);
        if used + w > room {
            break;
        }
        used += w;
        out.push(c);
    }
    if width > 0 {
        out.push('…');
    }
    out
}

/// One label column across the unlock boxes, the entry form, the group prompt
/// and the detail: three screens that should share a rhythm, and eight ran
/// "password" straight into its value.
const LABEL: usize = 10;

/* Only worth the column when the list actually runs off the pane. Drawn into
   the pane's own last column, so the lists hand that column back (see
   `list_width`) rather than letting the thumb land on a name. */
fn draw_scrollbar(frame: &mut Frame, area: Rect, len: usize, at: usize, p: &Palette) {
    if !overflows(area, len) {
        return;
    }
    let mut state = ScrollbarState::new(len).position(at);
    frame.render_stateful_widget(
        Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(None)
            .end_symbol(None)
            .thumb_style(Style::new().fg(p.muted))
            .track_symbol(None),
        area,
        &mut state,
    );
}

fn overflows(area: Rect, len: usize) -> bool {
    len > area.height as usize
}

/// Columns a row may use: the pane, less the marker and its space, less the
/// scrollbar's column when one is going to be drawn.
fn list_width(area: Rect, len: usize) -> usize {
    (area.width as usize)
        .saturating_sub(2 + usize::from(overflows(area, len)))
}

/* What fits on one entry row. The title used to be truncated to the pane and
   the username appended after it, so the line ran past the edge and ratatui
   clipped it — a username cut with no marker, the very thing `truncate`
   exists to prevent. Everything is measured against one budget now, and the
   least important column is the first to go. */
fn fit_row(avail: usize, title: &str, user: &str, group: &str) -> (String, String, String) {
    const GAP: usize = 2;
    const MIN_TITLE: usize = 8;
    const MIN_SIDE: usize = 6;
    let mut left = avail;
    let title_want = cols(title);
    let mut title_room = title_want.min(left);

    let fitted = |text: &str, prefix: usize, left: &mut usize, title_room: &mut usize| {
        if text.is_empty() {
            return String::new();
        }
        let want = cols(text) + prefix;
        let spare = left.saturating_sub(*title_room);
        /* Borrow from the title only down to a readable stub: a row whose
           name is three characters has stopped being a list. */
        let room = if spare >= want {
            want
        } else {
            let borrow = (*title_room).saturating_sub(MIN_TITLE);
            (spare + borrow).min(want)
        };
        if room < prefix + MIN_SIDE {
            return String::new();
        }
        if room > spare {
            *title_room -= room - spare;
        }
        *left -= room;
        truncate(text, room - prefix)
    };

    /* Group first, because it is the one the search band adds and the one the
       tree already answers. */
    let group = fitted(group, 4, &mut left, &mut title_room);
    let user = fitted(user, GAP, &mut left, &mut title_room);
    (truncate(title, title_room), user, group)
}

/* Pre-order with two cells of indent per depth: a flat list of names hides
   which folder an entry row belongs to, and the tree is the only place depth
   is visible. The marker is `cursor` in the live pane and `muted` in the
   other, so each pane still says where its own cursor is. */
fn draw_groups(frame: &mut Frame, app: &mut App, area: Rect) {
    let p = app.theme;
    let tree = app.group_tree();
    if tree.is_empty() {
        frame.render_widget(
            Paragraph::new(Line::from(p.faint(" no groups  ·  A adds one"))),
            area,
        );
        return;
    }
    let at = tree
        .iter()
        .position(|(id, _)| Some(*id) == app.group_cursor)
        .unwrap_or(0);
    let live = app.active_pane == Pane::Groups;
    let width = list_width(area, tree.len());
    let items: Vec<ListItem> = tree
        .iter()
        .map(|(id, depth)| {
            let selected = Some(*id) == app.group_cursor;
            let (name, expanded) = app
                .vault
                .as_ref()
                .and_then(|v| v.get_group(id))
                .map(|g| (g.name.clone(), g.is_expanded))
                .unwrap_or_default();
            /* ▸/▾ only where folding means something: a leaf gets blanks so
               names still line up down the pane. */
            let has_children = app
                .vault
                .as_ref()
                .is_some_and(|v| !v.groups_in(id).is_empty());
            let branch = if !has_children {
                "  "
            } else if expanded {
                "▾ "
            } else {
                "▸ "
            };
            let binned = app
                .vault
                .as_ref()
                .is_some_and(|v| v.in_recycle_bin(id));
            /* A count turns the tree into a map: every folder otherwise looks
               equally full, and the status bar only counts the whole vault. */
            let held = app.entries_in(id);
            let count = if held == 0 {
                String::new()
            } else {
                format!("  {held}")
            };
            let shown = truncate(
                &format!("{}{}{name}", "  ".repeat(*depth), branch),
                width.saturating_sub(cols(&count)),
            );
            let mark = p.mark(selected, live);
            /* The bin and everything in it draw back: a deleted row that
               looks exactly like a live one is how somebody copies a password
               they threw away last week. */
            let style = if binned {
                Style::new().fg(p.muted)
            } else {
                p.row(selected)
            };
            ListItem::new(Line::from(vec![
                mark,
                Span::styled(format!(" {shown}"), style),
                p.faint(count),
            ]))
        })
        .collect();
    /* Carried across frames, or ratatui recomputes the least scroll that makes
       the selection visible and pins the cursor to the last row. */
    app.group_scroll = app::scroll_to(app.group_scroll, at, tree.len(), area.height as usize);
    let mut state = ListState::default().with_offset(app.group_scroll);
    state.select(Some(at));
    frame.render_stateful_widget(List::new(items), area, &mut state);
    draw_scrollbar(frame, area, tree.len(), at, &p);
}

fn draw_entries(frame: &mut Frame, app: &mut App, area: Rect) {
    let p = app.theme;
    let rows = app.entry_rows();
    /* A live needle owns the empty state: "no entries here" would be a lie
       when the pane is global, and the way out (Esc) is part of the message. */
    let searching = app.search.as_deref().is_some_and(|n| !n.is_empty());
    if rows.is_empty() {
        let text = if searching {
            p.faint(format!(
                " nothing matches {} · esc clears it",
                app.search.as_deref().unwrap_or("")
            ))
        } else {
            p.faint(" no entries here  ·  a adds one")
        };
        frame.render_widget(Paragraph::new(Line::from(text)), area);
        return;
    }
    let at = rows
        .iter()
        .position(|id| Some(*id) == app.entry_cursor)
        .unwrap_or(0);
    let live = app.active_pane == Pane::Entries;
    let width = list_width(area, rows.len());
    /* The scroll before the rows, not after: only the window is built, so the
       pane has to know which window it is. Five thousand ListItems a frame
       cost twenty milliseconds to allocate and forty rows to show. */
    app.entry_scroll = app::scroll_to(app.entry_scroll, at, rows.len(), area.height as usize);
    let first = app.entry_scroll;
    let window: Vec<keepass::db::EntryId> = rows
        .iter()
        .skip(first)
        .take(area.height as usize)
        .copied()
        .collect();
    let needle = searching.then(|| app.search.clone().unwrap_or_default());
    let items: Vec<ListItem> = window
        .iter()
        .map(|id| {
            let selected = Some(*id) == app.entry_cursor;
            let has_code = app
                .vault
                .as_ref()
                .and_then(|v| v.get_entry(id))
                .is_some_and(|e| crate::vault::raw_otp(&e).is_some());
            let (title, user, group) = app
                .vault
                .as_ref()
                .and_then(|v| {
                    let entry = v.get_entry(id)?;
                    let path = v
                        .parent_group_of_entry(id)
                        .map(|g| v.group_path(&g).join("/"))
                        .unwrap_or_default();
                    Some((
                        EntryExt::title(&entry).to_string(),
                        EntryExt::username(&entry).to_string(),
                        path,
                    ))
                })
                .unwrap_or_default();
            let (name, user, group) = fit_row(
                width,
                &title,
                &user,
                /* Global search pulls rows out of their folder, so the pane
                   says where each one lives — the same dim-suffix rule as the
                   user, and the first column dropped when space runs out. */
                if searching { &group } else { "" },
            );
            /* Which characters the needle matched, for this row only: the
               ones scrolled off the pane light nothing. */
            let hits = match &needle {
                Some(needle) => app.searcher.indices(needle, &title),
                None => Vec::new(),
            };
            let mark = p.mark(selected, live);
            let mut spans = vec![mark, Span::raw(" ")];
            spans.extend(highlight(&name, &hits, p.row(selected), &p));
            if !user.is_empty() {
                spans.push(p.faint(format!("  {user}")));
            }
            if !group.is_empty() {
                spans.push(p.faint(format!("  · {group}")));
            }
            /* A field lookup, not a parse: the marker says a row has a code
               without pricing every row on every frame. */
            if has_code {
                spans.push(p.faint(" ⊙"));
            }
            ListItem::new(Line::from(spans))
        })
        .collect();
    /* The widget is handed the window, so its own indices are window-local;
       the scrollbar still speaks in whole-list terms. */
    let mut state = ListState::default();
    state.select(Some(at.saturating_sub(first)));
    frame.render_stateful_widget(List::new(items), area, &mut state);
    draw_scrollbar(frame, area, rows.len(), at, &p);
}

/* The row keeps only title and user, so the pane says the rest: url, notes,
   and the password masked to a fixed run of bullets. Fixed length because
   even the length is something the screen may not reveal. */
fn draw_detail(frame: &mut Frame, app: &App, area: Rect) {
    let p = app.theme;
    let block = Block::new()
        .borders(Borders::LEFT)
        .border_style(Style::new().fg(p.rule));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.width == 0 || inner.height == 0 {
        return;
    }
    let width = inner.width as usize;
    let Some(entry) = app.selected_entry() else {
        frame.render_widget(
            Paragraph::new(Line::from(p.faint(" no entry  ·  a adds one"))),
            inner,
        );
        return;
    };
    let row = |label: &str, value: String, style: Style| {
        Line::from(vec![
            p.faint(format!(" {label:<LABEL$}")),
            Span::styled(value, style),
        ])
    };
    let cream = Style::new().fg(p.text);
    let faint = Style::new().fg(p.muted);
    let mut lines = vec![
        Line::from(Span::styled(
            truncate(entry.title(), width),
            p.row(true),
        )),
        Line::default(),
        row(
            "user",
            truncate(entry.username(), width.saturating_sub(LABEL + 1)),
            cream,
        ),
        row(
            "pass",
            if app.show_password {
                truncate(entry.password(), width.saturating_sub(LABEL + 1))
            } else {
                "••••••••".to_string()
            },
            cream,
        ),
    ];
    if !entry.url().is_empty() {
        lines.push(row(
            "url",
            truncate(entry.url(), width.saturating_sub(LABEL + 1)),
            faint,
        ));
    }
    /* First line only: the row is one row, and a note that wraps the pane is
       what Enter's popup is for. */
    let notes = entry.notes().lines().next().unwrap_or("");
    if !notes.is_empty() {
        lines.push(row(
            "notes",
            truncate(notes, width.saturating_sub(LABEL + 1)),
            faint,
        ));
    }
    /* A one-time code is the field people reach for most and the one Sennel
       could not show at all: an entry with `otp` looked exactly like an entry
       without one, and the answer was to pick up a phone. */
    if let Some((code, left)) = crate::vault::totp_now(&entry) {
        lines.push(Line::from(vec![
            p.faint(format!(" {:<LABEL$}", "totp")),
            Span::styled(code, Style::new().fg(p.cursor)),
            p.faint(format!("  {left}s")),
        ]));
    }
    for extra in crate::vault::extras(&entry) {
        lines.push(Line::from(p.faint(format!(" {:<LABEL$}{extra}", ""))));
    }
    lines.push(row("group", truncate(&app.here(), width.saturating_sub(LABEL + 1)), faint));
    for (label, value) in stamps(&entry) {
        lines.push(row(label, value, faint));
    }
    /* Under the fields, not at the foot of twenty blank rows: a hint the eye
       never travels to is a hint nobody reads. */
    lines.push(Line::default());
    lines.push(Line::from(Span::styled(
        format!(" {}", "─".repeat(width.saturating_sub(2))),
        Style::new().fg(p.rule),
    )));
    lines.push(Line::from(p.faint(truncate(
        " y p U copy · t totp · * reveal · e edit",
        width,
    ))));
    lines.truncate(inner.height as usize);
    frame.render_widget(Paragraph::new(lines), inner);
}

/* KDBX stores stamps in UTC and may store none at all. Shown in local time:
   "this afternoon" is what a timestamp is read for, and a clock the reader
   has to shift in their head is a clock they have to check. */
fn stamps(entry: &keepass::db::EntryRef<'_>) -> Vec<(&'static str, String)> {
    [
        ("updated", entry.times.last_modification),
        ("created", entry.times.creation),
    ]
    .into_iter()
    .filter_map(|(label, t)| t.map(|t| (label, local(t))))
    .collect()
}

fn local(utc: chrono::NaiveDateTime) -> String {
    chrono::Local
        .from_utc_datetime(&utc)
        .format("%Y-%m-%d %H:%M")
        .to_string()
}

/* Enter's detail popup: the whole entry, wide enough for a url and tall
   enough for the notes, on the 80-column terminal where no side pane fits.
   Same masking rule as the pane — `*` is the only way to a plain password. */
fn draw_detail_popup(frame: &mut Frame, app: &App) {
    let p = app.theme;
    let Some(entry) = app.selected_entry() else {
        return;
    };
    let area = frame.area();
    /* Room for the frame and a margin either side; the popup never grows past
       what the notes actually need. */
    let width = area.width.saturating_sub(8).clamp(20, 76);
    let inner = width.saturating_sub(4) as usize;
    let cream = Style::new().fg(p.text);
    let faint = Style::new().fg(p.muted);
    let row = |label: &str, value: String, style: Style| {
        Line::from(vec![
            p.faint(format!(" {label:<LABEL$}")),
            Span::styled(value, style),
        ])
    };
    let value = inner.saturating_sub(LABEL + 1);
    let mut lines = vec![
        row("user", truncate(entry.username(), value), cream),
        row(
            "password",
            if app.show_password {
                truncate(entry.password(), value)
            } else {
                "••••••••".to_string()
            },
            cream,
        ),
    ];
    if !entry.url().is_empty() {
        lines.push(row("url", truncate(entry.url(), value), faint));
    }
    /* Notes get a block of their own: the pane's one-line form is most of
       why this popup exists. */
    let notes: Vec<&str> = entry.notes().lines().take(NOTE_LINES).collect();
    if !notes.is_empty() {
        lines.push(Line::default());
        for (n, note) in notes.iter().enumerate() {
            let label = if n == 0 { "notes" } else { "" };
            lines.push(row(label, truncate(note, value), faint));
        }
    }
    if let Some((code, left)) = crate::vault::totp_now(&entry) {
        lines.push(Line::from(vec![
            p.faint(format!(" {:<LABEL$}", "totp")),
            Span::styled(code, Style::new().fg(p.cursor)),
            p.faint(format!("  {left}s · t copies")),
        ]));
    }
    for extra in crate::vault::extras(&entry) {
        lines.push(Line::from(p.faint(format!(" {:<LABEL$}{extra}", ""))));
    }
    lines.push(row("group", truncate(&app.here(), value), faint));
    for (label, stamp) in stamps(&entry) {
        lines.push(row(label, stamp, faint));
    }
    lines.push(Line::default());
    lines.push(Line::from(vec![
        Span::styled(" y p U", Style::new().fg(p.accent)),
        p.faint(" copy   "),
        Span::styled("*", Style::new().fg(p.accent)),
        p.faint(" reveal   "),
        Span::styled("e", Style::new().fg(p.accent)),
        p.faint(" edit   "),
        Span::styled("j k", Style::new().fg(p.accent)),
        p.faint(" next entry   "),
        Span::styled("esc", Style::new().fg(p.accent)),
        p.faint(" close"),
    ]));
    let title = truncate(entry.title(), inner);
    popup(frame, &title, lines, width, &p);
}

/// Where the popup stops reading notes: past this it is an editor, not a view.
const NOTE_LINES: usize = 8;

/* One question with two or three boxes: the password always, the key file
   beside it (empty means none), the confirm joining only when creating. Only
   the focused box draws the block, or the popup shows two cursors and neither
   is where typing lands. The password is bullets end to end unless `^r`
   revealed it — length is otherwise the only thing about it the screen may
   show. */
fn draw_unlock(frame: &mut Frame, app: &App) {
    let p = app.theme;
    use crate::app::UnlockField;
    /* The picker stands in for this box while it is open: two popups over
       each other read as one broken one, and the boxes behind are not
       answering anything until a file is chosen. */
    if app.browse.is_some() {
        return;
    }
    let title = if app.unlock_new && app.db_path.is_some() {
        "new database"
    } else if app.db_path.is_none() {
        "no database"
    } else {
        "unlock"
    };

    let mut rows: Vec<Line> = Vec::new();
    if app.db_path.is_none() && !app.unlock_new {
        rows.push(Line::from(p.faint(
            " no vault yet  ·  set one in the file box below",
        )));
        rows.push(Line::default());
    }

    /* Byte offset of a char-index caret, shared with the editor: a byte index
       lands inside a multi-byte character the moment a path has an accent in
       it, and slicing panics. */
    let split_at_char = |text: &str, caret: usize| {
        text.char_indices()
            .nth(caret)
            .map_or(text.len(), |(at, _)| at)
    };
    let field = |label: &str, value: &str, at: UnlockField, secret: bool| {
        let focused = app.unlock_field == at;
        /* `^r` reveals: the caret is a char index over the raw value, and the
           masked form has the same char count, so the block lands in the
           same place either way. */
        let shown = if secret && !app.unlock_reveal {
            "•".repeat(value.chars().count())
        } else {
            value.to_string()
        };
        /* Drawn between the halves, so the block is where the next character
           lands rather than always at the end of the line. */
        let text = if focused {
            let (before, after) = shown.split_at(split_at_char(&shown, app.caret));
            format!("{before}█{after}")
        } else {
            shown
        };
        let style = if focused {
            Style::new().fg(p.text)
        } else {
            Style::new().fg(p.muted)
        };
        Line::from(vec![
            p.faint(format!(" {label:<LABEL$}")),
            Span::styled(text, style),
        ])
    };
    /* The file box lives on the popup itself: editing it and pressing Enter
       re-points the session at another vault, which is how one screen serves
       many vaults. It is display text, never a secret, so it draws plainly. */
    rows.push(field(
        "file",
        &app.unlock_file,
        UnlockField::File,
        false,
    ));
    rows.push(field(
        "password",
        &app.unlock_password,
        UnlockField::Password,
        true,
    ));
    rows.push(field(
        "key file",
        &app.unlock_keyfile,
        UnlockField::KeyFile,
        false,
    ));
    if app.unlock_new {
        rows.push(field(
            "confirm",
            &app.unlock_confirm,
            UnlockField::Confirm,
            true,
        ));
    }
    rows.push(Line::default());
    /* Enter does three different things on this screen, so the hint names the
       one the focused box will do. */
    let go = if app.unlock_field == UnlockField::File {
        "enter apply path"
    } else if app.unlock_new {
        "enter create"
    } else {
        "enter unlock"
    };
    rows.push(Line::from(p.faint(format!(
        " tab field   {go}   ^o browse   esc clear   ^r reveal"
    ))));
    let width = rows.iter().map(|l| l.width() as u16).max().unwrap_or(0) + 3;
    popup(frame, title, rows, width.max(20), &p);
}

/* Left to right in priority order, with `h keys` right-aligned in whatever
   is left: the bar used to append until the line clipped, and the first thing
   off the end was the one hint that always matters. What does not fit is
   dropped whole — half a count is worse than no count. */
fn draw_status(frame: &mut Frame, app: &mut App, area: Rect) {
    let p = app.theme;
    const KEYS: &str = "h keys";
    let width = area.width as usize;
    /* Narrower than this and the copy keys are what has to go: `h keys` is
       the row's reason to exist, and at 24 columns it was the thing falling
       off the end. */
    if width < 40 {
        let keys = if app.view == View::Browser { KEYS } else { "F1 keys" };
        let spans = vec![
            Span::raw(" ".repeat(pad(width, 0, cols(keys)))),
            p.faint(keys),
        ];
        frame.render_widget(Paragraph::new(Line::from(spans)), area);
        return;
    }
    /* The lock screen takes every printable key as text, so its bar names
       only chords: `h` there types an h, and a bar promising "h keys" on the
       first screen anybody sees was promising a key that does not exist. */
    if app.view != View::Browser {
        const LOCK_KEYS: &str = "F1 keys";
        let left = "  enter unlock   ^r reveal   ^c quit";
        let spans = vec![
            Span::raw(" "),
            p.faint(left),
            Span::raw(" ".repeat(pad(width, cols(left) + 1, cols(LOCK_KEYS)))),
            p.faint(LOCK_KEYS),
        ];
        frame.render_widget(Paragraph::new(Line::from(spans)), area);
        return;
    }
    /* The copy keys are the bar: they name what the whole app is for, so they
       are what everything else has to fit around. */
    /* Dim when there is nothing under the cursor to copy: three keys offered
       in gold that all answer "no entry here" is a bar making promises the
       selection cannot keep. */
    let armed = app.selected_entry().is_some();
    let mut spans = vec![
        Span::raw(" "),
        Span::styled(
            "y user",
            Style::new().fg(if armed { p.accent } else { p.muted }),
        ),
        p.faint("   p pass   U url"),
    ];
    let mut used = cols(" y user   p pass   U url");
    /* In the order they may be dropped, last first: unsaved work outranks a
       count, and a count outranks the notes about keys the bar also names. */
    let mut optional: Vec<Span> = Vec::new();
    if app.working() {
        optional.push(Span::styled("  unsaved", Style::new().fg(p.warn)));
    }
    /* A secret is on the clipboard until this reaches zero. The flash says so
       once; the chip says so for as long as it is true. */
    if let Some(left) = app.clipboard_left() {
        optional.push(Span::styled(
            format!("  clipboard {left}s"),
            Style::new().fg(p.cursor),
        ));
    }
    /* The entries header counts the matches where it is drawn; on a window
       too short for headers the bar is the only place left to say it. */
    if app.search.is_some() && !app.heads {
        let (shown, total) = (app.entry_matches(), app.entry_total());
        optional.push(Span::styled(
            format!("  {shown} of {total} shown"),
            Style::new().fg(p.accent),
        ));
    }
    if let Some(vault) = &app.vault {
        let groups = app.group_tree().len();
        let entries = vault.entry_count();
        let g = if groups == 1 { "group" } else { "groups" };
        let e = if entries == 1 { "entry" } else { "entries" };
        optional.push(p.faint(format!("  {groups} {g} · {entries} {e}")));
    }
    /* An armed cut and a live undo slot are one keypress from mattering, so
       they are named — but they are also the first things the bar can lose. */
    if let Some(note) = app.cut_note() {
        optional.push(Span::styled(format!("  {note} · V pastes"), Style::new().fg(p.warn)));
    }
    if let Some(note) = app.undo_note() {
        optional.push(Span::styled(format!("  {note}"), Style::new().fg(p.warn)));
    }
    for span in optional {
        let want = cols(&span.content);
        if used + want + cols(KEYS) + 3 > width {
            continue;
        }
        used += want;
        spans.push(span);
    }
    spans.push(Span::raw(" ".repeat(pad(width, used, cols(KEYS)))));
    spans.push(p.faint(KEYS));
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// Gap that right-aligns the trailing hint, and one space when the line is
/// already full: a bar that clips must not also run its words together.
fn pad(width: usize, used: usize, tail: usize) -> usize {
    width.saturating_sub(used + tail + 1).max(1)
}

/* The filter band, one row between body and status: `/needle█` like earworm.
   The caret is a block between the split halves of the needle, the same
   char-index rule as every other box in the app. */
fn draw_search(frame: &mut Frame, app: &App, area: Rect) {
    let p = app.theme;
    let needle = app.search.as_deref().unwrap_or_default();
    /* A kept filter gave the keys back: a caret on a box that no longer takes
       typing reads as one that does. */
    if !app.band {
        let line = Line::from(vec![
            Span::styled(format!("/{needle}"), Style::new().fg(p.accent)),
            p.faint("  esc clears"),
        ]);
        frame.render_widget(Paragraph::new(line), area);
        return;
    }
    let at = char_index_to_byte(needle, app.search_caret);
    let (head, tail) = needle.split_at(at.min(needle.len()));
    let line = Line::from(vec![
        Span::styled("/", Style::new().fg(p.accent)),
        Span::styled(head.to_string(), Style::new().fg(p.text)),
        Span::styled("█", Style::new().fg(p.accent)),
        Span::styled(tail.to_string(), Style::new().fg(p.text)),
        p.faint(if app.search_global {
            "  enter keep · esc clear · ^g this group"
        } else {
            "  enter keep · esc clear · ^g whole vault"
        }),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

fn popup(frame: &mut Frame, title: &str, lines: Vec<Line<'_>>, width: u16, p: &Palette) {
    let height = lines.len() as u16 + 2;
    let area = frame.area();
    let at = Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width.min(area.width),
        height.min(area.height),
    );
    frame.render_widget(Clear, at);
    let block = Block::new()
        .borders(Borders::ALL)
        .border_style(Style::new().fg(p.accent))
        .title(Span::styled(format!(" {title} "), Style::new().fg(p.accent)))
        .style(Style::new().bg(p.surface));
    let inner = block.inner(at);
    frame.render_widget(block, at);
    frame.render_widget(Paragraph::new(lines), inner);
}

/* The file picker: directories and vaults only, the current directory in the
   title, and a typed filter that narrows rather than ranks. Nobody knows the
   path to a vault they have not opened yet. */
fn draw_browse(frame: &mut Frame, app: &App) {
    let p = app.theme;
    let Some(browse) = &app.browse else {
        return;
    };
    let area = frame.area();
    let width = area.width.saturating_sub(8).clamp(24, 72);
    let inner = width.saturating_sub(4) as usize;
    /* Room for the frame, the title, the hint and a blank: the list takes
       whatever is left rather than growing the popup off the screen. */
    let room = (area.height as usize).saturating_sub(7).clamp(1, 18);
    let shown = browse.shown();
    let mut lines: Vec<Line> = Vec::new();
    if let Some(problem) = &browse.problem {
        lines.push(Line::from(Span::styled(
            truncate(&format!(" {problem}"), inner),
            Style::new().fg(p.error),
        )));
    } else if shown.is_empty() {
        lines.push(Line::from(p.faint(if browse.filter.is_empty() {
            " no vaults or folders here  ·  ← goes up".to_string()
        } else {
            format!(" nothing matches {}  ·  backspace clears", browse.filter)
        })));
    }
    /* The window follows the cursor: a list that always starts at the top
       hides everything past the fold once the cursor is past it. */
    let first = browse.cursor.saturating_sub(room.saturating_sub(1));
    for (n, row) in shown.iter().enumerate().skip(first).take(room) {
        let live = n == browse.cursor;
        let mark = if live { p.lit("▌") } else { Span::raw(" ") };
        let name = if row.dir {
            format!("{}/", row.name)
        } else {
            row.name.clone()
        };
        let style = if row.dir {
            Style::new().fg(p.muted)
        } else {
            p.row(live)
        };
        lines.push(Line::from(vec![
            mark,
            Span::styled(format!(" {}", truncate(&name, inner.saturating_sub(2))), style),
        ]));
    }
    if shown.len() > room {
        lines.push(p.faint(format!(
            " {} of {} shown",
            room.min(shown.len()),
            shown.len()
        )).into());
    }
    lines.push(Line::default());
    if !browse.filter.is_empty() {
        lines.push(Line::from(vec![
            Span::styled(" /", Style::new().fg(p.accent)),
            Span::styled(browse.filter.clone(), Style::new().fg(p.text)),
        ]));
    }
    lines.push(Line::from(p.faint(truncate(
        " enter open · ← up · type to narrow · esc cancel",
        inner,
    ))));
    /* The directory, tail first: the end of a long path is the part that says
       where you are. */
    let title = browse.dir.display().to_string();
    let title = if cols(&title) > inner.saturating_sub(2) {
        let keep: String = title
            .chars()
            .rev()
            .take(inner.saturating_sub(3))
            .collect::<Vec<char>>()
            .into_iter()
            .rev()
            .collect();
        format!("…{keep}")
    } else {
        title
    };
    popup(frame, &title, lines, width, &p);
}

/* Its own question rather than a prompt: no vault is blocked on the answer,
   so it carries no reply channel. Only a named key confirms, so an
   unrecognised key must not be an accidental yes. */
fn draw_confirm(frame: &mut Frame, app: &App, what: &Confirm) {
    let p = app.theme;
    let _ = app;
    /* The title is the part that truncates, never the sentence: a question
       that renders as "…this cannot be" has lost the only word doing any
       work. Sized against the terminal first, then the title fills the rest. */
    let room = (frame.area().width as usize).saturating_sub(4);
    let (title, question, yes, after) = match what {
        Confirm::Quit => (
            "quit?",
            " unsaved changes would be lost".to_string(),
            Span::styled(" q  quit", Style::new().fg(p.accent)),
            "",
        ),
        /* The title travels in the confirm so the answer is about a row the
           user can see. A name is user-chosen text, never a secret.

           Two questions, not one with a hedge. Outside the bin the row is
           moved and `u` brings it back, so the box says so: a warning that
           overstates the risk is a warning people learn to click through.
           Inside the bin nothing brings it back, and that box says that. */
        Confirm::DeleteEntry { title, forever, .. } => (
            if *forever { "delete for good?" } else { "delete?" },
            delete_question("entry", title, room, *forever),
            Span::styled(" y  delete", Style::new().fg(p.error)),
            if *forever { "this cannot be undone" } else { "u restores it" },
        ),
        Confirm::DeleteGroup { title, forever, .. } => (
            if *forever { "delete for good?" } else { "delete?" },
            delete_question("group", title, room, *forever),
            Span::styled(" y  delete", Style::new().fg(p.error)),
            /* A group takes its whole subtree either way. `u` puts the
               subtree back; the permanent one has nothing to put back. */
            if *forever {
                "this cannot be undone"
            } else {
                "contents included · u restores it"
            },
        ),
    };
    let lines = vec![
        Line::from(Span::styled(question, Style::new().fg(p.text))),
        Line::default(),
        Line::from(vec![
            yes,
            p.faint("     esc  keep going"),
            p.faint(if after.is_empty() {
                String::new()
            } else {
                format!("     {after}")
            }),
        ]),
    ];
    let width = lines.iter().map(|l| l.width() as u16).max().unwrap_or(0) + 3;
    popup(frame, title, lines, width, &p);
}

/// The question with the name cut to fit, so the verb always renders.
fn delete_question(kind: &str, title: &str, room: usize, forever: bool) -> String {
    // The verb is the difference, so it is the part that never truncates.
    let verb = if forever { "delete" } else { "bin" };
    let fixed = cols(&format!(" {verb} {kind} “”?"));
    format!(
        " {verb} {kind} “{}”?",
        truncate(title, room.saturating_sub(fixed).max(8))
    )
}

/* The modal entry editor: five labelled boxes, the caret block only in the
   focused one. Shape mirrors the unlock screen so muscle memory carries over.
   The password box masks as bullets and, on edit, advertises that empty
   keeps — the one box where emptiness has a meaning. */
fn split_at_char(text: &str, caret: usize) -> (String, String) {
    let mut first = text.chars();
    let head: String = first.by_ref().take(caret).collect();
    (head, first.collect())
}

fn draw_form(frame: &mut Frame, app: &App) {
    let p = app.theme;
    let Some(form) = &app.form else {
        return;
    };

    let row = |label: &'static str, field: FormField, value: &str| -> Line<'_> {
        let focused = form.field == field;
        let shown = match field {
            /* The edit password box starts empty on purpose; typed content
               masks. The hint only shows while the box holds nothing. */
            FormField::Password if value.is_empty() && !form.password_touched => {
                "(leave empty to keep)".to_string()
            }
            FormField::Password if form.reveal => value.to_string(),
            FormField::Password => "•".repeat(value.chars().count()),
            /* The seed box says which of the two empties it is in: an entry
               that already has a code keeps it, and one that does not says
               what it will take. */
            FormField::Otp if value.is_empty() && !form.otp_touched => {
                if form.had_otp {
                    "(leave empty to keep)".to_string()
                } else {
                    "(otpauth:// url or the printed secret)".to_string()
                }
            }
            FormField::Otp if form.reveal => value.to_string(),
            FormField::Otp => "•".repeat(value.chars().count()),
            _ => value.to_string(),
        };
        let (head, tail) = split_at_char(&shown, if focused { form.caret } else { 0 });
        let style = if focused {
            Style::new().fg(p.text)
        } else {
            Style::new().fg(p.muted)
        };
        Line::from(vec![
            Span::styled(format!(" {label:<LABEL$}"), style),
            Span::styled(head, style),
            /* The block caret sits between the split halves; an unfocused
               box draws none, so the eye finds the live box first. */
            Span::styled(if focused { "█" } else { "" }, style),
            Span::styled(tail, style),
        ])
    };

    /* Notes are the one field that holds newlines, and rendering them as one
       Line welded them together — "card ending 4417second line" — while Enter
       submitted the form, so a break could be destroyed but never typed. One
       row per line, `⏎` where a break is, and the caret lands on the row it
       is actually in. */
    let notes_rows = |value: &str, focused: bool, caret: usize| -> Vec<Line<'_>> {
        let style = if focused {
            Style::new().fg(p.text)
        } else {
            Style::new().fg(p.muted)
        };
        let mut out = Vec::new();
        let mut seen = 0;
        let parts: Vec<&str> = value.split('\n').collect();
        for (n, part) in parts.iter().enumerate() {
            let len = part.chars().count();
            let last = n + 1 == parts.len();
            let label = if n == 0 { "notes" } else { "" };
            let mut spans = vec![Span::styled(format!(" {label:<LABEL$}"), style)];
            /* The caret belongs to exactly one row: the one whose span of the
               string contains it, and the break itself counts as a column. */
            if focused && caret >= seen && caret <= seen + len {
                let (head, tail) = split_at_char(part, caret - seen);
                spans.push(Span::styled(head, style));
                spans.push(Span::styled("█".to_string(), style));
                spans.push(Span::styled(tail, style));
            } else {
                spans.push(Span::styled((*part).to_string(), style));
            }
            if !last {
                spans.push(p.faint("⏎"));
            }
            out.push(Line::from(spans));
            seen += len + 1;
        }
        out
    };

    let mut lines = vec![
        row("title", FormField::Title, &form.title),
        row("username", FormField::Username, &form.username),
        row("password", FormField::Password, &form.password),
    ];
    /* What the box is worth, in the only terms the app can honestly give:
       the classes actually present times the length. Shown while the box
       holds something, so `^s` and a typed password answer the same way. */
    if !form.password.is_empty() {
        let bits = crate::generator::typed_bits(&form.password);
        let word = crate::generator::strength(bits);
        let ink = if bits < 60.0 { p.warn } else { p.cursor };
        lines.push(Line::from(vec![
            p.faint(format!(" {:<LABEL$}", "")),
            Span::styled(format!("~{bits:.0} bits · {word}"), Style::new().fg(ink)),
        ]));
    }
    lines.push(row("url", FormField::Url, &form.url));
    lines.push(row("otp", FormField::Otp, &form.otp));
    /* The code the typed seed produces, right now. A seed is a run of
       characters nobody can check by eye, and the site asks for a code to
       confirm the setup — so the box answers with one before it is saved. */
    if form.otp_touched && !form.otp.trim().is_empty() {
        let note = match crate::vault::totp_url(&form.otp, &form.title, &form.username) {
            Ok(url) => match url.parse::<keepass::db::TOTP>().ok().and_then(|t| t.value_now().ok()) {
                Some(code) => (
                    format!("{} · {}s", code.code, code.valid_for.as_secs()),
                    p.cursor,
                ),
                None => ("cannot read the clock".to_string(), p.warn),
            },
            Err(why) => (why, p.warn),
        };
        lines.push(Line::from(vec![
            p.faint(format!(" {:<LABEL$}", "")),
            Span::styled(note.0, Style::new().fg(note.1)),
        ]));
    }
    lines.extend(notes_rows(
        &form.notes,
        form.field == FormField::Notes,
        form.caret,
    ));
    lines.push(Line::default());
    lines.push(Line::from(vec![
        Span::styled(" enter", Style::new().fg(p.accent)),
        p.faint(" save   "),
        Span::styled("^s", Style::new().fg(p.accent)),
        p.faint(" generate   "),
        Span::styled("^r", Style::new().fg(p.accent)),
        p.faint(" reveal   "),
        Span::styled("tab", Style::new().fg(p.accent)),
        p.faint(" next   "),
        Span::styled("esc", Style::new().fg(p.accent)),
        p.faint(" throw away"),
    ]));
    if form.field == FormField::Notes {
        lines.push(Line::from(p.faint(" alt+enter starts a new line")));
    }
    let width = lines.iter().map(|l| l.width() as u16).max().unwrap_or(0) + 3;
    /* Entries land in the cursor group, which may be scrolled out of sight;
       the title is the only place that can say so before Enter. */
    let title = match form.kind {
        FormKind::Add => format!("new entry in {}", app.here()),
        FormKind::Edit(_) => format!("edit entry · {}", app.here()),
    };
    popup(frame, &truncate(&title, width.saturating_sub(4) as usize), lines, width, &p);
}

/* One entry per line in three aligned columns. Only live keys: a row naming
   a key that does nothing on this screen is documentation for a bug. */
fn draw_help(frame: &mut Frame, app: &App) {
    let p = app.theme;
    /* Only live keys: a row naming a key that does nothing on this screen is
       documentation for a bug. The lock owns every printable key, so its
       table names the boxes rather than the browser's list. */
    let rows: Vec<(&str, &str, &str)> = if app.view == View::Unlock {
        vec![
            ("type", "a–z  0–9", "the boxes take every key"),
            ("move", "tab  ↑ ↓", "between boxes"),
            ("edit", "^u  ^w", "clear box, kill word"),
            ("reveal", "^r", "show the password plainly"),
            ("theme", "^t", "next palette · remembered"),
            ("find", "^o", "pick a vault file from a list"),
            ("go", "enter", "unlock · apply path from the file box"),
            ("close", "any key", "dismisses this table"),
            ("quit", "^c", ""),
        ]
    } else {
        vec![
            ("move", "j k  ↑ ↓", "through the panes"),
            ("page", "^d ^u  PgUp PgDn", "a screen at a time"),
            ("ends", "g G", "top, bottom of the pane"),
            ("panes", "Tab", "groups ↔ entries"),
            ("open", "enter", "open group, open entry"),
            ("copy", "y p U t", "username, password, url, one-time code"),
            ("reveal", "*", "show the password"),
            ("edit", "a e D", "add, edit, delete entry"),
            ("groups", "A E D", "add, rename, delete group"),
            ("cut", "X V", "cut, paste"),
            ("fold", "← →", "collapse, expand · ← hops from entries"),
            ("order", "o", "entries: name, recent, updated"),
            ("find", "/", "fuzzy search · ^g narrows it to this group"),
            ("match", "n N", "next, previous match"),
            ("undo", "u", "one level"),
            ("save", "^s  ^r", "save now · reload the file on disk"),
            ("lock", "^l", "lock now"),
            ("master", "^p", "change the master password"),
            ("theme", "^t", "next palette · remembered"),
            ("back", "esc", "drop cut, clear filter, then report"),
            ("quit", "q  ^c", ""),
        ]
    };

    let group = rows.iter().map(|r| r.0.chars().count()).max().unwrap_or(0) + 2;
    let key = rows.iter().map(|r| r.1.chars().count()).max().unwrap_or(0) + 2;

    let render = |(label, keys, what): &(&str, &str, &str)| {
        vec![
            Span::styled(format!(" {label:group$}"), Style::new().fg(p.muted)),
            Span::styled(format!("{keys:key$}"), Style::new().fg(p.accent)),
            Span::styled((*what).to_string(), Style::new().fg(p.text)),
        ]
    };
    let mut lines: Vec<Line> = rows.iter().map(|r| Line::from(render(r))).collect();

    /* A help table that silently loses its last five rows is worse than a
       short one: on an 80×14 window this used to draw twelve of seventeen
       keys, with the border sitting on the status bar. Two columns first,
       since the window is usually wider than it is short. */
    let area = frame.area();
    let fits = |lines: &[Line]| lines.len() as u16 + 2 <= area.height;
    if !fits(&lines) {
        let half = lines.len().div_ceil(2);
        let paired: Vec<Line> = (0..half)
            .map(|n| {
                let mut spans = render(&rows[n]);
                if let Some(right) = rows.get(n + half) {
                    spans.push(p.faint("   "));
                    spans.extend(render(right));
                }
                Line::from(spans)
            })
            .collect();
        let width = paired.iter().map(|l| l.width() as u16).max().unwrap_or(0) + 3;
        if fits(&paired) && width <= area.width {
            lines = paired;
        }
    }
    /* Still too tall: say how many rows are missing rather than dropping them
       behind the border, and name the one thing that brings them back. */
    if !fits(&lines) {
        let room = (area.height as usize).saturating_sub(3).max(1);
        let hidden = lines.len() - room;
        lines.truncate(room);
        lines.push(p.faint(format!(" +{hidden} more · a taller window shows them")).into());
    }

    let content = lines.iter().map(|l| l.width() as u16).max().unwrap_or(0);
    popup(frame, "keys", lines, content + 3, &p);
}

/* The change-password prompt: two masked boxes, and a line saying what is
   about to happen. Worth more words than the other popups, because this is
   the one action in Sennel nobody can take back and nothing can remind them
   of — a forgotten master password is a lost vault. */
fn draw_rekey(frame: &mut Frame, app: &App) {
    let p = app.theme;
    let Some(rekey) = &app.rekey else {
        return;
    };
    let file = app
        .vault
        .as_ref()
        .and_then(|v| v.path())
        .map(|path| path.display().to_string())
        .unwrap_or_default();
    let row = |label: &str, value: &str, focused: bool| {
        /* Masked to its own length, not a fixed run: on the box you are
           typing into, the count is the only feedback there is, and it is
           already on your screen and nowhere else. */
        let shown = if rekey.reveal {
            value.to_string()
        } else {
            "•".repeat(value.chars().count())
        };
        let (head, tail) = split_at_char(&shown, if focused { rekey.caret } else { 0 });
        let style = if focused {
            Style::new().fg(p.text)
        } else {
            Style::new().fg(p.muted)
        };
        Line::from(vec![
            Span::styled(format!(" {label:<LABEL$}"), style),
            Span::styled(head, style),
            Span::styled(if focused { "█" } else { "" }, Style::new().fg(p.accent)),
            Span::styled(tail, style),
        ])
    };
    let mut lines = vec![
        Line::from(p.faint(truncate(&format!(" {file}"), 60))),
        Line::default(),
        row("new", &rekey.password, rekey.field == crate::app::RekeyField::New),
        row("again", &rekey.confirm, rekey.field == crate::app::RekeyField::Again),
    ];
    /* Strength on the way in, the same estimate the entry form gives: a
       master password is the one worth measuring before it is committed. */
    if !rekey.password.is_empty() {
        let bits = crate::generator::typed_bits(&rekey.password);
        let word = crate::generator::strength(bits);
        let ink = if bits < 60.0 { p.warn } else { p.cursor };
        lines.push(Line::from(vec![
            p.faint(format!(" {:<LABEL$}", "")),
            Span::styled(format!("~{bits:.0} bits · {word}"), Style::new().fg(ink)),
        ]));
    }
    lines.push(Line::default());
    lines.push(Line::from(Span::styled(
        " nothing can recover this password if you forget it",
        Style::new().fg(p.warn),
    )));
    lines.push(Line::from(vec![
        Span::styled(" enter", Style::new().fg(p.accent)),
        p.faint(" change   "),
        Span::styled("tab", Style::new().fg(p.accent)),
        p.faint(" field   "),
        Span::styled("^r", Style::new().fg(p.accent)),
        p.faint(" reveal   "),
        Span::styled("esc", Style::new().fg(p.accent)),
        p.faint(" keep the old one"),
    ]));
    let width = lines.iter().map(|l| l.width() as u16).max().unwrap_or(0) + 3;
    popup(frame, "change master password", lines, width.max(30), &p);
}

/* The one-box group prompt behind A and E. Same field shape as the entry
   form's rows so the caret and styling read identically, minus the cycling:
   there is only the name. */
fn draw_group_prompt(frame: &mut Frame, app: &App) {
    let p = app.theme;
    let Some(prompt) = &app.group_prompt else {
        return;
    };
    /* One box, always focused: the popup only exists while it holds the keys. */
    let style = Style::new().fg(p.text);
    let mut first = prompt.value.chars();
    let head: String = first.by_ref().take(prompt.caret).collect();
    let tail: String = first.collect();
    let lines = vec![
        Line::from(vec![
            Span::styled(format!(" {:<LABEL$}", "name"), style),
            Span::styled(head, style),
            Span::styled("█", style),
            Span::styled(tail, style),
        ]),
        Line::default(),
        Line::from(vec![
            Span::styled(" enter", Style::new().fg(p.accent)),
            p.faint(" save   "),
            Span::styled("esc", Style::new().fg(p.accent)),
            p.faint(" throw away"),
        ]),
    ];
    let width = lines.iter().map(|l| l.width() as u16).max().unwrap_or(0) + 3;
    let title = match prompt.kind {
        GroupPromptKind::New => "new group",
        GroupPromptKind::Rename(_) => "rename group",
    };
    popup(frame, title, lines, width, &p);
}

/* The matched characters of a row, in `cursor` and bold against the rest: a list
   sorted by relevance still leaves the reader working out why each row is
   there. Indices are char positions into the untruncated title, so anything
   past the cut simply does not match a span. */
fn highlight(text: &str, hits: &[u32], base: Style, p: &Palette) -> Vec<Span<'static>> {
    if hits.is_empty() {
        return vec![Span::styled(text.to_string(), base)];
    }
    let lit = Style::new().fg(p.cursor).add_modifier(Modifier::BOLD);
    let mut out: Vec<Span<'static>> = Vec::new();
    let mut run = String::new();
    let mut run_lit = false;
    for (at, c) in text.chars().enumerate() {
        let on = hits.contains(&(at as u32));
        if on != run_lit && !run.is_empty() {
            out.push(Span::styled(std::mem::take(&mut run), if run_lit { lit } else { base }));
        }
        run_lit = on;
        run.push(c);
    }
    if !run.is_empty() {
        out.push(Span::styled(run, if run_lit { lit } else { base }));
    }
    out
}


#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    /* A `TestBackend` row is cells, not a string: a double-width glyph fills
       one cell and leaves the next blank. Collect per row and trim the end,
       never join the whole buffer and substring it. */
    fn screen(t: &Terminal<TestBackend>) -> Vec<String> {
        let buf = t.backend().buffer();
        let area = buf.area;
        (area.top()..area.bottom())
            .map(|y| {
                (area.left()..area.right())
                    .map(|x| buf[(x, y)].symbol().to_string())
                    .collect::<String>()
                    .trim_end()
                    .to_string()
            })
            .collect()
    }

    /* The frame's contract in one test: the wordmark, the lock question, and
       the one key that is always live. */
    #[test]
    fn the_frame_names_sennel_and_offers_keys() {
        let backend = TestBackend::new(80, 24);
        let mut t = Terminal::new(backend).unwrap();
        let mut app = App::new();
        t.draw(|f| draw(f, &mut app)).unwrap();
        let joined = screen(&t).join("\n");
        assert!(joined.contains("Sennel"), "{joined}");
        assert!(joined.contains("database"), "{joined}");
        assert!(joined.contains("F1 keys"), "{joined}");
    }

    /* The password box shows bullets end to end: length is the only thing
       about it the screen may reveal, and the plaintext never reaches a
       cell. */
    #[test]
    fn the_lock_screen_never_shows_the_password() {
        let backend = TestBackend::new(80, 24);
        let mut t = Terminal::new(backend).unwrap();
        let mut app = App::new();
        app.unlock_password = "s3cret".to_string();
        app.caret = 6;
        t.draw(|f| draw(f, &mut app)).unwrap();
        let joined = screen(&t).join("\n");
        assert!(!joined.contains("s3cret"), "{joined}");
        assert!(joined.contains("••••••"), "{joined}");
    }

    /* `^r` turns the bullets into the typed password — the lock's sibling of
       the browser detail pane's `*`, moved to a control key so a star in the
       password itself stays a password character. Toggling off hides again. */
    #[test]
    fn ctrl_r_reveals_the_lock_screen_password_and_hides_it_again() {
        let backend = TestBackend::new(80, 24);
        let mut t = Terminal::new(backend).unwrap();
        let mut app = App::new();
        app.unlock_password = "s3cret".to_string();
        app.caret = 6;
        app.toggle_unlock_reveal();
        t.draw(|f| draw(f, &mut app)).unwrap();
        let joined = screen(&t).join("\n");
        assert!(joined.contains("s3cret"), "{joined}");
        assert!(!joined.contains("••••••"), "{joined}");

        let backend = TestBackend::new(80, 24);
        let mut t = Terminal::new(backend).unwrap();
        app.toggle_unlock_reveal();
        t.draw(|f| draw(f, &mut app)).unwrap();
        let joined = screen(&t).join("\n");
        assert!(!joined.contains("s3cret"), "{joined}");
        assert!(joined.contains("••••••"), "{joined}");
    }

    /* The browser's contract: both panes list what the vault holds, the
       detail names the entry's user, and the password never reaches a cell —
       the detail carries a fixed run of bullets instead. */
    #[test]
    fn the_browser_shows_groups_entries_and_a_masked_detail() {
        use crate::vault::Vault;
        let backend = TestBackend::new(120, 24);
        let mut t = Terminal::new(backend).unwrap();
        let mut app = App::new();
        let mut vault = Vault::new();
        let root = vault.root_id();
        let banks = vault.create_group(&root, "Banks").unwrap();
        vault
            .create_entry(
                &banks,
                "checking",
                "octo",
                "s3cret-pw",
                "https://bank.example",
                "main account",
            )
            .unwrap();
        app.open_vault(vault);
        /* Pre-order is root then Banks, so one step down lands on it, and
           stepping groups re-points the entry cursor at its first entry. */
        app.step_group(true);
        t.draw(|f| draw(f, &mut app)).unwrap();
        let joined = screen(&t).join("\n");
        assert!(joined.contains("Banks"), "{joined}");
        assert!(joined.contains("checking"), "{joined}");
        assert!(joined.contains("octo"), "{joined}");
        assert!(!joined.contains("s3cret-pw"), "{joined}");
        assert!(joined.contains("••••••••"), "{joined}");
    }

    /* The tree says which groups fold: ▾ on an open parent, ▸ once folded,
       and nothing on a leaf. A folded subtree must not appear at all. */
    #[test]
    fn the_tree_marks_folds_and_hides_folded_children() {
        use crate::vault::Vault;
        let backend = TestBackend::new(120, 24);
        let mut t = Terminal::new(backend).unwrap();
        let mut app = App::new();
        let mut vault = Vault::new();
        let root = vault.root_id();
        let banks = vault.create_group(&root, "Banks").unwrap();
        vault.create_group(&banks, "Work").unwrap();
        vault.create_entry(&root, "loose", "u", "p", "", "").unwrap();
        app.open_vault(vault);
        t.draw(|f| draw(f, &mut app)).unwrap();
        let joined = screen(&t).join("\n");
        assert!(joined.contains("▾ Banks"), "{joined}");
        assert!(joined.contains("Work"), "{joined}");
        // Fold Banks, redraw: its marker flips and Work disappears.
        app.step_group(true); // onto Banks
        app.collapse_group();
        t.draw(|f| draw(f, &mut app)).unwrap();
        let folded = screen(&t).join("\n");
        assert!(folded.contains("▸ Banks"), "{folded}");
        assert!(!folded.contains("Work"), "{folded}");
    }

    /* `*` reveals the real password in the detail, and the bar counts the
       whole vault: root plus Banks is two groups, one entry. */
    #[test]
    fn star_reveals_the_password_and_the_bar_counts_the_vault() {
        use crate::vault::Vault;
        let backend = TestBackend::new(120, 24);
        let mut t = Terminal::new(backend).unwrap();
        let mut app = App::new();
        let mut vault = Vault::new();
        let root = vault.root_id();
        let banks = vault.create_group(&root, "Banks").unwrap();
        vault
            .create_entry(
                &banks,
                "checking",
                "octo",
                "s3cret-pw",
                "https://bank.example",
                "main account",
            )
            .unwrap();
        app.open_vault(vault);
        app.step_group(true);
        /* One frame first: `*` refuses until a draw has said whether the
           detail pane fits, which is the only place that width is known. */
        t.draw(|f| draw(f, &mut app)).unwrap();
        app.toggle_password();
        t.draw(|f| draw(f, &mut app)).unwrap();
        let joined = screen(&t).join("\n");
        assert!(joined.contains("s3cret-pw"), "{joined}");
        assert!(joined.contains("2 groups"), "{joined}");
        assert!(joined.contains("1 entry"), "{joined}");
    }

    /* The overlay is a popup, not a screen: the frame behind it is still
       drawn, and dismissing it changes nothing else. */
    #[test]
    fn h_opens_a_keys_popup_over_the_frame() {
        let backend = TestBackend::new(80, 24);
        let mut t = Terminal::new(backend).unwrap();
        let mut app = App::new();
        app.show_help = true;
        t.draw(|f| draw(f, &mut app)).unwrap();
        let joined = screen(&t).join("\n");
        assert!(joined.contains("keys"), "{joined}");
        assert!(joined.contains("Sennel"), "{joined}");
    }

    /* The overlay only names live keys, and it names all of them: the keys
       that were missing from it were keys nobody could find. */
    #[test]
    fn the_overlay_names_the_browsers_live_keys() {
        use crate::vault::Vault;
        let backend = TestBackend::new(100, 40);
        let mut t = Terminal::new(backend).unwrap();
        let mut app = App::new();
        app.open_vault(Vault::new());
        app.show_help = true;
        t.draw(|f| draw(f, &mut app)).unwrap();
        let joined = screen(&t).join("\n");
        for key in ["enter", "*", "n N", "g G", "PgUp", "^d", "X V", "/", "^s", "esc"] {
            assert!(joined.contains(key), "the overlay forgot {key}: {joined}");
        }
        // ^s here is save-now; the form's generate is advertised by the form.
        assert!(joined.contains("save now"), "{joined}");
        assert!(!joined.contains("generate"), "the overlay claimed a form-only key");
    }

    /* Enter means three things on the lock screen, and the hint names the one
       the focused box will do. */
    #[test]
    fn the_unlock_hint_follows_the_focused_box() {
        use crate::app::UnlockField;
        let backend = TestBackend::new(80, 24);
        let mut t = Terminal::new(backend).unwrap();
        let mut app = App::new();
        app.set_db_path(Some(std::path::PathBuf::from("/nowhere/new.kdbx")));
        app.unlock_field = UnlockField::Password;
        t.draw(|f| draw(f, &mut app)).unwrap();
        let joined = screen(&t).join("\n");
        assert!(joined.contains("new database"), "{joined}");
        assert!(joined.contains("enter create"), "{joined}");
        app.unlock_field = UnlockField::File;
        t.draw(|f| draw(f, &mut app)).unwrap();
        let joined = screen(&t).join("\n");
        assert!(joined.contains("enter apply path"), "{joined}");
    }

    /* The edit form masks the password box and advertises that empty keeps;
       the stored secret never reaches the popup buffer. */
    #[test]
    fn the_form_masks_the_password_and_names_the_keep_rule() {
        use crate::vault::Vault;
        let backend = TestBackend::new(80, 24);
        let mut t = Terminal::new(backend).unwrap();
        let mut app = App::new();
        let mut vault = Vault::new();
        let root = vault.root_id();
        let banks = vault.create_group(&root, "Banks").unwrap();
        vault
            .create_entry(&banks, "checking", "octo", "s3cret-pw", "", "")
            .unwrap();
        app.open_vault(vault);
        app.step_group(true);
        app.open_edit_form();
        t.draw(|f| draw(f, &mut app)).unwrap();
        let joined = screen(&t).join("\n");
        assert!(joined.contains("edit entry"), "{joined}");
        assert!(joined.contains("leave empty to keep"), "{joined}");
        assert!(!joined.contains("s3cret-pw"), "the form leaked the stored secret");
        // Typed content masks as bullets, one per char. Two Tabs land in
        // the password box; the caret jumps to the end of an empty box.
        app.next_form_field(true);
        app.next_form_field(true);
        app.form_insert('n');
        app.form_insert('e');
        app.form_insert('w');
        t.draw(|f| draw(f, &mut app)).unwrap();
        let joined = screen(&t).join("\n");
        assert!(joined.contains("•••"), "{joined}");
        assert!(!joined.contains("new"), "the form showed the password in clear");
    }

    /* The delete confirm names the row it is about, so a yes is an answer
       to a visible question, not a blind id. */
    #[test]
    fn the_delete_confirm_names_the_entry() {
        use crate::vault::Vault;
        let backend = TestBackend::new(80, 24);
        let mut t = Terminal::new(backend).unwrap();
        let mut app = App::new();
        let mut vault = Vault::new();
        let root = vault.root_id();
        let banks = vault.create_group(&root, "Banks").unwrap();
        vault
            .create_entry(&banks, "checking", "octo", "s3cret-pw", "", "")
            .unwrap();
        app.open_vault(vault);
        app.step_group(true);
        app.ask_delete_entry();
        t.draw(|f| draw(f, &mut app)).unwrap();
        let joined = screen(&t).join("\n");
        // `bin`, not `delete`: outside the bin the row is moved, not destroyed.
        assert!(joined.contains("bin entry"), "{joined}");
        assert!(joined.contains("checking"), "{joined}");
        assert!(joined.contains("u restores it"), "{joined}");
        assert!(!joined.contains("cannot be undone"), "{joined}");
    }

    /* Inside the bin the same key asks the other question, and promises no
       undo it does not have. */
    #[test]
    fn the_delete_confirm_inside_the_bin_says_it_is_permanent() {
        use crate::vault::Vault;
        let backend = TestBackend::new(80, 24);
        let mut t = Terminal::new(backend).unwrap();
        let mut app = App::new();
        let mut vault = Vault::new();
        let root = vault.root_id();
        let id = vault.create_entry(&root, "checking", "octo", "p", "", "").unwrap();
        vault.recycle_entry(&id).unwrap();
        let bin = vault.recycle_bin_id().unwrap();
        app.open_vault(vault);
        app.group_cursor = Some(bin);
        app.entry_cursor = Some(id);
        app.ask_delete_entry();
        t.draw(|f| draw(f, &mut app)).unwrap();
        let joined = screen(&t).join("\n");
        assert!(joined.contains("delete entry"), "{joined}");
        assert!(joined.contains("cannot be undone"), "{joined}");
        assert!(!joined.contains("u restores it"), "{joined}");
    }

    /* A long title must not push the verb off the popup: the name truncates,
       the question never does. */
    #[test]
    fn the_delete_confirm_keeps_its_verb_at_eighty_columns() {
        use crate::vault::Vault;
        let backend = TestBackend::new(80, 24);
        let mut t = Terminal::new(backend).unwrap();
        let mut app = App::new();
        let mut vault = Vault::new();
        let root = vault.root_id();
        vault
            .create_entry(
                &root,
                "Commonwealth Bank — personal everyday account and card, plus the offset mortgage redraw",
                "octo",
                "p",
                "",
                "",
            )
            .unwrap();
        app.open_vault(vault);
        app.switch_pane();
        app.ask_delete_entry();
        t.draw(|f| draw(f, &mut app)).unwrap();
        let joined = screen(&t).join("\n");
        assert!(joined.contains("bin entry"), "{joined}");
        assert!(joined.contains("y  delete"), "{joined}");
        assert!(joined.contains("…”?"), "the title did not truncate: {joined}");
    }

    /* A deleted row that looks exactly like a live one is how somebody
       copies a password they threw away last week, so the bin draws back. */
    #[test]
    fn the_recycle_bin_draws_back_from_the_live_groups() {
        use crate::vault::Vault;
        let backend = TestBackend::new(80, 24);
        let mut t = Terminal::new(backend).unwrap();
        let mut app = App::new();
        let mut vault = Vault::new();
        let root = vault.root_id();
        vault.create_group(&root, "Banks").unwrap();
        let id = vault.create_entry(&root, "checking", "octo", "p", "", "").unwrap();
        vault.recycle_entry(&id).unwrap();
        app.open_vault(vault);
        t.draw(|f| draw(f, &mut app)).unwrap();

        let rows = screen(&t);
        let at = rows
            .iter()
            .position(|r| r.contains("Recycle Bin"))
            .unwrap_or_else(|| panic!("the bin is not in the tree: {rows:?}"));
        let buf = t.backend().buffer();
        let x = rows[at].find("Recycle").unwrap() as u16;
        assert_eq!(
            buf[(x, at as u16)].fg,
            crate::theme::WARM.muted,
            "the bin drew like a live group"
        );
        // A live group beside it does not, so this is the bin and not the pane.
        let live = rows.iter().position(|r| r.contains("Banks")).unwrap();
        let lx = rows[live].find("Banks").unwrap() as u16;
        assert_ne!(
            buf[(lx, live as u16)].fg,
            crate::theme::WARM.muted,
            "a live group drew like the bin"
        );
    }

    /* The one action nobody can take back and nothing can remind them of, so
       the popup has to say so, mask both boxes and name the file. */
    #[test]
    fn the_change_password_popup_warns_and_masks_both_boxes() {
        use crate::vault::Vault;
        let backend = TestBackend::new(80, 24);
        let mut t = Terminal::new(backend).unwrap();
        let mut app = App::new();
        app.open_vault(Vault::new());
        app.rekey = Some(crate::app::Rekey::default());
        for c in "hunter2".chars() {
            app.rekey_insert(c);
        }
        t.draw(|f| draw(f, &mut app)).unwrap();
        let joined = screen(&t).join("\n");
        assert!(joined.contains("change master password"), "{joined}");
        assert!(joined.contains("nothing can recover"), "{joined}");
        assert!(!joined.contains("hunter2"), "the password drew in the clear");
        assert!(joined.contains("•••••••"), "the box did not mask: {joined}");

        // ^r is the way to read it back, the same as every other secret box.
        app.rekey_reveal();
        t.draw(|f| draw(f, &mut app)).unwrap();
        assert!(screen(&t).join("\n").contains("hunter2"), "^r revealed nothing");
    }

    /* The group prompt: one box, named for what it does, prefilled with the
       current name. */
    #[test]
    fn the_group_prompt_draws_a_single_named_box() {
        use crate::vault::Vault;
        let backend = TestBackend::new(80, 24);
        let mut t = Terminal::new(backend).unwrap();
        let mut app = App::new();
        let mut vault = Vault::new();
        let root = vault.root_id();
        vault.create_group(&root, "Banks").unwrap();
        app.open_vault(vault);
        app.step_group(true);
        app.open_group_prompt_rename();
        t.draw(|f| draw(f, &mut app)).unwrap();
        let joined = screen(&t).join("\n");
        assert!(joined.contains("rename group"), "{joined}");
        assert!(joined.contains("name"), "{joined}");
        assert!(joined.contains("Banks"), "{joined}");
    }

    /* The group delete confirm names the group, same rule as the entry one. */
    #[test]
    fn the_delete_group_confirm_names_the_group() {
        use crate::vault::Vault;
        let backend = TestBackend::new(80, 24);
        let mut t = Terminal::new(backend).unwrap();
        let mut app = App::new();
        let mut vault = Vault::new();
        let root = vault.root_id();
        vault.create_group(&root, "Empty").unwrap();
        app.open_vault(vault);
        app.step_group(true);
        app.ask_delete_group();
        t.draw(|f| draw(f, &mut app)).unwrap();
        let joined = screen(&t).join("\n");
        assert!(joined.contains("bin group"), "{joined}");
        assert!(joined.contains("Empty"), "{joined}");
        // A group takes its subtree with it, and the box says so.
        assert!(joined.contains("contents included"), "{joined}");
    }

    /* An armed cut is named in the status bar, so X never reads as dead. */
    #[test]
    fn the_status_bar_names_an_armed_cut() {
        use crate::vault::Vault;
        let backend = TestBackend::new(120, 24);
        let mut t = Terminal::new(backend).unwrap();
        let mut app = App::new();
        let mut vault = Vault::new();
        let root = vault.root_id();
        let banks = vault.create_group(&root, "Banks").unwrap();
        vault
            .create_entry(&banks, "checking", "octo", "s3cret-pw", "", "")
            .unwrap();
        app.open_vault(vault);
        app.step_group(true);
        app.switch_pane();
        app.cut_selected();
        t.draw(|f| draw(f, &mut app)).unwrap();
        let joined = screen(&t).join("\n");
        assert!(joined.contains("cut: checking"), "{joined}");
        assert!(joined.contains("V pastes"), "{joined}");
    }

    /* The band draws `/needle` with a block caret and the status bar counts
       honestly: "N of M shown" over the whole vault, not just this pane. */
    #[test]
    fn the_search_band_draws_the_needle_and_counts_matches() {
        use crate::vault::Vault;
        let backend = TestBackend::new(120, 24);
        let mut t = Terminal::new(backend).unwrap();
        let mut app = App::new();
        let mut vault = Vault::new();
        let root = vault.root_id();
        let banks = vault.create_group(&root, "Banks").unwrap();
        vault
            .create_entry(&banks, "checking", "octo", "s3cret-pw", "", "")
            .unwrap();
        vault
            .create_entry(&banks, "savings", "octo", "s3cret-pw", "", "")
            .unwrap();
        app.open_vault(vault);
        app.step_group(true);
        app.open_search();
        for ch in "check".chars() {
            app.search_insert(ch);
        }
        t.draw(|f| draw(f, &mut app)).unwrap();
        let joined = screen(&t).join("\n");
        assert!(joined.contains("/check"), "{joined}");
        // The entries header owns the count while it is drawn.
        assert!(joined.contains("1 of 2"), "{joined}");
        assert!(joined.contains("whole vault"), "{joined}");
        assert!(joined.contains("esc clear"), "{joined}");
    }

    /* `h keys` is the one hint that always matters, so it is pinned to the
       right of the bar and the notes are what drop when 80 columns run out.
       Unsaved work is named for as long as it is unsaved, not for one flash. */
    #[test]
    fn the_status_bar_pins_the_hint_and_names_unsaved_work() {
        use crate::vault::Vault;
        let backend = TestBackend::new(80, 24);
        let mut t = Terminal::new(backend).unwrap();
        let mut app = App::new();
        let mut vault = Vault::new();
        let root = vault.root_id();
        let banks = vault.create_group(&root, "Banks").unwrap();
        vault
            .create_entry(&banks, "checking", "octo", "p", "", "")
            .unwrap();
        app.open_vault(vault);
        app.step_group(true);
        app.mark_dirty();
        app.switch_pane();
        app.cut_selected();
        app.open_search();
        for ch in "check".chars() {
            app.search_insert(ch);
        }
        t.draw(|f| draw(f, &mut app)).unwrap();
        let bar = screen(&t).last().cloned().unwrap_or_default();
        assert!(bar.ends_with("h keys"), "the hint was pushed off: {bar:?}");
        assert!(bar.contains("y user"), "{bar:?}");
        assert!(bar.contains("unsaved"), "{bar:?}");
        assert!(cols(&bar) <= 80, "the bar overran the row: {bar:?}");
    }

    /* Every column of a row is measured against one budget: the username used
       to be appended after a title already truncated to the pane, so the line
       ran off the edge and was clipped with no marker. */
    #[test]
    fn an_entry_row_never_runs_past_its_pane() {
        use crate::vault::Vault;
        let backend = TestBackend::new(80, 24);
        let mut t = Terminal::new(backend).unwrap();
        let mut app = App::new();
        let mut vault = Vault::new();
        let root = vault.root_id();
        let banks = vault.create_group(&root, "Banking").unwrap();
        vault
            .create_entry(
                &banks,
                "Commonwealth Bank — personal everyday account",
                "grant.deelstra",
                "p",
                "",
                "",
            )
            .unwrap();
        app.open_vault(vault);
        app.step_group(true);
        t.draw(|f| draw(f, &mut app)).unwrap();
        let row = screen(&t)
            .into_iter()
            .find(|l| l.contains("Commonwealth"))
            .expect("the row did not draw");
        assert!(cols(&row) <= 80, "the row overran: {row:?}");
        // Both columns are there, and the cut one says it was cut.
        assert!(row.contains("grant.deelstra"), "{row:?}");
        assert!(row.contains('…'), "the title was cut without a marker: {row:?}");
    }

    /* The scrollbar draws into the pane's last column, so the list stops one
       column short while one is live — otherwise the thumb lands on a name. */
    #[test]
    fn the_scrollbar_gets_a_column_of_its_own() {
        use crate::vault::Vault;
        let backend = TestBackend::new(60, 8);
        let mut t = Terminal::new(backend).unwrap();
        let mut app = App::new();
        let mut vault = Vault::new();
        let root = vault.root_id();
        for n in 0..20 {
            vault.create_group(&root, &format!("Group {n:02}")).unwrap();
        }
        app.open_vault(vault);
        t.draw(|f| draw(f, &mut app)).unwrap();
        let rows = screen(&t);
        let listed: Vec<&String> = rows.iter().filter(|l| l.contains("Group ")).collect();
        assert!(!listed.is_empty(), "nothing drew: {rows:?}");
        /* The groups pane is 35% of 60 = 21 columns, and the thumb owns the
           last of them: no name may reach it. */
        for row in listed {
            if let Some(at) = row.chars().position(|c| c == '█') {
                assert_eq!(at, 20, "the thumb left its column: {row:?}");
            }
        }
        // And the thumb is actually drawn somewhere, or this proves nothing.
        assert!(rows.iter().any(|l| l.contains('█')), "no scrollbar: {rows:?}");
    }

    /* A help table that does not fit says how much it is hiding. Dropping the
       rows behind the border — which is what it used to do — is a help screen
       lying about the keymap. */
    #[test]
    fn the_overlay_admits_when_it_cannot_show_everything() {
        use crate::vault::Vault;
        let backend = TestBackend::new(80, 14);
        let mut t = Terminal::new(backend).unwrap();
        let mut app = App::new();
        app.open_vault(Vault::new());
        app.show_help = true;
        t.draw(|f| draw(f, &mut app)).unwrap();
        let joined = screen(&t).join("\n");
        assert!(joined.contains("more · a taller window"), "{joined}");
    }

    /* Under 40 columns the copy keys are what has to go: the hint is the
       row's reason to exist. */
    #[test]
    fn a_narrow_bar_keeps_the_hint_and_drops_the_rest() {
        use crate::vault::Vault;
        let backend = TestBackend::new(28, 10);
        let mut t = Terminal::new(backend).unwrap();
        let mut app = App::new();
        app.open_vault(Vault::new());
        t.draw(|f| draw(f, &mut app)).unwrap();
        let bar = screen(&t).last().cloned().unwrap_or_default();
        assert!(bar.trim() == "h keys", "{bar:?}");
    }

    /* Notes hold newlines; one Line welded them together and Enter submitted
       the form, so a break could be lost but never typed. */
    #[test]
    fn the_form_shows_notes_one_line_at_a_time() {
        use crate::vault::Vault;
        let backend = TestBackend::new(80, 24);
        let mut t = Terminal::new(backend).unwrap();
        let mut app = App::new();
        let mut vault = Vault::new();
        let root = vault.root_id();
        vault
            .create_entry(&root, "checking", "octo", "p", "", "first line\nsecond line")
            .unwrap();
        app.open_vault(vault);
        app.switch_pane();
        app.open_edit_form();
        t.draw(|f| draw(f, &mut app)).unwrap();
        let rows = screen(&t);
        let joined = rows.join("\n");
        assert!(!joined.contains("first linesecond"), "the break was welded: {joined}");
        assert!(joined.contains("first line⏎"), "{joined}");
        assert!(
            rows.iter().any(|l| l.contains("second line")),
            "the second line did not draw: {joined}"
        );
    }

    /* The box says what it is worth while it holds something: `^s` and a
       typed password answer the same way, in bits and in a word. */
    #[test]
    fn the_form_prices_the_password_it_holds() {
        use crate::vault::Vault;
        let backend = TestBackend::new(80, 24);
        let mut t = Terminal::new(backend).unwrap();
        let mut app = App::new();
        let mut vault = Vault::new();
        let root = vault.root_id();
        vault.create_entry(&root, "checking", "octo", "p", "", "").unwrap();
        app.open_vault(vault);
        app.switch_pane();
        app.open_edit_form();
        t.draw(|f| draw(f, &mut app)).unwrap();
        assert!(!screen(&t).join("\n").contains("bits"), "priced an empty box");
        app.form_generate();
        t.draw(|f| draw(f, &mut app)).unwrap();
        let joined = screen(&t).join("\n");
        assert!(joined.contains("bits"), "{joined}");
        assert!(joined.contains("strong"), "{joined}");
    }

    /* `^r` in the form reveals what `^s` just generated: a password masked
       end to end cannot be checked before it is stored. */
    #[test]
    fn the_form_reveals_the_password_on_ctrl_r() {
        use crate::vault::Vault;
        let backend = TestBackend::new(80, 24);
        let mut t = Terminal::new(backend).unwrap();
        let mut app = App::new();
        let mut vault = Vault::new();
        let root = vault.root_id();
        vault.create_entry(&root, "checking", "octo", "p", "", "").unwrap();
        app.open_vault(vault);
        app.switch_pane();
        app.open_edit_form();
        app.next_form_field(true);
        app.next_form_field(true);
        for c in "hunter2".chars() {
            app.form_insert(c);
        }
        t.draw(|f| draw(f, &mut app)).unwrap();
        assert!(!screen(&t).join("\n").contains("hunter2"), "masked by default");
        app.toggle_form_reveal();
        t.draw(|f| draw(f, &mut app)).unwrap();
        assert!(screen(&t).join("\n").contains("hunter2"), "^r did not reveal");
    }

    /* Three unlabelled columns could not say which pane you were in, which
       folder you were looking at, or how it was sorted. The headers answer
       all three, and the live one is the bold, cream one. */
    #[test]
    fn the_pane_headers_name_the_place_and_the_order() {
        use crate::vault::Vault;
        let backend = TestBackend::new(130, 24);
        let mut t = Terminal::new(backend).unwrap();
        let mut app = App::new();
        let mut vault = Vault::new();
        let root = vault.root_id();
        let banks = vault.create_group(&root, "Banking").unwrap();
        vault.create_entry(&banks, "checking", "octo", "p", "", "").unwrap();
        vault.create_entry(&banks, "savings", "octo", "p", "", "").unwrap();
        app.open_vault(vault);
        app.step_group(true);
        t.draw(|f| draw(f, &mut app)).unwrap();
        let joined = screen(&t).join("\n");
        assert!(joined.contains("groups"), "{joined}");
        assert!(joined.contains("Root/Banking · 2 entries"), "{joined}");
        assert!(joined.contains("sort: stored"), "{joined}");
        assert!(joined.contains("detail"), "{joined}");
        // Counts turn the tree into a map.
        assert!(joined.contains("Banking  2"), "{joined}");
        /* A narrow header keeps the front of the list and drops the tail,
           rather than truncating every part of itself into an ellipsis. */
        let narrow = TestBackend::new(100, 24);
        let mut t2 = Terminal::new(narrow).unwrap();
        t2.draw(|f| draw(f, &mut app)).unwrap();
        let tight = screen(&t2).join("\n");
        assert!(tight.contains("Root/Banking · 2 entries"), "{tight}");
        assert!(!tight.contains("sort:"), "the tail did not drop: {tight}");

        // And `o` shows up where the order lives, not only in a flash.
        app.cycle_order();
        t.draw(|f| draw(f, &mut app)).unwrap();
        assert!(screen(&t).join("\n").contains("sort: name"), "order not shown");
    }

    /* The vault keeps the right-hand end of the header, so a flash no longer
       costs the line that says which vault is open — and a failure carries a
       glyph, since NO_COLOR takes the red away. */
    #[test]
    fn the_header_keeps_the_vault_beside_the_flash() {
        let backend = TestBackend::new(80, 24);
        let mut t = Terminal::new(backend).unwrap();
        let (mut app, tmp) = crate::app::tests::locked_app_with_db("pw");
        let name = tmp.0.file_name().unwrap().to_string_lossy().into_owned();
        let mut password = b"pw".to_vec();
        app.try_unlock(&mut password, None);
        app.error("save failed  ·  disk is full");
        t.draw(|f| draw(f, &mut app)).unwrap();
        let header = screen(&t).first().cloned().unwrap_or_default();
        assert!(header.contains("save failed"), "{header:?}");
        assert!(header.contains(&name), "the vault fell off the header: {header:?}");
        assert!(header.contains('×'), "no severity glyph: {header:?}");
    }

    /* The empty states name the key that fills them: this is the first screen
       after a vault is created. */
    #[test]
    fn empty_panes_name_the_way_out() {
        use crate::vault::Vault;
        let backend = TestBackend::new(100, 24);
        let mut t = Terminal::new(backend).unwrap();
        let mut app = App::new();
        app.open_vault(Vault::new());
        t.draw(|f| draw(f, &mut app)).unwrap();
        let joined = screen(&t).join("\n");
        assert!(joined.contains("no entries here  ·  a adds one"), "{joined}");
    }

    /* Nobody knows the path to a vault they have not opened yet, so `^o`
       lists what is there: folders and vaults, nothing else, with a typed
       filter that narrows rather than ranks. */
    #[test]
    fn the_picker_lists_folders_and_vaults_and_narrows() {
        let dir = std::env::temp_dir().join(format!("sennel-pick-ui-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("Work")).unwrap();
        for name in ["personal.kdbx", "shared.kdbx", "notes.txt"] {
            std::fs::write(dir.join(name), b"x").unwrap();
        }
        let backend = TestBackend::new(80, 24);
        let mut t = Terminal::new(backend).unwrap();
        let mut app = App::new();
        app.unlock_file = dir.display().to_string();
        app.open_browse();
        t.draw(|f| draw(f, &mut app)).unwrap();
        let joined = screen(&t).join("\n");
        assert!(joined.contains("Work/"), "{joined}");
        assert!(joined.contains("personal.kdbx"), "{joined}");
        assert!(!joined.contains("notes.txt"), "the picker listed a non-vault");
        // The unlock boxes step aside rather than sitting under the popup.
        assert!(!joined.contains("key file"), "two popups at once: {joined}");

        app.browse_filter('h');
        t.draw(|f| draw(f, &mut app)).unwrap();
        let joined = screen(&t).join("\n");
        assert!(joined.contains("shared.kdbx"), "{joined}");
        assert!(!joined.contains("personal.kdbx"), "the filter did not narrow");
        assert!(joined.contains("/h"), "the filter is not shown: {joined}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /* The pane builds only the rows it can show, so the window it picks has
       to be the right one: the cursor is always on screen, and what is far
       above it is not. */
    #[test]
    fn a_long_list_draws_the_window_around_the_cursor() {
        use crate::vault::Vault;
        let backend = TestBackend::new(60, 14);
        let mut t = Terminal::new(backend).unwrap();
        let mut app = App::new();
        let mut vault = Vault::new();
        let root = vault.root_id();
        for n in 0..60 {
            vault
                .create_entry(&root, &format!("entry-{n:02}"), "u", "p", "", "")
                .unwrap();
        }
        app.open_vault(vault);
        app.switch_pane();
        for _ in 0..40 {
            app.step_entry(true);
        }
        t.draw(|f| draw(f, &mut app)).unwrap();
        let joined = screen(&t).join("\n");
        assert!(joined.contains("entry-40"), "the cursor row is off screen: {joined}");
        assert!(!joined.contains("entry-00"), "the whole list drew: {joined}");
        // The scrollbar still speaks in whole-list terms.
        assert!(joined.contains('█'), "no scrollbar for a list this long");

        // And back to the top brings the first rows back.
        app.jump_pane(false);
        t.draw(|f| draw(f, &mut app)).unwrap();
        let joined = screen(&t).join("\n");
        assert!(joined.contains("entry-00"), "{joined}");
        assert!(!joined.contains("entry-40"), "{joined}");
    }

    /* A theme may change colour and must never change layout. Every built-in
       draws the same screen, cell for cell, as the one before it — so a
       palette cannot quietly take a column with a wider glyph or drop a span,
       and the frame tests that pin content stay true under all of them. */
    #[test]
    fn every_palette_draws_the_same_frame() {
        use crate::theme::BUILT_INS;
        use crate::vault::Vault;
        let symbols = |palette| {
            let backend = TestBackend::new(100, 24);
            let mut t = Terminal::new(backend).unwrap();
            let mut app = App::new();
            let mut vault = Vault::new();
            let root = vault.root_id();
            let banks = vault.create_group(&root, "Banking").unwrap();
            vault
                .create_entry(&banks, "checking", "octo", "p", "https://b.example", "note")
                .unwrap();
            app.open_vault(vault);
            app.theme = palette;
            app.step_group(true);
            app.mark_dirty();
            t.draw(|f| draw(f, &mut app)).unwrap();
            screen(&t)
        };
        let (first_name, first) = BUILT_INS[0];
        let want = symbols(first);
        for (name, palette) in BUILT_INS {
            assert_eq!(
                symbols(palette),
                want,
                "{name} draws a different screen from {first_name}"
            );
        }
    }

    /* The gradient is painted from the palette, so a theme's ground has to
       arrive on screen — a palette whose colours change while the background
       stays put is the light theme's failure mode. */
    #[test]
    fn the_background_comes_from_the_palette() {
        use crate::vault::Vault;
        let mut pale = crate::theme::WARM;
        pale.near = (250, 250, 250);
        pale.far = (250, 250, 250);
        let backend = TestBackend::new(40, 10);
        let mut t = Terminal::new(backend).unwrap();
        let mut app = App::new();
        app.open_vault(Vault::new());
        app.theme = pale;
        t.draw(|f| draw(f, &mut app)).unwrap();
        let buf = t.backend().buffer();
        assert_eq!(
            buf[(0, 3)].bg,
            ratatui::style::Color::Rgb(250, 250, 250),
            "the ground ignored the palette"
        );
    }

    /* A cut name has to look cut: "Root/Bankin" is otherwise a group
       somebody named Bankin. Columns, so a wide glyph never straddles. */
    #[test]
    fn truncation_says_that_it_truncated() {
        assert_eq!(truncate("Banking", 20), "Banking");
        assert_eq!(truncate("Banking", 7), "Banking");
        assert_eq!(truncate("Banking", 4), "Ban\u{2026}");
        assert_eq!(cols(&truncate("Banking", 4)), 4);
        // A double-width glyph keeps the ellipsis inside the budget.
        assert_eq!(cols(&truncate("\u{9280}\u{884c}\u{53e3}\u{5ea7}", 5)), 5);
        assert_eq!(truncate("Banking", 0), "");
    }

    /* One label column across the lock, the form and the group prompt: at
       eight, "password" ran straight into its own value. */
    #[test]
    fn labels_keep_a_gap_before_their_value() {
        let backend = TestBackend::new(80, 24);
        let mut t = Terminal::new(backend).unwrap();
        let mut app = App::new();
        app.unlock_password = "s3cret".to_string();
        app.caret = 6;
        t.draw(|f| draw(f, &mut app)).unwrap();
        let joined = screen(&t).join("\n");
        assert!(!joined.contains("password\u{2022}"), "the label ran into the box");
        assert!(joined.contains("password  "), "{joined}");
    }

    /* Stamps are stored UTC and read local: an hour that has to be shifted
       in the reader's head is an hour they end up checking elsewhere. */
    #[test]
    fn stamps_render_in_local_time() {
        use chrono::{NaiveDate, TimeZone};
        let utc = NaiveDate::from_ymd_opt(2026, 1, 2)
            .unwrap()
            .and_hms_opt(23, 30, 0)
            .unwrap();
        let shown = local(utc);
        let want = chrono::Local
            .from_utc_datetime(&utc)
            .format("%Y-%m-%d %H:%M")
            .to_string();
        assert_eq!(shown, want);
        // In any zone off UTC the wall clock differs from the stored stamp.
        if chrono::Local.from_utc_datetime(&utc).offset().to_string() != "+00:00" {
            assert_ne!(shown, "2026-01-02 23:30", "the stamp was left in UTC");
        }
    }

    /* The 80-column terminal has no side pane, so Enter's popup is where an
       entry is read: it carries the fields, the notes and its own keys, and
       masks the password until `*` says otherwise. */
    #[test]
    fn the_detail_popup_reads_an_entry_at_eighty_columns() {
        use crate::vault::Vault;
        let backend = TestBackend::new(80, 24);
        let mut t = Terminal::new(backend).unwrap();
        let mut app = App::new();
        let mut vault = Vault::new();
        let root = vault.root_id();
        let banks = vault.create_group(&root, "Banks").unwrap();
        vault
            .create_entry(
                &banks,
                "checking",
                "octo",
                "s3cret-pw",
                "https://bank.example",
                "main account\nsecond line",
            )
            .unwrap();
        app.open_vault(vault);
        app.step_group(true);
        app.switch_pane();
        app.open_detail();
        t.draw(|f| draw(f, &mut app)).unwrap();
        let joined = screen(&t).join("\n");
        assert!(joined.contains("checking"), "{joined}");
        assert!(joined.contains("octo"), "{joined}");
        assert!(joined.contains("second line"), "{joined}");
        assert!(joined.contains("updated"), "{joined}");
        assert!(joined.contains("esc"), "{joined}");
        assert!(!joined.contains("s3cret-pw"), "the popup leaked the password");
        app.toggle_password();
        t.draw(|f| draw(f, &mut app)).unwrap();
        let shown = screen(&t).join("\n");
        assert!(shown.contains("s3cret-pw"), "{shown}");
    }

    /* The popup is the detail view below 100 columns, so the next entry must
       be one key away — and the reveal must not ride along to it. */
    #[test]
    fn the_detail_popup_walks_to_the_next_entry() {
        use crate::vault::Vault;
        let backend = TestBackend::new(80, 24);
        let mut t = Terminal::new(backend).unwrap();
        let mut app = App::new();
        let mut vault = Vault::new();
        let root = vault.root_id();
        vault.create_entry(&root, "checking", "octo", "aaa-pw", "", "").unwrap();
        vault.create_entry(&root, "savings", "gecko", "bbb-pw", "", "").unwrap();
        app.open_vault(vault);
        app.switch_pane();
        app.open_detail();
        app.toggle_password();
        t.draw(|f| draw(f, &mut app)).unwrap();
        assert!(screen(&t).join("\n").contains("aaa-pw"));

        app.step_detail(true);
        t.draw(|f| draw(f, &mut app)).unwrap();
        let joined = screen(&t).join("\n");
        assert!(app.detail, "walking closed the popup");
        assert!(joined.contains("savings"), "{joined}");
        assert!(!joined.contains("bbb-pw"), "the reveal followed the cursor");
        // And the popup says which keys it has.
        assert!(joined.contains("e"), "{joined}");
        assert!(joined.contains("j k"), "{joined}");
        assert!(joined.contains("group"), "{joined}");
    }

    /* A sorted list still leaves the reader working out why each row is
       there: the matched characters are lit, so the answer is visible. */
    #[test]
    fn search_lights_the_characters_it_matched() {
        use crate::vault::Vault;
        use ratatui::style::Color;
        let backend = TestBackend::new(100, 24);
        let mut t = Terminal::new(backend).unwrap();
        let mut app = App::new();
        let mut vault = Vault::new();
        let root = vault.root_id();
        vault.create_entry(&root, "checking", "octo", "p", "", "").unwrap();
        app.open_vault(vault);
        app.open_search();
        for ch in "chk".chars() {
            app.search_insert(ch);
        }
        t.draw(|f| draw(f, &mut app)).unwrap();
        let buf = t.backend().buffer().clone();
        let lit: String = (0..buf.area.width)
            .flat_map(|x| (0..buf.area.height).map(move |y| (x, y)))
            .filter(|(x, y)| buf[(*x, *y)].fg == Color::Rgb(96, 178, 158))
            .map(|(x, y)| buf[(x, y)].symbol().to_string())
            .collect();
        /* c, h and k of "checking" are lit; the marker is teal too, so the
           assertion is about the letters being in there. */
        for c in ['c', 'h', 'k'] {
            assert!(lit.contains(c), "{c} was not lit: {lit:?}");
        }
    }

    /* The scope is a choice, and the screen says which one is in force. */
    #[test]
    fn the_band_names_the_scope_it_is_searching() {
        use crate::vault::Vault;
        let backend = TestBackend::new(100, 24);
        let mut t = Terminal::new(backend).unwrap();
        let mut app = App::new();
        let mut vault = Vault::new();
        let root = vault.root_id();
        let banks = vault.create_group(&root, "Banking").unwrap();
        vault.create_entry(&banks, "checking", "octo", "p", "", "").unwrap();
        vault.create_entry(&root, "loose", "octo", "p", "", "").unwrap();
        app.open_vault(vault);
        app.step_group(true);
        app.open_search();
        app.search_insert('c');
        t.draw(|f| draw(f, &mut app)).unwrap();
        assert!(screen(&t).join("\n").contains("whole vault"), "not global");
        app.toggle_search_scope();
        t.draw(|f| draw(f, &mut app)).unwrap();
        let joined = screen(&t).join("\n");
        assert!(joined.contains("Root/Banking · 1 of"), "{joined}");
        assert!(joined.contains("^g whole vault"), "{joined}");
    }

    /* Enter keeps the filter and hands the keys back, so the band stops being
       a box: the needle stays visible as a chip with no caret to type into. */
    #[test]
    fn a_kept_filter_draws_as_a_chip_without_a_caret() {
        use crate::vault::Vault;
        let backend = TestBackend::new(120, 24);
        let mut t = Terminal::new(backend).unwrap();
        let mut app = App::new();
        let mut vault = Vault::new();
        let root = vault.root_id();
        vault.create_entry(&root, "checking", "octo", "p", "", "").unwrap();
        app.open_vault(vault);
        app.open_search();
        for ch in "check".chars() {
            app.search_insert(ch);
        }
        app.keep_search();
        t.draw(|f| draw(f, &mut app)).unwrap();
        let joined = screen(&t).join("\n");
        assert!(joined.contains("/check"), "{joined}");
        assert!(joined.contains("esc clears"), "{joined}");
        assert!(!joined.contains("█"), "a kept filter drew a text caret");
    }

    /* A live needle widens the pane to the whole vault: a hit from another
       folder carries its group path so it is locatable, and a needle that
       matches nothing says so instead of leaving a blank pane. */
    #[test]
    fn global_search_names_the_folder_and_the_empty_state() {
        use crate::vault::Vault;
        let backend = TestBackend::new(120, 24);
        let mut t = Terminal::new(backend).unwrap();
        let mut app = App::new();
        let mut vault = Vault::new();
        let root = vault.root_id();
        let banks = vault.create_group(&root, "Banks").unwrap();
        let work = vault.create_group(&banks, "Work").unwrap();
        vault
            .create_entry(&work, "github token", "octo", "s3cret-pw", "", "")
            .unwrap();
        app.open_vault(vault);
        app.open_search();
        for ch in "github".chars() {
            app.search_insert(ch);
        }
        t.draw(|f| draw(f, &mut app)).unwrap();
        let joined = screen(&t).join("\n");
        assert!(joined.contains("github token"), "{joined}");
        assert!(joined.contains("Banks/Work"), "{joined}");
        // Now a needle that matches nothing: the empty state names the way out.
        app.search_clear();
        for ch in "zzz".chars() {
            app.search_insert(ch);
        }
        t.draw(|f| draw(f, &mut app)).unwrap();
        let empty = screen(&t).join("\n");
        assert!(empty.contains("nothing matches zzz"), "{empty}");
        assert!(empty.contains("esc clears it"), "{empty}");
    }
}
