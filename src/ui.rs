use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Clear, List, ListItem, ListState, Paragraph, Scrollbar,
    ScrollbarOrientation, ScrollbarState,
};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::app::{self, App, Confirm, FormField, FormKind, GroupPromptKind, Pane, View, char_index_to_byte};
use crate::vault::EntryExt;
use crate::theme::{self, AMBER, CREAM, DIM, GOLD, RED, RULE, SURFACE, TEAL};

/* Columns, not characters. A CJK glyph takes two cells and a combining mark
   takes none, so a column padded to a character count steps out of line by
   the width of whatever is in it. */
fn cols(text: &str) -> usize {
    UnicodeWidthStr::width(text)
}

fn dim(text: impl Into<String>) -> Span<'static> {
    Span::styled(text.into(), Style::new().fg(DIM))
}

pub fn draw(frame: &mut Frame, app: &mut App) {
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

    draw_background(frame);
    draw_header(frame, app, header);
    draw_rule(frame, rule);
    draw_body(frame, app, body);
    if app.search.is_some() {
        draw_search(frame, app, band_area);
    }
    draw_rule(frame, footrule);
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
fn draw_background(frame: &mut Frame) {
    if theme::plain() {
        return;
    }
    let area = frame.area();
    let buffer = frame.buffer_mut();
    for y in area.top()..area.bottom() {
        for x in area.left()..area.right() {
            let bg = theme::background(x - area.left(), y - area.top(), area.width, area.height);
            buffer[(x, y)].set_bg(bg);
        }
    }
}

fn draw_rule(frame: &mut Frame, area: Rect) {
    frame.render_widget(
        Paragraph::new(Span::styled(
            "─".repeat(area.width as usize),
            Style::new().fg(RULE),
        )),
        area,
    );
}

fn draw_header(frame: &mut Frame, app: &App, area: Rect) {
    let spans = vec![
        Span::styled(" Sennel", Style::new().fg(GOLD)),
        dim("  ·  "),
        Span::styled(app.stage.clone(), Style::new().fg(CREAM)),
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
    if app.vault.is_none() {
        frame.render_widget(Paragraph::new(Line::from(dim(" no vault open"))), area);
        return;
    }
    if area.width >= PREVIEW_FROM {
        /* u32: the product overflows u16 past 32767 columns. */
        let detail = (u32::from(area.width) * 2 / 5).min(46) as u16;
        let [groups, entries, detail] = Layout::horizontal([
            Constraint::Percentage(25),
            Constraint::Min(1),
            Constraint::Length(detail),
        ])
        .areas(area);
        draw_groups(frame, app, groups);
        draw_entries(frame, app, entries);
        draw_detail(frame, app, detail);
        app.viewport = (groups.height as usize).min(entries.height as usize).max(1);
        app.wide = true;
    } else {
        let [groups, entries] =
            Layout::horizontal([Constraint::Percentage(35), Constraint::Min(1)]).areas(area);
        /* What a page key moves by, which only the layout knows. The lower
           of the two, so a page never overshoots whichever pane is live. */
        app.viewport = (groups.height as usize).min(entries.height as usize).max(1);
        app.wide = false;
        draw_groups(frame, app, groups);
        draw_entries(frame, app, entries);
    }
}

/* Columns, not characters, and never straddling the edge: a width of one
   against a two-column glyph would otherwise take nothing and spill into the
   next field. Callers pad to the column count, which absorbs coming back
   short. */
fn truncate(text: &str, width: usize) -> String {
    if cols(text) <= width {
        return text.to_string();
    }
    let mut out = String::new();
    let mut used = 0;
    for c in text.chars() {
        let w = UnicodeWidthChar::width(c).unwrap_or(0);
        if used + w > width {
            break;
        }
        used += w;
        out.push(c);
    }
    out
}

/* Only worth the column when the list actually runs off the pane. */
fn draw_scrollbar(frame: &mut Frame, area: Rect, len: usize, at: usize) {
    if len > area.height as usize {
        let mut state = ScrollbarState::new(len).position(at);
        frame.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(None)
                .end_symbol(None)
                .thumb_style(Style::new().fg(DIM))
                .track_symbol(None),
            area,
            &mut state,
        );
    }
}

/* Pre-order with two cells of indent per depth: a flat list of names hides
   which folder an entry row belongs to, and the tree is the only place depth
   is visible. The marker is TEAL in the live pane and DIM in the other, so
   each pane still says where its own cursor is. */
fn draw_groups(frame: &mut Frame, app: &mut App, area: Rect) {
    let tree = app.group_tree();
    if tree.is_empty() {
        frame.render_widget(Paragraph::new(Line::from(dim(" no groups"))), area);
        return;
    }
    let at = tree
        .iter()
        .position(|(id, _)| Some(*id) == app.group_cursor)
        .unwrap_or(0);
    let live = app.active_pane == Pane::Groups;
    let width = area.width as usize;
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
            let shown = truncate(
                &format!("{}{}{name}", "  ".repeat(*depth), branch),
                width.saturating_sub(2),
            );
            let mark = if selected && live {
                teal("▌")
            } else if selected {
                dim("▌")
            } else {
                Span::raw(" ")
            };
            ListItem::new(Line::from(vec![
                mark,
                Span::styled(format!(" {shown}"), row_style(selected)),
            ]))
        })
        .collect();
    /* Carried across frames, or ratatui recomputes the least scroll that makes
       the selection visible and pins the cursor to the last row. */
    app.group_scroll = app::scroll_to(app.group_scroll, at, tree.len(), area.height as usize);
    let mut state = ListState::default().with_offset(app.group_scroll);
    state.select(Some(at));
    frame.render_stateful_widget(List::new(items), area, &mut state);
    draw_scrollbar(frame, area, tree.len(), at);
}

fn draw_entries(frame: &mut Frame, app: &mut App, area: Rect) {
    let rows = app.entry_rows();
    /* A live needle owns the empty state: "no entries here" would be a lie
       when the pane is global, and the way out (Esc) is part of the message. */
    let searching = app.search.as_deref().is_some_and(|n| !n.is_empty());
    if rows.is_empty() {
        let text = if searching {
            dim(format!(
                " nothing matches {} · esc clears it",
                app.search.as_deref().unwrap_or("")
            ))
        } else {
            dim(" no entries here")
        };
        frame.render_widget(Paragraph::new(Line::from(text)), area);
        return;
    }
    let at = rows
        .iter()
        .position(|id| Some(*id) == app.entry_cursor)
        .unwrap_or(0);
    let live = app.active_pane == Pane::Entries;
    let width = area.width as usize;
    let items: Vec<ListItem> = rows
        .iter()
        .map(|id| {
            let selected = Some(*id) == app.entry_cursor;
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
            let name = truncate(&title, width.saturating_sub(2));
            let mark = if selected && live {
                teal("▌")
            } else if selected {
                dim("▌")
            } else {
                Span::raw(" ")
            };
            let mut spans = vec![
                mark,
                Span::styled(format!(" {name}"), row_style(selected)),
            ];
            if !user.is_empty() {
                spans.push(dim(format!("  {user}")));
            }
            /* Global search pulls rows out of their folder, so the pane says
               where each one lives — the same dim-suffix rule as the user. */
            if searching && !group.is_empty() {
                spans.push(dim(format!("  · {group}")));
            }
            ListItem::new(Line::from(spans))
        })
        .collect();
    app.entry_scroll = app::scroll_to(app.entry_scroll, at, rows.len(), area.height as usize);
    let mut state = ListState::default().with_offset(app.entry_scroll);
    state.select(Some(at));
    frame.render_stateful_widget(List::new(items), area, &mut state);
    draw_scrollbar(frame, area, rows.len(), at);
}

/* The row keeps only title and user, so the pane says the rest: url, notes,
   and the password masked to a fixed run of bullets. Fixed length because
   even the length is something the screen may not reveal. */
fn draw_detail(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::new()
        .borders(Borders::LEFT)
        .border_style(Style::new().fg(RULE));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.width == 0 || inner.height == 0 {
        return;
    }
    let width = inner.width as usize;
    let Some(entry) = app.selected_entry() else {
        frame.render_widget(Paragraph::new(Line::from(dim(" no entry"))), inner);
        return;
    };
    let row = |label: &str, value: String, style: Style| {
        Line::from(vec![
            dim(format!(" {label:<8}")),
            Span::styled(value, style),
        ])
    };
    let cream = Style::new().fg(CREAM);
    let faint = Style::new().fg(DIM);
    let mut lines = vec![
        Line::from(Span::styled(
            truncate(entry.title(), width),
            row_style(true),
        )),
        Line::default(),
        row(
            "user",
            truncate(entry.username(), width.saturating_sub(10)),
            cream,
        ),
        row(
            "pass",
            if app.show_password {
                truncate(entry.password(), width.saturating_sub(10))
            } else {
                "••••••••".to_string()
            },
            cream,
        ),
    ];
    if !entry.url().is_empty() {
        lines.push(row(
            "url",
            truncate(entry.url(), width.saturating_sub(10)),
            faint,
        ));
    }
    /* First line only: the row is one row, and a note that wraps the pane is
       what Enter's popup is for. */
    let notes = entry.notes().lines().next().unwrap_or("");
    if !notes.is_empty() {
        lines.push(row(
            "notes",
            truncate(notes, width.saturating_sub(10)),
            faint,
        ));
    }
    for (label, value) in stamps(&entry) {
        lines.push(row(label, value, faint));
    }
    /* The pane has room to spare, and a key nobody knows about is a key that
       does not exist: the hint sits at the foot of the empty half. */
    let hint = Line::from(dim(" y copy · p pass · * reveal"));
    let height = inner.height as usize;
    if height > lines.len() + 1 {
        lines.resize(height - 1, Line::default());
        lines.push(hint);
    }
    lines.truncate(height);
    frame.render_widget(Paragraph::new(lines), inner);
}

/* KDBX stamps are UTC and optional, and say so: a stamp quietly converted
   wrong reads as a wrong stamp. */
fn stamps(entry: &keepass::db::EntryRef<'_>) -> Vec<(&'static str, String)> {
    [
        ("updated", entry.times.last_modification),
        ("created", entry.times.creation),
    ]
    .into_iter()
    .filter_map(|(label, t)| {
        t.map(|t| (label, format!("{} UTC", t.format("%Y-%m-%d %H:%M"))))
    })
    .collect()
}

/* Enter's detail popup: the whole entry, wide enough for a url and tall
   enough for the notes, on the 80-column terminal where no side pane fits.
   Same masking rule as the pane — `*` is the only way to a plain password. */
fn draw_detail_popup(frame: &mut Frame, app: &App) {
    let Some(entry) = app.selected_entry() else {
        return;
    };
    let area = frame.area();
    /* Room for the frame and a margin either side; the popup never grows past
       what the notes actually need. */
    let width = area.width.saturating_sub(8).clamp(20, 76);
    let inner = width.saturating_sub(4) as usize;
    let cream = Style::new().fg(CREAM);
    let faint = Style::new().fg(DIM);
    let row = |label: &str, value: String, style: Style| {
        Line::from(vec![
            dim(format!(" {label:<10}")),
            Span::styled(value, style),
        ])
    };
    let value = inner.saturating_sub(11);
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
    for (label, stamp) in stamps(&entry) {
        lines.push(row(label, stamp, faint));
    }
    lines.push(Line::default());
    lines.push(Line::from(vec![
        Span::styled(" y p U", Style::new().fg(GOLD)),
        dim(" copy   "),
        Span::styled("*", Style::new().fg(GOLD)),
        dim(" reveal   "),
        Span::styled("esc", Style::new().fg(GOLD)),
        dim(" close"),
    ]));
    let title = truncate(entry.title(), inner);
    popup(frame, &title, lines, width);
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
    use crate::app::UnlockField;
    let title = if app.unlock_new && app.db_path.is_some() {
        "new database"
    } else if app.db_path.is_none() {
        "no database"
    } else {
        "unlock"
    };

    let mut rows: Vec<Line> = Vec::new();
    if app.db_path.is_none() && !app.unlock_new {
        rows.push(Line::from(dim(
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
            Style::new().fg(CREAM)
        } else {
            Style::new().fg(DIM)
        };
        Line::from(vec![
            dim(format!(" {label:<8}")),
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
    rows.push(Line::from(dim(" tab field   enter unlock   esc clear   ^r reveal")));
    let width = rows.iter().map(|l| l.width() as u16).max().unwrap_or(0) + 3;
    popup(frame, title, rows, width.max(20));
}

fn draw_status(frame: &mut Frame, app: &mut App, area: Rect) {
    let mut spans = vec![Span::raw(" ")];
    if app.view == View::Browser {
        spans.push(Span::styled("y user", Style::new().fg(GOLD)));
        spans.push(dim("   p pass   U url"));
        /* Whole-vault health where earworm puts the run summary: the panes
           show one group at a time, so only the bar says how big the vault
           is. Skipped while locked: there is no vault to count. */
        if let Some(vault) = &app.vault {
            let groups = app.group_tree().len();
            let entries = vault.entry_count();
            let g = if groups == 1 { "group" } else { "groups" };
            let e = if entries == 1 { "entry" } else { "entries" };
            spans.push(dim(format!("  {groups} {g} · {entries} {e}   ")));
        }
        /* While the band filters, the bar counts honestly: N of M tells the
           truth about matches across the whole vault, not just this pane. */
        if app.search.is_some() {
            let shown = app.entry_matches();
            let total = app.entry_total();
            spans.push(Span::styled(
                format!("  {shown} of {total} shown  "),
                Style::new().fg(GOLD),
            ));
        }
        /* An armed cut is one keypress from moving something: the bar names
           it so X never reads as a silent no-op. */
        if let Some(note) = app.cut_note() {
            spans.push(Span::styled(format!("{note} · v pastes  "), Style::new().fg(AMBER)));
        }
        /* The undo slot is the same deal: `u` has a name, so the key can be
           pressed on purpose rather than as a gamble. */
        if let Some(note) = app.undo_note() {
            spans.push(Span::styled(format!("{note}  "), Style::new().fg(AMBER)));
        }
    } else {
        spans.push(dim("   enter unlock   "));
    }
    spans.push(Span::styled("h keys", Style::new().fg(DIM)));
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

/* The filter band, one row between body and status: `/needle█` like earworm.
   The caret is a block between the split halves of the needle, the same
   char-index rule as every other box in the app. */
fn draw_search(frame: &mut Frame, app: &App, area: Rect) {
    let needle = app.search.as_deref().unwrap_or_default();
    /* A kept filter gave the keys back: a caret on a box that no longer takes
       typing reads as one that does. */
    if !app.band {
        let line = Line::from(vec![
            Span::styled(format!("/{needle}"), Style::new().fg(GOLD)),
            dim("  esc clears"),
        ]);
        frame.render_widget(Paragraph::new(line), area);
        return;
    }
    let at = char_index_to_byte(needle, app.search_caret);
    let (head, tail) = needle.split_at(at.min(needle.len()));
    let line = Line::from(vec![
        Span::styled("/", Style::new().fg(GOLD)),
        Span::styled(head.to_string(), Style::new().fg(CREAM)),
        Span::styled("█", Style::new().fg(GOLD)),
        Span::styled(tail.to_string(), Style::new().fg(CREAM)),
        dim("  enter keep · esc clear"),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

fn popup(frame: &mut Frame, title: &str, lines: Vec<Line<'_>>, width: u16) {
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
        .border_style(Style::new().fg(GOLD))
        .title(Span::styled(format!(" {title} "), Style::new().fg(GOLD)))
        .style(Style::new().bg(SURFACE));
    let inner = block.inner(at);
    frame.render_widget(block, at);
    frame.render_widget(Paragraph::new(lines), inner);
}

/* Its own question rather than a prompt: no vault is blocked on the answer,
   so it carries no reply channel. Only a named key confirms, so an
   unrecognised key must not be an accidental yes. */
fn draw_confirm(frame: &mut Frame, app: &App, what: &Confirm) {
    let _ = app;
    let (title, question, yes) = match what {
        Confirm::Quit => (
            "quit?",
            " unsaved changes would be lost".to_string(),
            Span::styled(" q  quit", Style::new().fg(GOLD)),
        ),
        /* The title travels in the confirm so the answer is about a row the
           user can see. A name is user-chosen text, never a secret. */
        Confirm::DeleteEntry { title, .. } => (
            "delete?",
            format!(" delete entry “{title}”?  this cannot be undone"),
            Span::styled(" y  delete", Style::new().fg(RED)),
        ),
        Confirm::DeleteGroup { title, .. } => (
            "delete?",
            format!(" delete group “{title}”?  this cannot be undone"),
            Span::styled(" y  delete", Style::new().fg(RED)),
        ),
    };
    let lines = vec![
        Line::from(Span::styled(question, Style::new().fg(CREAM))),
        Line::default(),
        Line::from(vec![yes, dim("     esc  keep going")]),
    ];
    let width = lines.iter().map(|l| l.width() as u16).max().unwrap_or(0) + 3;
    popup(frame, title, lines, width);
}

/* The modal entry editor: five labelled boxes, the caret block only in the
   focused one. Shape mirrors the unlock screen so muscle memory carries over.
   The password box masks as bullets and, on edit, advertises that empty
   keeps — the one box where emptiness has a meaning. */
fn draw_form(frame: &mut Frame, app: &App) {
    let Some(form) = &app.form else {
        return;
    };
    let split_at_char = |text: &str, caret: usize| -> (String, String) {
        let mut first = text.chars();
        let head: String = first.by_ref().take(caret).collect();
        (head, first.collect())
    };
    let row = |label: &'static str, field: FormField, value: &str| -> Line<'_> {
        let focused = form.field == field;
        let shown = match field {
            /* The edit password box starts empty on purpose; typed content
               masks. The hint only shows while the box holds nothing. */
            FormField::Password if value.is_empty() && !form.password_touched => {
                "(leave empty to keep)".to_string()
            }
            FormField::Password => "•".repeat(value.chars().count()),
            _ => value.to_string(),
        };
        let (head, tail) = split_at_char(&shown, if focused { form.caret } else { 0 });
        let style = if focused {
            Style::new().fg(CREAM)
        } else {
            Style::new().fg(DIM)
        };
        Line::from(vec![
            Span::styled(format!(" {label:<9}"), style),
            Span::styled(head, style),
            /* The block caret sits between the split halves; an unfocused
               box draws none, so the eye finds the live box first. */
            Span::styled(if focused { "█" } else { "" }, style),
            Span::styled(tail, style),
        ])
    };
    let lines = vec![
        row("title", FormField::Title, &form.title),
        row("username", FormField::Username, &form.username),
        row("password", FormField::Password, &form.password),
        row("url", FormField::Url, &form.url),
        row("notes", FormField::Notes, &form.notes),
        Line::default(),
        Line::from(vec![
            Span::styled(" enter", Style::new().fg(GOLD)),
            dim(" save   "),
            Span::styled("^s", Style::new().fg(GOLD)),
            dim(" generate   "),
            Span::styled("tab", Style::new().fg(GOLD)),
            dim(" next box   "),
            Span::styled("esc", Style::new().fg(GOLD)),
            dim(" throw away"),
        ]),
    ];
    let width = lines.iter().map(|l| l.width() as u16).max().unwrap_or(0) + 3;
    let title = match form.kind {
        FormKind::Add => "new entry",
        FormKind::Edit(_) => "edit entry",
    };
    popup(frame, title, lines, width);
}

/* One entry per line in three aligned columns. Only live keys: a row naming
   a key that does nothing on this screen is documentation for a bug. */
fn draw_help(frame: &mut Frame, app: &App) {
    /* Only live keys: a row naming a key that does nothing on this screen is
       documentation for a bug. The lock owns every printable key, so its
       table names the boxes rather than the browser's list. */
    let mut rows: Vec<(&str, &str, &str)> = if app.view == View::Unlock {
        vec![
            ("type", "a–z  0–9", "the boxes take every key"),
            ("move", "tab  ↑ ↓", "between boxes"),
            ("edit", "^u  ^w", "clear box, kill word"),
            ("reveal", "^r", "show the password plainly"),
            ("go", "enter", "unlock"),
            ("quit", "^c", ""),
        ]
    } else {
        vec![
            ("move", "j k  ↑ ↓", "through the panes"),
            ("quit", "q  ^c", ""),
        ]
    };
    if app.view == View::Browser {
        rows.insert(1, ("copy", "y p U", "username, password, url"));
        rows.insert(2, ("edit", "a e D", "add, edit, delete entry"));
        rows.insert(3, ("groups", "A E D", "add, rename, delete group"));
        rows.insert(4, ("move", "X V", "cut, paste"));
        rows.insert(5, ("fold", "← →", "collapse, expand group"));
        rows.insert(6, ("order", "o", "entries: name, recent, updated"));
        rows.insert(7, ("undo", "u", "one level · ^s generates"));
        rows.insert(7, ("find", "/", "fuzzy search"));
    }

    let group = rows.iter().map(|r| r.0.chars().count()).max().unwrap_or(0) + 2;
    let key = rows.iter().map(|r| r.1.chars().count()).max().unwrap_or(0) + 2;

    let lines: Vec<Line> = rows
        .iter()
        .map(|(label, keys, what)| {
            Line::from(vec![
                Span::styled(format!(" {label:group$}"), Style::new().fg(DIM)),
                Span::styled(format!("{keys:key$}"), Style::new().fg(GOLD)),
                Span::styled((*what).to_string(), Style::new().fg(CREAM)),
            ])
        })
        .collect();

    let content = lines.iter().map(|l| l.width() as u16).max().unwrap_or(0);
    popup(frame, "keys", lines, content + 3);
}

/* The one-box group prompt behind A and E. Same field shape as the entry
   form's rows so the caret and styling read identically, minus the cycling:
   there is only the name. */
fn draw_group_prompt(frame: &mut Frame, app: &App) {
    let Some(prompt) = &app.group_prompt else {
        return;
    };
    /* One box, always focused: the popup only exists while it holds the keys. */
    let style = Style::new().fg(CREAM);
    let mut first = prompt.value.chars();
    let head: String = first.by_ref().take(prompt.caret).collect();
    let tail: String = first.collect();
    let lines = vec![
        Line::from(vec![
            Span::styled(" name     ", style),
            Span::styled(head, style),
            Span::styled("█", style),
            Span::styled(tail, style),
        ]),
        Line::default(),
        Line::from(vec![
            Span::styled(" enter", Style::new().fg(GOLD)),
            dim(" save   "),
            Span::styled("esc", Style::new().fg(GOLD)),
            dim(" throw away"),
        ]),
    ];
    let width = lines.iter().map(|l| l.width() as u16).max().unwrap_or(0) + 3;
    let title = match prompt.kind {
        GroupPromptKind::New => "new group",
        GroupPromptKind::Rename(_) => "rename group",
    };
    popup(frame, title, lines, width);
}

/* The row under the cursor is what the next key acts on, so its name is bold
   as well as marked. Bold is safe here because every colour is RGB: a
   terminal cannot swap it for a bright ANSI variant. */
fn row_style(selected: bool) -> Style {
    let style = Style::new().fg(CREAM);
    if selected {
        style.add_modifier(Modifier::BOLD)
    } else {
        style
    }
}

fn teal(text: impl Into<String>) -> Span<'static> {
    Span::styled(text.into(), Style::new().fg(TEAL))
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
        assert!(joined.contains("h keys"), "{joined}");
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
        assert!(joined.contains("delete entry"), "{joined}");
        assert!(joined.contains("checking"), "{joined}");
        assert!(joined.contains("cannot be undone"), "{joined}");
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
        assert!(joined.contains("delete group"), "{joined}");
        assert!(joined.contains("Empty"), "{joined}");
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
        assert!(joined.contains("v pastes"), "{joined}");
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
        assert!(joined.contains("1 of 2 shown"), "{joined}");
        assert!(joined.contains("esc clear"), "{joined}");
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
