use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Clear, List, ListItem, ListState, Paragraph, Scrollbar,
    ScrollbarOrientation, ScrollbarState,
};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::app::{self, App, Confirm, Pane, View};
use crate::theme::{self, CREAM, DIM, GOLD, RULE, SURFACE, TEAL};

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
    let [header, rule, body, footrule, status] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(frame.area());

    draw_background(frame);
    draw_header(frame, app, header);
    draw_rule(frame, rule);
    draw_body(frame, app, body);
    draw_rule(frame, footrule);
    draw_status(frame, app, status);

    if app.show_help {
        draw_help(frame, app);
    }
    if let Some(what) = app.confirm {
        draw_confirm(frame, app, what);
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
        Span::styled(" sennel", Style::new().fg(GOLD)),
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
    } else {
        let [groups, entries] =
            Layout::horizontal([Constraint::Percentage(35), Constraint::Min(1)]).areas(area);
        /* What a page key moves by, which only the layout knows. The lower
           of the two, so a page never overshoots whichever pane is live. */
        app.viewport = (groups.height as usize).min(entries.height as usize).max(1);
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
            let name = app
                .vault
                .as_ref()
                .and_then(|v| v.get_group(id))
                .map(|g| g.title.clone())
                .unwrap_or_default();
            let shown = truncate(&format!("{}{name}", "  ".repeat(*depth)), width.saturating_sub(2));
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
    if rows.is_empty() {
        frame.render_widget(
            Paragraph::new(Line::from(dim(" no entries here"))),
            area,
        );
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
            let (title, user) = app
                .vault
                .as_ref()
                .and_then(|v| v.get_entry(id))
                .map(|e| (e.title.clone(), e.username.as_str().to_string()))
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
            truncate(&entry.title, width),
            row_style(true),
        )),
        Line::default(),
        row(
            "user",
            truncate(entry.username.as_str(), width.saturating_sub(10)),
            cream,
        ),
        row(
            "pass",
            if app.show_password {
                truncate(entry.password.as_str(), width.saturating_sub(10))
            } else {
                "••••••••".to_string()
            },
            cream,
        ),
    ];
    if !entry.url.is_empty() {
        lines.push(row(
            "url",
            truncate(&entry.url, width.saturating_sub(10)),
            faint,
        ));
    }
    /* First line only: the row is one row, and a note that wraps the pane is
       a detail view of its own, which is Wave 7's editor to give. */
    let notes = entry.notes.as_str().lines().next().unwrap_or("");
    if !notes.is_empty() {
        lines.push(row(
            "notes",
            truncate(notes, width.saturating_sub(10)),
            faint,
        ));
    }
    lines.truncate(inner.height as usize);
    frame.render_widget(Paragraph::new(lines), inner);
}

/* One question with two or three boxes: the password always, the key file
   beside it (empty means none), the confirm joining only when creating. Only
   the focused box draws the block, or the popup shows two cursors and neither
   is where typing lands. The password is bullets end to end: length is the
   only thing about it the screen may reveal. */
fn draw_unlock(frame: &mut Frame, app: &App) {
    use crate::app::UnlockField;
    let title = if app.db_path.is_none() {
        "no database"
    } else if app.unlock_new {
        "new database"
    } else {
        "unlock"
    };

    let mut rows: Vec<Line> = Vec::new();
    match &app.db_path {
        Some(p) => rows.push(Line::from(dim(format!(" file  {}", p.display())))),
        /* Not an error state: the next step is a flag away, and the boxes
           below still take an answer worth keeping once one is named. */
        None => rows.push(Line::from(dim(" pass --db <file> or set db in the config"))),
    }
    rows.push(Line::default());

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
        let shown = if secret {
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
    rows.push(Line::from(dim(" tab field   enter unlock   esc clear")));
    let width = rows.iter().map(|l| l.width() as u16).max().unwrap_or(0) + 3;
    popup(frame, title, rows, width.max(20));
}

fn draw_status(frame: &mut Frame, app: &App, area: Rect) {
    let mut spans = vec![Span::raw(" ")];
    if app.view == View::Browser {
        spans.push(Span::styled("y user", Style::new().fg(GOLD)));
        spans.push(dim("   p pass   "));
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
    } else {
        spans.push(dim("   enter unlock   "));
    }
    spans.push(Span::styled("h keys", Style::new().fg(DIM)));
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

/* Wide enough for the content, centred, two rows of margin so it never
   touches the frame edge. `Clear` first: without it the gradient shows
   through and the popup reads as a hole rather than a surface. */
fn popup_width(area: Rect) -> u16 {
    (area.width.saturating_sub(4)).min(72).max(20)
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
fn draw_confirm(frame: &mut Frame, app: &App, what: Confirm) {
    let Confirm::Quit = what;
    let _ = app;
    let lines = vec![
        Line::from(Span::styled(
            " unsaved changes would be lost",
            Style::new().fg(CREAM),
        )),
        Line::default(),
        Line::from(vec![
            Span::styled(" q  quit", Style::new().fg(GOLD)),
            dim("     esc  keep going"),
        ]),
    ];
    let width = lines.iter().map(|l| l.width() as u16).max().unwrap_or(0) + 3;
    popup(frame, "quit?", lines, width);
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
            ("go", "enter", "unlock"),
            ("quit", "^c", ""),
        ]
    } else {
        vec![
            ("move", "j k  ↑ ↓", "wave 1 gives these a list"),
            ("quit", "q  ^c", ""),
        ]
    };
    if app.view == View::Browser {
        rows.insert(
            1,
            ("copy", "y  p", "username, password"),
        );
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
        assert!(joined.contains("sennel"), "{joined}");
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
        assert!(joined.contains("sennel"), "{joined}");
    }
}
