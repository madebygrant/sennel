// Environment variable entries: a pasted .env file read into protected fields, with its comments,
// blank lines and order kept in a layout beside them so the file can be written back out.

use std::collections::{HashMap, HashSet};

use zeroize::Zeroizing;

use keepass::db::{CustomDataItem, CustomDataValue, EntryId, EntryRef, Times};

use crate::vault::{EntryExt, STANDARD, Vault, VaultError, resolve_text};

/// Entry custom data that marks an entry as a set of environment variables.
pub const TYPE_KEY: &str = "sennel.type";
pub const TYPE_ENV: &str = "env";
/// The file's shape with every value taken out. See `Line` for the format.
pub const LAYOUT_KEY: &str = "sennel.env.layout";
/// Set on a field that was a commented-out variable, which `run` and export leave out.
pub const OFF_PREFIX: &str = "sennel.env.off:";
/// A real .env is a few kilobytes; this refuses a paste of the wrong thing.
pub const MAX_BYTES: usize = 256 * 1024;

/// One variable read from the file. The value wipes on drop.
pub struct Var {
    /// The KeePass field it is stored in. The same as `name`, except for a commented-out variable
    /// whose name is already taken, which gets ` (off)` or ` (off 2)` after it.
    pub field: String,
    pub name: String,
    pub value: Zeroizing<String>,
    pub disabled: bool,
    pub line: usize,
}

/// A line the parser would not take. `why` never quotes the line, which may hold a secret.
#[derive(Debug, PartialEq, Eq)]
pub struct Refused {
    pub line: usize,
    pub why: String,
}

#[derive(Default)]
pub struct Parsed {
    pub vars: Vec<Var>,
    pub layout: String,
    pub refused: Vec<Refused>,
}

impl Parsed {
    /// The first refused line, worded for a message, or None when every line was taken.
    pub fn refusal(&self) -> Option<String> {
        self.refused.first().map(|r| match r.line {
            0 => r.why.clone(),
            n => format!("line {n}: {}", r.why),
        })
    }
}

/// One line of a stored layout. Written as a tag and tab-separated parts: `t<text>` for a comment
/// or blank line kept as it was, `v<x?>\t<field>\t<name>\t<comment>` for a variable, where `x`
/// means it had `export` before it. The comment goes last so it may hold tabs.
#[derive(Debug, PartialEq, Eq)]
pub enum Line {
    Text(String),
    Var {
        field: String,
        name: String,
        export: bool,
        comment: String,
    },
}

/// A variable as the views show it, in file order. No value: the caller reads the field.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Row {
    pub field: String,
    pub name: String,
    pub label: Option<String>,
    pub section: Option<String>,
    pub disabled: bool,
}

pub fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

// `NAME=rest` with an optional `export ` first. None when the line is not shaped like one at all.
fn assignment(line: &str) -> Option<(bool, &str, &str)> {
    let (export, line) = match line.strip_prefix("export") {
        Some(rest) if rest.starts_with([' ', '\t']) => (true, rest.trim_start()),
        _ => (false, line),
    };
    let (name, rest) = line.split_once('=')?;
    Some((export, name.trim_end(), rest))
}

// Returns the value, the comment after it, and how many later lines a quoted value ran onto.
fn value(
    rest: &str,
    later: &[&str],
    multiline: bool,
) -> Result<(Zeroizing<String>, String, usize), String> {
    let start = rest.trim_start();
    let Some(quote) = start
        .chars()
        .next()
        .filter(|c| matches!(c, '"' | '\'' | '`'))
    else {
        return Ok(unquoted(rest));
    };
    let mut text = Zeroizing::new(start[1..].to_string());
    let mut used = 0;
    // Where the last scan stopped, so each added line is scanned once, not the whole text again.
    let mut scan = Scan::default();
    loop {
        if let Some(end) = scan.closing(&text, quote) {
            let after = text[end + 1..].trim();
            let comment = match after.strip_prefix('#') {
                Some(c) => c.trim().to_string(),
                None if after.is_empty() => String::new(),
                None => return Err("text after the closing quote".into()),
            };
            let inner = &text[..end];
            let value = match quote {
                '"' => unescape(inner),
                _ => Zeroizing::new(inner.to_string()),
            };
            return Ok((value, comment, used));
        }
        match later.get(used) {
            Some(next) if multiline => {
                text.push('\n');
                text.push_str(next);
                used += 1;
            }
            _ => return Err("a quote that is never closed".into()),
        }
    }
}

// A `#` starts a comment only after whitespace, as dotenv reads it, so `KEY=a#b` keeps `a#b`.
fn unquoted(rest: &str) -> (Zeroizing<String>, String, usize) {
    let mut prev_space = true;
    for (at, c) in rest.char_indices() {
        if c == '#' && prev_space {
            let value = Zeroizing::new(rest[..at].trim().to_string());
            return (value, rest[at + 1..].trim().to_string(), 0);
        }
        prev_space = c.is_whitespace();
    }
    (Zeroizing::new(rest.trim().to_string()), String::new(), 0)
}

#[derive(Default)]
struct Scan {
    from: usize,
    escaped: bool,
}

impl Scan {
    fn closing(&mut self, text: &str, quote: char) -> Option<usize> {
        for (at, c) in text[self.from..].char_indices() {
            match c {
                '\\' if quote == '"' && !self.escaped => self.escaped = true,
                c if c == quote && !self.escaped => return Some(self.from + at),
                _ => self.escaped = false,
            }
        }
        self.from = text.len();
        None
    }
}

fn unescape(inner: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(inner.len()));
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some(c @ ('"' | '\\' | '$' | '`')) => out.push(c),
            Some(c) => {
                out.push('\\');
                out.push(c);
            }
            None => out.push('\\'),
        }
    }
    out
}

// A commented-out variable: `# NAME=value`, `#NAME=value` or `# export NAME=value`.
fn commented(line: &str) -> Option<(bool, &str, &str)> {
    let body = line.trim_start().strip_prefix('#')?.trim_start();
    let (export, name, rest) = assignment(body)?;
    valid_name(name).then_some((export, name, rest))
}

/// Reads a whole .env file. Every line is kept in the layout, stored as a variable, or refused.
pub fn parse(text: &str) -> Parsed {
    let mut out = Parsed::default();
    if text.len() > MAX_BYTES {
        out.refused.push(Refused {
            line: 0,
            why: format!("over {} KB, which is not a .env file", MAX_BYTES / 1024),
        });
        return out;
    }
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut lines: Vec<&str> = text
        .split('\n')
        .map(|l| l.strip_suffix('\r').unwrap_or(l))
        .collect();
    // The newline that ends the last line starts no line of its own.
    if lines.last() == Some(&"") {
        lines.pop();
    }
    // Every live name up front, so a commented-out variable read first already knows to step aside.
    let live: HashSet<&str> = lines
        .iter()
        .map(|l| l.trim())
        .filter(|t| !t.starts_with('#'))
        .filter_map(|t| assignment(t).map(|(_, name, _)| name))
        .collect();
    let mut fields = Fields::default();
    let mut layout: Vec<Line> = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let n = i + 1;
        let line = lines[i];
        i += 1;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            layout.push(Line::Text(String::new()));
            continue;
        }
        if trimmed.starts_with('#') {
            let Some((export, name, rest)) = commented(trimmed) else {
                layout.push(Line::Text(trimmed.to_string()));
                continue;
            };
            // Stored as a protected field whatever it holds: it is usually an old secret, and the
            // layout is plain text.
            let (value, comment) = match value(rest, &[], false) {
                Ok((value, comment, _)) => (value, comment),
                Err(_) => (Zeroizing::new(rest.trim().to_string()), String::new()),
            };
            let field = fields.commented(name, &live);
            layout.push(Line::Var {
                field: field.clone(),
                name: name.to_string(),
                export,
                comment,
            });
            out.vars.push(Var {
                field,
                name: name.to_string(),
                value,
                disabled: true,
                line: n,
            });
            continue;
        }
        // Only the start is trimmed: a quoted value that runs onto the next line keeps its spaces.
        let Some((export, name, rest)) = assignment(line.trim_start()) else {
            out.refused.push(Refused {
                line: n,
                why: "not NAME=value".into(),
            });
            continue;
        };
        let refuse = |why: String| Refused { line: n, why };
        if !valid_name(name) {
            out.refused
                .push(refuse("the name is not letters, digits and _".into()));
            continue;
        }
        let (value, comment, used) = match value(rest, &lines[i..], true) {
            Ok(parsed) => parsed,
            Err(why) => {
                out.refused.push(refuse(format!("{name} has {why}")));
                continue;
            }
        };
        i += used;
        if STANDARD.contains(&name) {
            out.refused.push(refuse(format!(
                "{name} is a standard KeePass field · rename it"
            )));
            continue;
        }
        if !fields.used.insert(name.to_string()) {
            out.refused.push(refuse(format!("{name} is set twice")));
            continue;
        }
        layout.push(Line::Var {
            field: name.to_string(),
            name: name.to_string(),
            export,
            comment,
        });
        out.vars.push(Var {
            field: name.to_string(),
            name: name.to_string(),
            value,
            disabled: false,
            line: n,
        });
    }
    out.layout = write_layout(&layout);
    out
}

// Field names given out so far. Sets, so a pasted file of thousands of lines parses in one pass.
#[derive(Default)]
struct Fields {
    used: HashSet<String>,
    next_off: HashMap<String, usize>,
}

impl Fields {
    // A commented-out variable's field: its own name when no live variable and no earlier field
    // has it, else `NAME (off)`, `NAME (off 2)` and so on.
    fn commented(&mut self, name: &str, live: &HashSet<&str>) -> String {
        if !live.contains(name) && !STANDARD.contains(&name) && self.used.insert(name.into()) {
            return name.to_string();
        }
        let next = self.next_off.entry(name.to_string()).or_insert(1);
        loop {
            let candidate = match *next {
                1 => format!("{name} (off)"),
                n => format!("{name} (off {n})"),
            };
            *next += 1;
            if self.used.insert(candidate.clone()) {
                return candidate;
            }
        }
    }
}

pub fn write_layout(lines: &[Line]) -> String {
    let mut out = String::new();
    for line in lines {
        match line {
            Line::Text(text) => {
                out.push('t');
                out.push_str(text);
            }
            Line::Var {
                field,
                name,
                export,
                comment,
            } => {
                out.push('v');
                if *export {
                    out.push('x');
                }
                out.push_str(&format!("\t{field}\t{name}\t{comment}"));
            }
        }
        out.push('\n');
    }
    out
}

// A line it cannot read is dropped, since the fields are what count.
pub fn read_layout(text: &str) -> Vec<Line> {
    text.lines()
        .filter_map(|l| {
            if let Some(text) = l.strip_prefix('t') {
                return Some(Line::Text(text.to_string()));
            }
            let rest = l.strip_prefix('v')?;
            let (export, rest) = match rest.strip_prefix('x') {
                Some(r) => (true, r),
                None => (false, rest),
            };
            let mut parts = rest.strip_prefix('\t')?.splitn(3, '\t');
            let field = parts.next()?.to_string();
            let name = parts.next()?.to_string();
            let comment = parts.next().unwrap_or("").to_string();
            Some(Line::Var {
                field,
                name,
                export,
                comment,
            })
        })
        .collect()
}

// The words of a comment line, or None for a rule like `# -----` that says nothing.
fn comment_words(text: &str) -> Option<String> {
    let words = text.trim_start_matches('#').trim();
    words
        .chars()
        .any(char::is_alphanumeric)
        .then(|| words.to_string())
}

/// The variables in file order with their labels and sections. A comment right above a variable,
/// or after it on the same line, labels it. A comment followed by a blank line heads a section.
/// `exists` says whether a field is still on the entry, since another app may have removed it.
pub fn rows(
    layout: &[Line],
    exists: impl Fn(&str) -> bool,
    off: impl Fn(&str) -> bool,
) -> Vec<Row> {
    let mut rows = Vec::new();
    let mut seen: HashSet<&str> = HashSet::new();
    let mut pending: Vec<String> = Vec::new();
    let mut section: Option<String> = None;
    for line in layout {
        match line {
            Line::Text(text) if text.trim().is_empty() => {
                if !pending.is_empty() {
                    section = Some(pending.join(" "));
                    pending.clear();
                }
            }
            Line::Text(text) => pending.extend(comment_words(text)),
            Line::Var {
                field,
                name,
                comment,
                ..
            } => {
                let label = match comment_words(comment) {
                    Some(words) => Some(words),
                    None if !pending.is_empty() => Some(pending.join(" ")),
                    None => None,
                };
                pending.clear();
                if exists(field) && seen.insert(field.as_str()) {
                    rows.push(Row {
                        field: field.clone(),
                        name: name.clone(),
                        label,
                        section: section.clone(),
                        disabled: off(field),
                    });
                }
            }
        }
    }
    rows
}

/// A value as a .env line writes it: bare when that is safe, else single quotes, which both
/// dotenv and a shell read literally, else double quotes with escapes. `one_line` forces the
/// escapes for a line break, which a commented-out variable needs to stay one comment.
pub fn quoted(value: &str, one_line: bool) -> Zeroizing<String> {
    let bare = value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "-_./:@+,%=~^".contains(c));
    if bare {
        return Zeroizing::new(value.to_string());
    }
    if !value.contains('\'') && !(one_line && value.contains(['\n', '\r'])) {
        return Zeroizing::new(format!("'{value}'"));
    }
    let mut out = Zeroizing::new(String::with_capacity(value.len() + 2));
    out.push('"');
    for c in value.chars() {
        match c {
            '"' | '\\' | '$' | '`' => {
                out.push('\\');
                out.push(c);
            }
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// One line of an exported file.
pub fn render_var(
    name: &str,
    value: &str,
    export: bool,
    disabled: bool,
    comment: &str,
) -> Zeroizing<String> {
    let mut line = Zeroizing::new(String::new());
    if disabled {
        line.push_str("# ");
    }
    if export {
        line.push_str("export ");
    }
    line.push_str(name);
    line.push('=');
    line.push_str(&quoted(value, disabled));
    if !comment.is_empty() {
        line.push_str(" # ");
        line.push_str(comment);
    }
    line
}

fn custom_str<'a>(entry: &'a EntryRef<'_>, key: &str) -> Option<&'a str> {
    match entry.custom_data.get(key)?.value.as_ref()? {
        CustomDataValue::String(text) => Some(text),
        _ => None,
    }
}

pub fn is_env(entry: &EntryRef<'_>) -> bool {
    custom_str(entry, TYPE_KEY) == Some(TYPE_ENV)
}

pub fn is_off(entry: &EntryRef<'_>, field: &str) -> bool {
    entry
        .custom_data
        .contains_key(&format!("{OFF_PREFIX}{field}"))
}

/// The layout line for each variable, keyed by field, for export.
fn layout_of(entry: &EntryRef<'_>) -> Vec<Line> {
    custom_str(entry, LAYOUT_KEY)
        .map(read_layout)
        .unwrap_or_default()
}

/// Every variable on an env entry in file order. Fields the layout does not name, such as one
/// added in KeePassXC, follow at the end in name order with no label.
pub fn entry_rows(entry: &EntryRef<'_>) -> Vec<Row> {
    let custom = |f: &str| entry.fields.contains_key(f) && !STANDARD.contains(&f);
    let mut rows = rows(&layout_of(entry), custom, |f| is_off(entry, f));
    let listed: HashSet<String> = rows.iter().map(|r| r.field.clone()).collect();
    let mut rest: Vec<&String> = entry
        .fields
        .keys()
        .filter(|f| custom(f) && !listed.contains(*f))
        .collect();
    rest.sort();
    rows.extend(rest.into_iter().map(|f| Row {
        field: f.clone(),
        name: f.clone(),
        label: None,
        section: None,
        disabled: is_off(entry, f),
    }));
    rows
}

/// How many variables `entry_rows` would list, without parsing the layout: every row it returns
/// is a field outside the standard five, so counting those fields gives the same number.
pub fn var_count(entry: &EntryRef<'_>) -> usize {
    entry
        .fields
        .keys()
        .filter(|f| !STANDARD.contains(&f.as_str()))
        .count()
}

/// The entry written back out as a .env file, comments and order included. Field references are
/// resolved, falling back to the raw text when one is broken, as the other exports do. Returns the
/// fields left out because their names are not variable names.
pub fn export(vault: &Vault, entry: &EntryRef<'_>) -> (Zeroizing<String>, Vec<String>) {
    let mut out = Zeroizing::new(String::new());
    let mut skipped = Vec::new();
    let value = |field: &str| {
        let raw = entry
            .fields
            .get(field)
            .map(|v| v.get().as_str())
            .unwrap_or("");
        resolve_text(vault, raw).unwrap_or_else(|_| Zeroizing::new(raw.to_string()))
    };
    let mut written: HashSet<&str> = HashSet::new();
    let layout = layout_of(entry);
    for line in &layout {
        match line {
            Line::Text(text) => out.push_str(text),
            Line::Var {
                field,
                name,
                export,
                comment,
            } => {
                if !entry.fields.contains_key(field) || STANDARD.contains(&field.as_str()) {
                    continue;
                }
                if !written.insert(field) {
                    continue;
                }
                let value = value(field);
                out.push_str(&render_var(
                    name,
                    &value,
                    *export,
                    is_off(entry, field),
                    comment,
                ));
            }
        }
        out.push('\n');
    }
    for row in entry_rows(entry) {
        if written.contains(&row.field.as_str()) {
            continue;
        }
        if !valid_name(&row.name) {
            skipped.push(row.field);
            continue;
        }
        let value = value(&row.field);
        out.push_str(&render_var(&row.name, &value, false, row.disabled, ""));
        out.push('\n');
    }
    (out, skipped)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    New,
    Changed,
    Same,
    Removed,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::New => "new",
            Status::Changed => "changed",
            Status::Same => "same",
            Status::Removed => "removed",
        }
    }
}

/// What writing `parsed` over an entry would do to each field, for a preview. Labels and sections
/// come from the new layout; removed fields follow at the end.
pub struct Planned {
    pub row: Row,
    pub status: Status,
}

pub fn plan(entry: Option<&EntryRef<'_>>, parsed: &Parsed) -> Vec<Planned> {
    let by_field: HashMap<&str, &Var> = parsed.vars.iter().map(|v| (v.field.as_str(), v)).collect();
    let var = |f: &str| by_field.get(f).copied();
    let layout = read_layout(&parsed.layout);
    let mut out: Vec<Planned> = rows(
        &layout,
        |f| var(f).is_some(),
        |f| var(f).is_some_and(|v| v.disabled),
    )
    .into_iter()
    .map(|row| {
        let new = var(&row.field).expect("rows only lists fields that exist");
        let status = match entry.and_then(|e| e.fields.get(&row.field)) {
            None => Status::New,
            Some(old) if old.get().as_str() == new.value.as_str() => {
                match entry.is_some_and(|e| is_off(e, &row.field)) == new.disabled {
                    true => Status::Same,
                    false => Status::Changed,
                }
            }
            Some(_) => Status::Changed,
        };
        Planned { row, status }
    })
    .collect();
    if let Some(entry) = entry {
        for row in entry_rows(entry) {
            if var(&row.field).is_none() {
                out.push(Planned {
                    row,
                    status: Status::Removed,
                });
            }
        }
    }
    out
}

impl Vault {
    /// Makes an entry hold exactly the variables in `parsed`: new and changed ones are written
    /// protected, and custom fields the file no longer has are removed. Refused when the paste had
    /// refused lines, or when the entry has custom fields and is not an env entry. False when
    /// nothing changed.
    pub fn write_env(&mut self, id: &EntryId, parsed: &Parsed) -> Result<bool, VaultError> {
        if let Some(why) = parsed.refusal() {
            return Err(VaultError::Db(why));
        }
        let entry = self.get_entry(id).ok_or(VaultError::EntryNotFound)?;
        let has_custom = entry.fields.keys().any(|f| !STANDARD.contains(&f.as_str()));
        if !is_env(&entry) && has_custom {
            return Err(VaultError::Db(format!(
                "{} has its own fields and is not an env entry",
                entry.title()
            )));
        }
        let changed = custom_str(&entry, LAYOUT_KEY) != Some(parsed.layout.as_str())
            || !is_env(&entry)
            || plan(Some(&entry), parsed)
                .iter()
                .any(|p| p.status != Status::Same);
        if !changed {
            return Ok(false);
        }
        let kept: HashSet<&str> = parsed.vars.iter().map(|v| v.field.as_str()).collect();
        let gone: Vec<String> = entry
            .fields
            .keys()
            .filter(|f| !STANDARD.contains(&f.as_str()) && !kept.contains(f.as_str()))
            .cloned()
            .collect();
        let mut entry = self
            .db_mut()
            .entry_mut(*id)
            .ok_or(VaultError::EntryNotFound)?;
        let stamp = || CustomDataItem {
            value: None,
            last_modification_time: Some(Times::now()),
        };
        let text = |text: &str| CustomDataItem {
            value: Some(CustomDataValue::String(text.to_string())),
            ..stamp()
        };
        for field in &gone {
            entry.fields.remove(field);
        }
        // Kind and off marks are rebuilt below, so a field that changed role keeps neither.
        entry
            .custom_data
            .retain(|k, _| !k.starts_with(OFF_PREFIX) && !k.starts_with("sennel.kind:"));
        for var in &parsed.vars {
            entry.set_protected(&var.field, var.value.as_str());
            if var.disabled {
                entry
                    .custom_data
                    .insert(format!("{OFF_PREFIX}{}", var.field), text("1"));
            }
        }
        entry.custom_data.insert(TYPE_KEY.into(), text(TYPE_ENV));
        entry
            .custom_data
            .insert(LAYOUT_KEY.into(), text(&parsed.layout));
        entry.times.last_modification = Some(Times::now());
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(parsed: &Parsed) -> Vec<(&str, &str, &str, bool)> {
        parsed
            .vars
            .iter()
            .map(|v| {
                (
                    v.field.as_str(),
                    v.name.as_str(),
                    v.value.as_str(),
                    v.disabled,
                )
            })
            .collect()
    }

    const FILE: &str = "\
# Database

# Main Postgres, pooled
DATABASE_URL=postgres://u:p@db/app
REDIS_URL=redis://localhost  # local
# OLD_API_KEY=sk-123
export TOKEN='a b#c'
";

    #[test]
    fn a_file_reads_into_variables_labels_and_sections() {
        let parsed = parse(FILE);
        assert!(parsed.refused.is_empty());
        assert_eq!(
            names(&parsed),
            vec![
                (
                    "DATABASE_URL",
                    "DATABASE_URL",
                    "postgres://u:p@db/app",
                    false
                ),
                ("REDIS_URL", "REDIS_URL", "redis://localhost", false),
                ("OLD_API_KEY", "OLD_API_KEY", "sk-123", true),
                ("TOKEN", "TOKEN", "a b#c", false),
            ]
        );
        let rows = rows(
            &read_layout(&parsed.layout),
            |_| true,
            |f| f == "OLD_API_KEY",
        );
        let labels: Vec<_> = rows
            .iter()
            .map(|r| (r.label.as_deref(), r.section.as_deref()))
            .collect();
        assert_eq!(
            labels,
            vec![
                (Some("Main Postgres, pooled"), Some("Database")),
                (Some("local"), Some("Database")),
                (None, Some("Database")),
                (None, Some("Database")),
            ]
        );
        assert!(rows[2].disabled);
    }

    #[test]
    fn the_layout_holds_no_value_even_a_commented_out_one() {
        let parsed = parse(FILE);
        for secret in ["postgres://u:p", "redis://localhost", "sk-123", "a b#c"] {
            assert!(
                !parsed.layout.contains(secret),
                "{secret} leaked into the layout"
            );
        }
    }

    #[test]
    fn a_commented_out_variable_beside_a_live_one_moves_aside() {
        let parsed = parse("# KEY=prod\nKEY=local\n# KEY=staging\n");
        assert_eq!(
            names(&parsed),
            vec![
                ("KEY (off)", "KEY", "prod", true),
                ("KEY", "KEY", "local", false),
                ("KEY (off 2)", "KEY", "staging", true),
            ]
        );
    }

    #[test]
    fn hash_starts_a_comment_only_after_whitespace_or_outside_quotes() {
        let parsed = parse("A=a#b\nB=x # note\nC=\"q # not\"\nD= #empty\n");
        let values: Vec<_> = parsed.vars.iter().map(|v| v.value.as_str()).collect();
        assert_eq!(values, vec!["a#b", "x", "q # not", ""]);
    }

    #[test]
    fn quoted_values_may_span_lines_and_double_quotes_unescape() {
        let parsed = parse("KEY='-----BEGIN\nabc\n-----END'\nNEXT=\"a\\nb \\\"c\\\"\"\n");
        assert!(parsed.refused.is_empty());
        assert_eq!(parsed.vars[0].value.as_str(), "-----BEGIN\nabc\n-----END");
        assert_eq!(parsed.vars[1].value.as_str(), "a\nb \"c\"");
        assert_eq!(parsed.vars[1].line, 4);
    }

    #[test]
    fn bad_lines_are_refused_by_number_without_their_text() {
        let parsed = parse("sk-live-secret\nmy-var=1\nURL=x\nA=1\nA=2\nB='open\n");
        let refused: Vec<_> = parsed.refused.iter().map(|r| r.line).collect();
        assert_eq!(refused, vec![1, 2, 3, 5, 6]);
        assert!(parsed.refused.iter().all(|r| !r.why.contains("sk-live")));
        assert_eq!(parsed.vars.len(), 1);
    }

    #[test]
    fn crlf_and_a_byte_order_mark_are_read_through() {
        let parsed = parse("\u{feff}A=1\r\nB=2\r\n");
        assert_eq!(
            names(&parsed),
            vec![("A", "A", "1", false), ("B", "B", "2", false)]
        );
    }

    #[test]
    fn a_commented_out_multiline_value_stays_one_comment() {
        let line = render_var("K", "a\nb", false, true, "");
        assert_eq!(line.as_str(), "# K=\"a\\nb\"");
        let parsed = parse(&line);
        assert_eq!(names(&parsed), vec![("K", "K", "a\nb", true)]);
    }

    #[test]
    fn a_quote_never_closed_across_a_full_size_paste_is_quick_to_refuse() {
        let mut text = String::from("K=\"start\n");
        while text.len() < MAX_BYTES - 16 {
            text.push_str("more text on a line\n");
        }
        let start = std::time::Instant::now();
        let parsed = parse(&text);
        assert!(!parsed.refused.is_empty());
        // Rescanning the whole value per added line took seconds here.
        assert!(
            start.elapsed() < std::time::Duration::from_millis(500),
            "{:?}",
            start.elapsed()
        );
    }

    #[test]
    fn a_full_size_paste_parses_and_plans_in_one_pass() {
        let mut text = String::new();
        let mut n = 0;
        while text.len() < MAX_BYTES - 64 {
            text.push_str(&format!("# K{}=v\nK{n}=v\n", n % 7));
            n += 1;
        }
        let start = std::time::Instant::now();
        let parsed = parse(&text);
        let planned = plan(None, &parsed);
        assert!(parsed.refused.is_empty());
        assert_eq!(planned.len(), parsed.vars.len());
        // Loose enough for a debug build; a parse that scans the file per line takes far longer.
        assert!(
            start.elapsed() < std::time::Duration::from_secs(2),
            "{:?}",
            start.elapsed()
        );
        assert!(parsed.vars.iter().any(|v| v.field == "K3 (off 2)"));
    }

    #[test]
    fn a_multiline_quoted_value_keeps_the_spaces_ending_its_first_line() {
        let parsed = parse("KEY=\"abc   \ndef\"\n");
        assert_eq!(parsed.vars[0].value.as_str(), "abc   \ndef");
    }

    #[test]
    fn a_comment_shaped_like_an_assignment_is_kept_as_a_protected_variable() {
        let parsed = parse("# NOTE=see wiki\n");
        assert_eq!(names(&parsed), vec![("NOTE", "NOTE", "see wiki", true)]);
    }

    #[test]
    fn decorative_rules_label_nothing() {
        let parsed = parse("# -----\nA=1\n");
        let rows = rows(&read_layout(&parsed.layout), |_| true, |_| false);
        assert_eq!(rows[0].label, None);
    }

    #[test]
    fn quoting_picks_the_plainest_form_that_reads_back() {
        for value in ["plain", "", "a b", "it's", "x\ny", "$HOME \"q\" \\", "a#b"] {
            let line = render_var("K", value, false, false, "");
            let parsed = parse(&line);
            assert!(parsed.refused.is_empty(), "{value:?} -> {}", line.as_str());
            assert_eq!(
                parsed.vars[0].value.as_str(),
                value,
                "via {}",
                line.as_str()
            );
        }
    }

    fn vault_with_entry() -> (Vault, EntryId) {
        let mut vault = Vault::new();
        let root = vault.root_id();
        let id = vault
            .create_entry(&root, "Acme API", "", "", "", "")
            .unwrap();
        (vault, id)
    }

    #[test]
    fn a_written_entry_exports_the_same_file() {
        let (mut vault, id) = vault_with_entry();
        assert!(vault.write_env(&id, &parse(FILE)).unwrap());
        let entry = vault.get_entry(&id).unwrap();
        assert!(is_env(&entry));
        assert!(entry.fields["DATABASE_URL"].is_protected());
        assert!(is_off(&entry, "OLD_API_KEY"));
        let (text, skipped) = export(&vault, &entry);
        assert!(skipped.is_empty());
        assert_eq!(
            text.as_str(),
            "# Database\n\n# Main Postgres, pooled\nDATABASE_URL=postgres://u:p@db/app\n\
             REDIS_URL=redis://localhost # local\n# OLD_API_KEY=sk-123\nexport TOKEN='a b#c'\n"
        );
    }

    #[test]
    fn the_quick_count_agrees_with_the_rows() {
        let (mut vault, id) = vault_with_entry();
        vault.write_env(&id, &parse(FILE)).unwrap();
        // A field the layout never mentions, such as one added by hand in KeePassXC.
        vault.set_field(&id, "EXTRA", "x", true).unwrap();
        let entry = vault.get_entry(&id).unwrap();
        let rows = entry_rows(&entry);
        assert!(rows.iter().any(|r| r.disabled) && rows.iter().any(|r| r.field == "EXTRA"));
        assert_eq!(var_count(&entry), rows.len());
    }

    #[test]
    fn writing_again_removes_dropped_variables_and_reports_no_change_when_equal() {
        let (mut vault, id) = vault_with_entry();
        vault.write_env(&id, &parse("A=1\nB=2\n")).unwrap();
        assert!(!vault.write_env(&id, &parse("A=1\nB=2\n")).unwrap());
        let next = parse("A=1\n# B=2\nC=3\n");
        let entry = vault.get_entry(&id).unwrap();
        let statuses: Vec<_> = plan(Some(&entry), &next)
            .iter()
            .map(|p| (p.row.field.clone(), p.status))
            .collect();
        assert_eq!(
            statuses,
            vec![
                ("A".into(), Status::Same),
                ("B".into(), Status::Changed),
                ("C".into(), Status::New),
            ]
        );
        vault.write_env(&id, &parse("A=1\n")).unwrap();
        let entry = vault.get_entry(&id).unwrap();
        assert!(!entry.fields.contains_key("B"));
        assert!(!is_off(&entry, "B"));
    }

    #[test]
    fn a_login_with_its_own_fields_is_not_overwritten() {
        let (mut vault, id) = vault_with_entry();
        vault.set_field(&id, "Recovery", "code", true).unwrap();
        assert!(vault.write_env(&id, &parse("A=1\n")).is_err());
        let entry = vault.get_entry(&id).unwrap();
        assert!(entry.fields.contains_key("Recovery"));
    }

    #[test]
    fn a_paste_with_refused_lines_writes_nothing() {
        let (mut vault, id) = vault_with_entry();
        let err = vault
            .write_env(&id, &parse("A=1\nnot a line\n"))
            .unwrap_err();
        assert_eq!(err, VaultError::Db("line 2: not NAME=value".into()));
        assert!(!is_env(&vault.get_entry(&id).unwrap()));
    }

    #[test]
    fn fields_added_elsewhere_follow_the_layout_on_export() {
        let (mut vault, id) = vault_with_entry();
        vault.write_env(&id, &parse("A=1\n")).unwrap();
        vault.set_field(&id, "LATER", "2", true).unwrap();
        vault.set_field(&id, "Not a name", "3", true).unwrap();
        let entry = vault.get_entry(&id).unwrap();
        let (text, skipped) = export(&vault, &entry);
        assert_eq!(text.as_str(), "A=1\nLATER=2\n");
        assert_eq!(skipped, vec!["Not a name".to_string()]);
    }
}
