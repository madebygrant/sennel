// `sennel export`: every live entry as plaintext CSV or JSON. The inverse of `import`, and just as
// dangerous: the output holds every password. It is built straight into one buffer that is wiped on
// drop, with no per-field copies, and the caller decides where it may go.

use zeroize::Zeroizing;

use crate::vault::{EntryExt, Extra, Vault, extra_rows, raw_otp};

/// What `export` writes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum ExportFormat {
    Csv,
    Json,
}

pub struct Exported {
    pub text: Zeroizing<String>,
    pub entries: usize,
    /// Custom fields and attachments the chosen format has no room for.
    pub left_out_fields: usize,
    pub left_out_files: usize,
}

struct Row<'a> {
    group: String,
    entry: keepass::db::EntryRef<'a>,
}

/// The entries under `group` (a `/` path, root left out), or all of them. Binned entries are never exported.
pub fn render(
    vault: &Vault,
    format: ExportFormat,
    group: Option<&str>,
) -> Result<Exported, String> {
    let wanted = group
        .map(|g| g.trim_matches('/').to_lowercase())
        .filter(|g| !g.is_empty());
    let mut rows: Vec<Row<'_>> = vault
        .entry_refs()
        .into_iter()
        .filter_map(|entry| {
            let parent = vault.parent_group_of_entry(&entry.id())?;
            // The root group's own name is the vault's, not part of anyone's path.
            let path = vault
                .group_path(&parent)
                .into_iter()
                .skip(1)
                .collect::<Vec<_>>()
                .join("/");
            Some(Row { group: path, entry })
        })
        .filter(|row| match &wanted {
            None => true,
            Some(want) => {
                let have = row.group.to_lowercase();
                have == *want || have.starts_with(&format!("{want}/"))
            }
        })
        .collect();
    if rows.is_empty() {
        return Err(match group {
            Some(g) => format!("no entries under {g:?}"),
            None => "the vault has no entries to export".to_string(),
        });
    }
    rows.sort_by_key(|r| (r.group.to_lowercase(), r.entry.title().to_lowercase()));

    let mut out = Zeroizing::new(String::new());
    let (mut fields, mut files) = (0, 0);
    match format {
        ExportFormat::Csv => {
            out.push_str("Group,Title,Username,Password,URL,Notes,TOTP\n");
            for row in &rows {
                let e = &row.entry;
                let otp = Zeroizing::new(raw_otp(e).unwrap_or_default());
                for (i, cell) in [
                    row.group.as_str(),
                    e.title(),
                    e.username(),
                    e.password(),
                    e.url(),
                    e.notes(),
                    otp.as_str(),
                ]
                .into_iter()
                .enumerate()
                {
                    if i > 0 {
                        out.push(',');
                    }
                    push_csv(&mut out, cell);
                }
                out.push('\n');
                for extra in extra_rows(e) {
                    match extra {
                        Extra::Field { .. } => fields += 1,
                        Extra::File { .. } => files += 1,
                    }
                }
            }
        }
        ExportFormat::Json => {
            out.push_str(
                "{\n  \"format\": \"sennel-export\",\n  \"version\": 1,\n  \"entries\": [\n",
            );
            for (i, row) in rows.iter().enumerate() {
                let e = &row.entry;
                out.push_str(if i == 0 { "    {" } else { ",\n    {" });
                let otp = raw_otp(e).map(Zeroizing::new);
                let mut first = true;
                let mut key = |out: &mut String, name: &str| {
                    out.push_str(if first { "\n      " } else { ",\n      " });
                    first = false;
                    push_json(out, name);
                    out.push_str(": ");
                };
                for (name, value) in [
                    ("group", row.group.as_str()),
                    ("title", e.title()),
                    ("username", e.username()),
                    ("password", e.password()),
                    ("url", e.url()),
                    ("notes", e.notes()),
                ] {
                    key(&mut out, name);
                    push_json(&mut out, value);
                }
                key(&mut out, "totp");
                match &otp {
                    Some(url) => push_json(&mut out, url.as_str()),
                    None => out.push_str("null"),
                }
                key(&mut out, "tags");
                out.push('[');
                for (n, tag) in e.tags.iter().enumerate() {
                    if n > 0 {
                        out.push_str(", ");
                    }
                    push_json(&mut out, tag);
                }
                out.push(']');
                key(&mut out, "expires");
                match (e.times.expires, e.times.expiry) {
                    (Some(true), Some(at)) => {
                        push_json(&mut out, &at.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                    }
                    _ => out.push_str("null"),
                }
                let extras = extra_rows(e);
                key(&mut out, "fields");
                out.push('[');
                let mut wrote = false;
                for extra in &extras {
                    if let Extra::Field { name, value, .. } = extra {
                        out.push_str(if wrote {
                            ", {\"name\": "
                        } else {
                            "{\"name\": "
                        });
                        wrote = true;
                        push_json(&mut out, name);
                        out.push_str(", \"value\": ");
                        push_json(&mut out, value);
                        out.push('}');
                    }
                }
                out.push(']');
                key(&mut out, "files");
                out.push('[');
                let mut wrote = false;
                for extra in &extras {
                    if let Extra::File { name, .. } = extra {
                        if wrote {
                            out.push_str(", ");
                        }
                        wrote = true;
                        push_json(&mut out, name);
                        files += 1;
                    }
                }
                out.push(']');
                out.push_str("\n    }");
            }
            out.push_str("\n  ]\n}\n");
        }
    }
    Ok(Exported {
        text: out,
        entries: rows.len(),
        left_out_fields: fields,
        left_out_files: files,
    })
}

// RFC 4180: quoted only when it has to be, so `import` and every spreadsheet read it back unchanged.
fn push_csv(out: &mut String, cell: &str) {
    if !cell.contains([',', '"', '\n', '\r']) {
        out.push_str(cell);
        return;
    }
    out.push('"');
    for c in cell.chars() {
        if c == '"' {
            out.push('"');
        }
        out.push(c);
    }
    out.push('"');
}

fn push_json(out: &mut String, text: &str) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::import;

    fn sample() -> Vault {
        let mut v = Vault::new();
        let root = v.root_id();
        let banks = v.create_group(&root, "Banks").unwrap();
        let savings = v.create_group(&banks, "Savings").unwrap();
        v.create_entry(&root, "top", "u0", "p0", "", "").unwrap();
        let a = v
            .create_entry(
                &banks,
                "check,ing",
                "oc\"to",
                "pa,ss\"word",
                "https://x",
                "line one\nline two",
            )
            .unwrap();
        v.set_otp(
            &a,
            Some("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=6"),
        )
        .unwrap();
        v.set_field(&a, "pin", "1234", true).unwrap();
        v.add_attachment(&a, "scan.png", b"png".to_vec()).unwrap();
        v.create_entry(&savings, "rainy day", "me", "s3cret", "", "")
            .unwrap();
        let gone = v.create_entry(&root, "binned", "", "", "", "").unwrap();
        v.recycle_entry(&gone).unwrap();
        v
    }

    #[test]
    fn csv_reads_back_through_import_with_nothing_lost() {
        let out = render(&sample(), ExportFormat::Csv, None).unwrap();
        assert_eq!(out.entries, 3, "the binned entry was exported");
        let found = import::read_csv(&out.text).unwrap();
        let by_title = |t: &str| found.rows.iter().find(|r| r.title == t).unwrap();

        let a = by_title("check,ing");
        assert_eq!((a.group.as_str(), a.username.as_str()), ("Banks", "oc\"to"));
        assert_eq!(
            (a.password.as_str(), a.url.as_str()),
            ("pa,ss\"word", "https://x")
        );
        assert_eq!(a.notes, "line one\nline two");
        assert!(a.otp.contains("secret=JBSWY3DPEHPK3PXP"), "{}", a.otp);
        assert_eq!(by_title("rainy day").group, "Banks/Savings");
        assert_eq!(
            by_title("top").group,
            "",
            "the root's own name leaked into the path"
        );
        assert_eq!((out.left_out_fields, out.left_out_files), (1, 1));

        // And into a fresh vault, where the tree comes back nested.
        let mut fresh = Vault::new();
        import::into_vault(&mut fresh, &found.rows, "Imported").unwrap();
        assert_eq!(fresh.entry_count(), 3);
    }

    #[test]
    fn a_group_filter_takes_that_group_and_below() {
        let all = sample();
        let some = render(&all, ExportFormat::Csv, Some("banks")).unwrap();
        assert_eq!(some.entries, 2);
        assert_eq!(
            render(&all, ExportFormat::Csv, Some("Banks/Savings"))
                .unwrap()
                .entries,
            1
        );
        assert!(
            render(&all, ExportFormat::Csv, Some("Bank")).is_err(),
            "a prefix is not a group"
        );
        assert!(render(&Vault::new(), ExportFormat::Csv, None).is_err());
    }

    #[test]
    fn json_is_valid_and_carries_fields_tags_and_file_names() {
        let out = render(&sample(), ExportFormat::Json, Some("Banks")).unwrap();
        let text: &str = &out.text;
        assert!(
            text.starts_with("{\n  \"format\": \"sennel-export\""),
            "{text}"
        );
        assert!(
            text.contains(r#""title": "check,ing""#)
                && text.contains(r#""password": "pa,ss\"word""#)
        );
        assert!(text.contains(r#""notes": "line one\nline two""#), "{text}");
        assert!(
            text.contains(r#"{"name": "pin", "value": "1234"}"#),
            "{text}"
        );
        assert!(text.contains(r#""files": ["scan.png"]"#), "{text}");
        assert!(text.contains(r#""totp": null"#), "the entry with no code");
        // Balanced, and every string closed: a cheap structural check without a parser.
        assert_eq!(text.matches('{').count(), text.matches('}').count());
        assert_eq!(text.matches('[').count(), text.matches(']').count());
        assert_eq!(out.left_out_fields, 0, "json has room for fields");
    }

    #[test]
    fn json_escapes_what_would_break_it() {
        let mut out = String::new();
        push_json(&mut out, "a\"b\\c\n\t\u{1}é");
        assert_eq!(out, "\"a\\\"b\\\\c\\n\\t\\u0001é\"");
    }
}
