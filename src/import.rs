/* Reading somebody else's export. Migration is when people try a new password
   manager, so the bar is: point it at whatever your old tool gave you and
   have it work, or say exactly which column it could not find.

   One reader, not three. KeePassXC, Bitwarden and 1Password all export CSV
   with a header row and different names for the same six things, so the
   mapping is by header rather than by format — which means a tool nobody
   here has heard of also works if it names its columns like everyone else.

   The CSV parser is here rather than a dependency because RFC 4180 is small
   and the alternative is pulling a crate into a password manager to read
   about sixty lines' worth of quoting rules. */

/// One row of an export, in Sennel's terms.
#[derive(Debug, PartialEq, Default)]
pub struct Row {
    pub group: String,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    /// An `otpauth://` url or a bare seed; the vault decides which.
    pub otp: String,
}

/// What a header column is, whatever the exporting tool called it.
fn column(name: &str) -> Option<&'static str> {
    /* Lower-cased and stripped of the punctuation exporters sprinkle in, so
       "Login Name", "login_name" and "login-name" are one column. */
    let key: String = name
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    Some(match key.as_str() {
        "group" | "folder" | "grouping" | "category" => "group",
        "title" | "name" | "account" | "itemname" => "title",
        "username" | "loginusername" | "user" | "loginname" | "email" => "username",
        "password" | "loginpassword" | "loginpwd" => "password",
        "url" | "loginuri" | "website" | "urls" | "loginurl" => "url",
        "notes" | "note" | "comments" => "notes",
        "totp" | "logintotp" | "otpauth" | "otp" | "onetimepassword" => "otp",
        _ => return None,
    })
}

/// What the file gave us, and what it could not.
#[derive(Debug, PartialEq)]
pub struct Import {
    pub rows: Vec<Row>,
    /// Header columns nothing was done with, named so the user can see what
    /// was dropped rather than discovering it later.
    pub ignored: Vec<String>,
}

/* A title is the one column with no sensible default: an entry called "" is
   an entry nobody can find again. Everything else may be absent. */
pub fn read_csv(text: &str) -> Result<Import, String> {
    let mut records = parse(text).into_iter();
    let Some(header) = records.next() else {
        return Err("the file is empty".into());
    };
    let map: Vec<Option<&'static str>> = header.iter().map(|h| column(h)).collect();
    if !map.contains(&Some("title")) {
        return Err(format!(
            "no title column · the header is: {}",
            header.join(", ")
        ));
    }
    let ignored: Vec<String> = header
        .iter()
        .zip(&map)
        .filter(|(_, c)| c.is_none())
        .map(|(name, _)| name.clone())
        .filter(|name| !name.trim().is_empty())
        .collect();

    let mut rows = Vec::new();
    for record in records {
        // A trailing newline gives one empty record; it is not an entry.
        if record.iter().all(|f| f.trim().is_empty()) {
            continue;
        }
        let mut row = Row::default();
        for (at, field) in record.into_iter().enumerate() {
            let Some(Some(into)) = map.get(at) else {
                continue;
            };
            let slot = match *into {
                "group" => &mut row.group,
                "title" => &mut row.title,
                "username" => &mut row.username,
                "password" => &mut row.password,
                "url" => &mut row.url,
                "notes" => &mut row.notes,
                "otp" => &mut row.otp,
                _ => continue,
            };
            /* First one wins: 1Password writes several url columns, and the
               first is the one the item is actually for. */
            if slot.is_empty() {
                *slot = field;
            }
        }
        if row.title.trim().is_empty() {
            row.title = "untitled".into();
        }
        rows.push(row);
    }
    Ok(Import { rows, ignored })
}

/* RFC 4180: fields split on commas, quotes protect commas and newlines, and
   a doubled quote inside a quoted field is one quote. Anything else is taken
   literally rather than refused — an export with a stray quote in a notes
   field should still import. */
fn parse(text: &str) -> Vec<Vec<String>> {
    let mut records = Vec::new();
    let mut record = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted => {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    field.push('"');
                } else {
                    quoted = false;
                }
            }
            '"' if field.is_empty() => quoted = true,
            ',' if !quoted => record.push(std::mem::take(&mut field)),
            '\r' if !quoted => {}
            '\n' if !quoted => {
                record.push(std::mem::take(&mut field));
                records.push(std::mem::take(&mut record));
            }
            _ => field.push(c),
        }
    }
    // A file with no trailing newline still ends in a record.
    if !field.is_empty() || !record.is_empty() {
        record.push(field);
        records.push(record);
    }
    records
}

/* The rows into a vault, under one new group. Split from the command so the
   shape of what lands can be tested without a file, a password prompt or a
   process: the CLI wrapper is then only "read the file, open the vault, call
   this, save".

   One new group rather than merged into the tree the file describes, because
   an import is the operation most likely to be regretted and one group is one
   thing to delete when it is. The file's own group column becomes a subgroup,
   so the shape survives without colonising the vault. */
pub fn into_vault(
    vault: &mut crate::vault::Vault,
    rows: &[Row],
    into: &str,
) -> Result<(usize, Vec<String>), String> {
    let root = vault.root_id();
    let top = vault.create_group(&root, into).map_err(|e| e.to_string())?;
    let mut made: std::collections::HashMap<String, keepass::db::GroupId> =
        std::collections::HashMap::new();
    let mut added = 0usize;
    let mut skipped = Vec::new();
    for row in rows {
        let parent = match row.group.trim() {
            "" => top,
            name => match made.get(name) {
                Some(id) => *id,
                None => {
                    let id = vault.create_group(&top, name).map_err(|e| e.to_string())?;
                    made.insert(name.to_string(), id);
                    id
                }
            },
        };
        let id = vault
            .create_entry(&parent, &row.title, &row.username, &row.password, &row.url, &row.notes)
            .map_err(|e| e.to_string())?;
        /* A seed that will not parse is not worth failing a whole import
           over: the entry lands without a code and the caller names it. */
        if !row.otp.trim().is_empty() {
            match crate::vault::totp_url(&row.otp, &row.title, &row.username) {
                Ok(url) => {
                    let _ = vault.set_otp(&id, Some(&url));
                }
                Err(why) => skipped.push(format!("{}: no one-time code · {why}", row.title)),
            }
        }
        added += 1;
    }
    Ok((added, skipped))
}

#[cfg(test)]
mod tests {
    use super::*;

    /* The three exporters people actually arrive from, each naming the same
       six things differently. One reader has to answer all of them. */
    #[test]
    fn the_headers_every_exporter_writes_map_onto_the_same_fields() {
        // KeePassXC.
        let xc = read_csv(
            "\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\",\"TOTP\"\n\
             \"Root/Bank\",\"checking\",\"octo\",\"pw\",\"https://b.example\",\"note\",\"otpauth://x\"\n",
        )
        .unwrap();
        assert_eq!(
            xc.rows[0],
            Row {
                group: "Root/Bank".into(),
                title: "checking".into(),
                username: "octo".into(),
                password: "pw".into(),
                url: "https://b.example".into(),
                notes: "note".into(),
                otp: "otpauth://x".into(),
            }
        );

        // Bitwarden, which calls them something else entirely.
        let bw = read_csv(
            "folder,favorite,type,name,notes,fields,login_uri,login_username,login_password,login_totp\n\
             Work,,login,jira,a note,,https://j.example,octo,pw,SEED\n",
        )
        .unwrap();
        assert_eq!(bw.rows[0].group, "Work");
        assert_eq!(bw.rows[0].title, "jira");
        assert_eq!(bw.rows[0].username, "octo");
        assert_eq!(bw.rows[0].url, "https://j.example");
        assert_eq!(bw.rows[0].otp, "SEED");
        /* Columns nothing was done with are named rather than dropped in
           silence: the user can then decide whether they mattered. */
        assert!(bw.ignored.contains(&"favorite".to_string()), "{:?}", bw.ignored);
        assert!(bw.ignored.contains(&"type".to_string()));

        // 1Password's spelling, where several url columns are normal.
        let op = read_csv("Title,Url,Username,Password,Notes\nmail,https://m.example,octo,pw,\n")
            .unwrap();
        assert_eq!(op.rows[0].title, "mail");
        assert_eq!(op.rows[0].url, "https://m.example");
        assert!(op.rows[0].notes.is_empty());
    }

    /* Quoting is the whole reason this is not a `split(',')`: a notes field
       with a comma, a newline or a quote in it is ordinary. */
    #[test]
    fn quoted_fields_survive_commas_newlines_and_quotes() {
        let got = read_csv(
            "Title,Notes\n\
             \"a,b\",\"line one\nline two\"\n\
             plain,\"he said \"\"hi\"\"\"\n",
        )
        .unwrap();
        assert_eq!(got.rows[0].title, "a,b");
        assert_eq!(got.rows[0].notes, "line one\nline two");
        assert_eq!(got.rows[1].notes, "he said \"hi\"");
    }

    /* The shape that lands in the vault: one new group, the file's own groups
       as subgroups under it, and nothing touching the tree that was there. */
    #[test]
    fn an_import_lands_under_one_new_group() {
        let mut vault = crate::vault::Vault::new();
        let root = vault.root_id();
        vault.create_group(&root, "Existing").unwrap();
        vault.create_entry(&root, "mine", "u", "p", "", "").unwrap();

        let found = read_csv(
            "folder,name,login_username,login_password,login_totp\n             Work,jira,octo,pw,JBSWY3DPEHPK3PXP\n             Work,confluence,octo,pw2,\n             ,mail,octo,pw3,\n             ,broken-seed,octo,pw4,not-base32!!\n",
        )
        .unwrap();
        let (added, skipped) = into_vault(&mut vault, &found.rows, "Imported").unwrap();
        assert_eq!(added, 4);

        /* A seed that will not parse costs its own entry a code and nothing
           else: failing the whole import over one bad column would strand
           somebody mid-migration. */
        assert_eq!(skipped.len(), 1, "{skipped:?}");
        assert!(skipped[0].contains("broken-seed"), "{skipped:?}");

        // One new group at the root, beside what was already there.
        let top: Vec<String> = vault.groups_in(&root).iter().map(|g| g.name.clone()).collect();
        assert_eq!(top, vec!["Existing", "Imported"]);
        let imported = vault.groups_in(&root)[1].id();

        // The file's own group becomes a subgroup, made once for two rows.
        let under: Vec<String> = vault.groups_in(&imported).iter().map(|g| g.name.clone()).collect();
        assert_eq!(under, vec!["Work"]);
        let work = vault.groups_in(&imported)[0].id();
        assert_eq!(vault.entries_in(&work).len(), 2);
        // Rows with no group sit directly under the new one.
        assert_eq!(vault.entries_in(&imported).len(), 2);
        // And the entry that was there before is untouched.
        assert_eq!(vault.entries_in(&root).len(), 1);

        /* The values land where they belong, and a bare seed is wrapped into
           the otpauth url KDBX stores. */
        let jira = vault.entries_in(&work)[0].id();
        let entry = vault.get_entry(&jira).unwrap();
        use crate::vault::EntryExt;
        assert_eq!(entry.title(), "jira");
        assert_eq!(entry.password(), "pw");
        assert!(crate::vault::totp_now(&entry).is_some(), "the seed did not become a code");
    }

    /* A file with no title column cannot be imported into anything useful,
       and the message has to name what it did find. */
    #[test]
    fn a_file_without_a_title_column_says_what_it_found_instead() {
        let err = read_csv("user,pass\nocto,pw\n").unwrap_err();
        assert!(err.contains("no title column"), "{err}");
        assert!(err.contains("user"), "{err}");
        assert!(read_csv("").unwrap_err().contains("empty"));

        // A row with an empty title still imports, under a name that says so.
        let got = read_csv("Title,Password\n,pw\n").unwrap();
        assert_eq!(got.rows[0].title, "untitled");
        // A trailing newline is not an entry.
        assert_eq!(read_csv("Title\nmail\n").unwrap().rows.len(), 1);
    }
}
