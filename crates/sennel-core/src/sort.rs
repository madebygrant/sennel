/* How the entries pane orders itself. `Stored` is the file's own order; the
rest are views over it — the vault vec is never re-ordered, so `o` cycling
back always lands exactly where the file left things. Session-only for
now: config has no write-back, so the choice does not survive a restart. */
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum SortOrder {
    #[default]
    Stored,
    Name,
    Recent,
    Updated,
}

impl SortOrder {
    pub fn next(self) -> Self {
        match self {
            SortOrder::Stored => SortOrder::Name,
            SortOrder::Name => SortOrder::Recent,
            SortOrder::Recent => SortOrder::Updated,
            SortOrder::Updated => SortOrder::Stored,
        }
    }

    /// The config file's name for it, and back. One spelling in `config.toml`
    /// and in the flash would be nicer, but "by name" is prose, not a key.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "stored" => Some(SortOrder::Stored),
            "name" => Some(SortOrder::Name),
            "recent" => Some(SortOrder::Recent),
            "updated" => Some(SortOrder::Updated),
            _ => None,
        }
    }

    /// A config or flag value, with the message both apps give for a name nobody knows.
    pub fn parse(name: &str) -> Result<Self, String> {
        Self::from_name(name)
            .ok_or_else(|| format!("unknown sort {name:?} · stored, name, recent or updated"))
    }

    /// One word for the pane header, where "by name" would read as part of
    /// the breadcrumb beside it.
    pub fn short(self) -> &'static str {
        match self {
            SortOrder::Stored => "stored",
            SortOrder::Name => "name",
            SortOrder::Recent => "recent",
            SortOrder::Updated => "updated",
        }
    }

    /// What the status flash calls it.
    pub fn label(self) -> &'static str {
        match self {
            SortOrder::Stored => "stored order",
            SortOrder::Name => "by name",
            SortOrder::Recent => "by recent",
            SortOrder::Updated => "by updated",
        }
    }
}
