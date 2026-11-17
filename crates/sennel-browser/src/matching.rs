use keepass::db::{CustomDataValue, EntryRef};
use serde::Deserialize;
use url::Url;

// Where KeePassXC keeps an entry's remembered allow and deny answers, as JSON in its custom data.
const SETTINGS: &str = "KeePassXC-Browser Settings";
// KeePassXC's "Hide this entry from the browser extension", stored as the text `true`.
const HIDE: &str = "BrowserHideEntry";

/// The page a browser asks about, reduced to what decides a match.
#[derive(Debug, PartialEq, Eq)]
pub struct Page {
    scheme: String,
    host: String,
    port: Option<u16>,
}

impl Page {
    pub fn parse(text: &str) -> Option<Page> {
        let url = Url::parse(text).ok()?;
        let host = url.host_str()?.to_ascii_lowercase();
        if host.is_empty() {
            return None;
        }
        Some(Page {
            scheme: url.scheme().to_string(),
            host,
            port: url.port_or_known_default(),
        })
    }

    pub fn host(&self) -> &str {
        &self.host
    }
}

/// Whether one of the entry's URLs is for this page: the same host and port, and a scheme that
/// keeps a password for an https site off a plain http page.
pub fn entry_matches(entry: &EntryRef<'_>, page: &Page) -> bool {
    entry_urls(entry)
        .iter()
        .filter_map(|text| stored(text))
        .any(|stored| same_site(&stored, page))
}

// The URL field, then KeePassXC's extra URLs: fields named `KP2A_URL` or `KP2A_URL_<n>`.
fn entry_urls<'a>(entry: &'a EntryRef<'_>) -> Vec<&'a str> {
    let mut urls: Vec<&str> = entry.get_url().into_iter().collect();
    let mut extra: Vec<(&String, &str)> = entry
        .fields
        .iter()
        .filter(|(name, _)| *name == "KP2A_URL" || name.starts_with("KP2A_URL_"))
        .map(|(name, value)| (name, value.get().as_str()))
        .collect();
    extra.sort();
    urls.extend(extra.into_iter().map(|(_, value)| value));
    urls.retain(|u| !u.trim().is_empty());
    urls
}

// An entry URL saved without a scheme is read as https, so it never matches a plain http page.
fn stored(text: &str) -> Option<Page> {
    let text = text.trim();
    if text.contains("://") {
        Page::parse(text)
    } else {
        Page::parse(&format!("https://{text}"))
    }
}

fn same_site(entry: &Page, page: &Page) -> bool {
    let scheme = entry.scheme == page.scheme || (entry.scheme == "http" && page.scheme == "https");
    let port = entry.port == page.port
        // An http entry also covers its https upgrade, which moves the default port with it.
        || (entry.scheme == "http" && page.scheme == "https" && entry.port == Some(80) && page.port == Some(443));
    scheme && port && entry.host == page.host
}

#[derive(Deserialize, Default)]
struct Settings {
    #[serde(rename = "Allow", default)]
    allow: Vec<String>,
    #[serde(rename = "Deny", default)]
    deny: Vec<String>,
}

// keepass reads any value that decodes as base64 as `Binary`, `true` included, so it is turned back
// into the text it was stored as.
fn custom_text(entry: &EntryRef<'_>, key: &str) -> Option<String> {
    match entry.custom_data.get(key)?.value.as_ref()? {
        CustomDataValue::String(text) => Some(text.clone()),
        CustomDataValue::Binary(bytes) => Some(crate::crypto::encode(bytes)),
    }
}

pub fn hidden(entry: &EntryRef<'_>) -> bool {
    custom_text(entry, HIDE).is_some_and(|text| text.eq_ignore_ascii_case("true"))
}

fn settings(entry: &EntryRef<'_>) -> Settings {
    custom_text(entry, SETTINGS)
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

/// What the entry's remembered answers say about this host.
#[derive(Debug, PartialEq, Eq)]
pub enum Remembered {
    Allowed,
    Denied,
    Unknown,
}

// Deny wins, so an entry listed both ways stays closed.
pub fn remembered(entry: &EntryRef<'_>, page: &Page) -> Remembered {
    let settings = settings(entry);
    let listed = |hosts: &[String]| hosts.iter().any(|h| h.eq_ignore_ascii_case(&page.host));
    if listed(&settings.deny) {
        Remembered::Denied
    } else if listed(&settings.allow) {
        Remembered::Allowed
    } else {
        Remembered::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn site(entry: &str, page: &str) -> bool {
        same_site(&stored(entry).unwrap(), &Page::parse(page).unwrap())
    }

    #[test]
    fn the_same_host_matches_and_a_neighbour_does_not() {
        assert!(site(
            "https://bank.example",
            "https://bank.example/login?next=1"
        ));
        assert!(site("https://Bank.Example/", "https://bank.example/"));
        assert!(!site("https://bank.example", "https://www.bank.example/"));
        assert!(!site(
            "https://bank.example",
            "https://bank.example.evil.test/"
        ));
        assert!(!site("https://www.bank.example", "https://bank.example/"));
    }

    #[test]
    fn an_https_entry_never_fills_an_http_page() {
        assert!(!site("https://bank.example", "http://bank.example/"));
        assert!(!site("bank.example", "http://bank.example/"));
        assert!(site("http://bank.example", "https://bank.example/"));
        assert!(site("http://bank.example", "http://bank.example/"));
    }

    #[test]
    fn the_port_has_to_match() {
        assert!(!site("https://bank.example", "https://bank.example:8443/"));
        assert!(site(
            "https://bank.example:8443",
            "https://bank.example:8443/x"
        ));
        assert!(site("https://bank.example:443", "https://bank.example/"));
        assert!(!site("http://bank.example:8080", "https://bank.example/"));
    }

    #[test]
    fn a_page_without_a_host_matches_nothing() {
        assert_eq!(Page::parse("file:///etc/passwd"), None);
        assert_eq!(Page::parse("not a url"), None);
        assert!(stored("").is_none());
    }
}
