/* Checking passwords against Have I Been Pwned, without handing it one.

   The k-anonymity API takes the first five hex characters of a password's
   SHA-1 and answers with every suffix it knows beginning with them — around
   800 lines. The password never leaves the machine, and the service learns
   only that somebody asked about one of roughly half a million hashes.

   Two decisions worth stating, because both are unusual:

   SHA-1 is implemented here rather than pulled in. The algorithm is fixed,
   short and fully specified, it is used for exactly one thing, and a hash of
   the user's passwords is not a place to inherit somebody else's release
   cadence. It is also not being used as a security primitive — HIBP chose it,
   and its brokenness is irrelevant to a prefix lookup.

   The request goes through curl rather than through a Rust HTTP client. A TLS
   stack and an HTTP parser are a large amount of code to add to a password
   manager for one optional GET, and this way the exact command is something
   the user can read, run themselves, and see in `ps`. The cost is a
   dependency on curl being installed, which is named when it is missing. */

/// SHA-1 of a string, upper-case hex — the shape HIBP's API answers in.
pub fn sha1_hex(text: &str) -> String {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let mut message = text.as_bytes().to_vec();
    let bits = (message.len() as u64) * 8;
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bits.to_be_bytes());

    for chunk in message.chunks(64) {
        let mut w = [0u32; 80];
        for (at, word) in chunk.chunks(4).enumerate() {
            w[at] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for at in 16..80 {
            w[at] = (w[at - 3] ^ w[at - 8] ^ w[at - 14] ^ w[at - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (at, word) in w.iter().enumerate() {
            let (f, k) = match at {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let next = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = next;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    h.iter().map(|word| format!("{word:08X}")).collect()
}

/// What the range endpoint returns, parsed: the suffix and how many breaches
/// it has turned up in.
pub fn count_in(body: &str, suffix: &str) -> u64 {
    for line in body.lines() {
        let Some((found, count)) = line.trim().split_once(':') else {
            continue;
        };
        if found.eq_ignore_ascii_case(suffix) {
            /* Some responses carry thousands separators; anything that is not
               a digit is not part of the number. */
            let digits: String = count.chars().filter(|c| c.is_ascii_digit()).collect();
            return digits.parse().unwrap_or(0);
        }
    }
    0
}

/// The five characters that leave this machine, and the rest that never do.
pub fn split_hash(password: &str) -> (String, String) {
    let hash = sha1_hex(password);
    let (prefix, suffix) = hash.split_at(5);
    (prefix.to_string(), suffix.to_string())
}

/* One range request. Separated from the lookup so the network is one small
   function: everything above it is arithmetic and everything below is the
   caller's own reporting. */
pub fn fetch_range(prefix: &str) -> Result<String, String> {
    /* The prefix is five hex characters we produced, never user input, but
       it is still going into a URL — so it is checked rather than trusted. */
    if prefix.len() != 5 || !prefix.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("bad prefix".into());
    }
    let url = format!("https://api.pwnedpasswords.com/range/{prefix}");
    let out = std::process::Command::new("curl")
        .args(["--silent", "--show-error", "--fail", "--max-time", "20", &url])
        .output()
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => {
                "curl is not installed · --pwned needs it to reach the api".to_string()
            }
            _ => format!("cannot run curl · {e}"),
        })?;
    if !out.status.success() {
        let why = String::from_utf8_lossy(&out.stderr);
        return Err(format!("the api call failed · {}", why.trim()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /* Known vectors, because a hash implementation that is subtly wrong finds
       nothing and looks exactly like a clean vault. */
    #[test]
    fn the_hash_matches_the_published_vectors() {
        assert_eq!(sha1_hex(""), "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709");
        assert_eq!(sha1_hex("abc"), "A9993E364706816ABA3E25717850C26C9CD0D89D");
        assert_eq!(
            sha1_hex("The quick brown fox jumps over the lazy dog"),
            "2FD4E1C67A2D28FCED849EE1BB76E7391B93EB12"
        );
        /* HIBP's own example, and the one that matters: this is the hash the
           service answers for. */
        assert_eq!(sha1_hex("password"), "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8");
        /* The lengths where padding decides how many blocks there are: 55
           fits with its length word, 56 needs a second block, 64 is exactly
           one block, and 119/120 do the same one block further along.
           Computed with a separate implementation, not read back out of this
           one — a test that asserts whatever the code does proves nothing. */
        assert_eq!(sha1_hex(&"a".repeat(55)), "C1C8BBDC22796E28C0E15163D20899B65621D65A");
        assert_eq!(sha1_hex(&"a".repeat(56)), "C2DB330F6083854C99D4B5BFB6E8F29F201BE699");
        assert_eq!(sha1_hex(&"a".repeat(64)), "0098BA824B5C16427BD7A1122A5A442A25EC644D");
        assert_eq!(sha1_hex(&"a".repeat(119)), "EE971065AAA017E0632A8CA6C77BB3BF8B1DFC56");
        assert_eq!(sha1_hex(&"a".repeat(120)), "F34C1488385346A55709BA056DDD08280DD4C6D6");
        // Multi-byte input is hashed as its utf-8 bytes, not its chars.
        assert_eq!(sha1_hex("héllo"), sha1_hex(std::str::from_utf8(&[104, 195, 169, 108, 108, 111]).unwrap()));
    }

    /* Five characters leave, thirty-five do not. This is the whole privacy
       claim, so it gets a test rather than a comment. */
    #[test]
    fn only_the_first_five_characters_ever_leave() {
        let (prefix, suffix) = split_hash("password");
        assert_eq!(prefix, "5BAA6");
        assert_eq!(suffix, "1E4C9B93F3F0682250B6CF8331B7EE68FD8");
        assert_eq!(prefix.len(), 5);
        assert_eq!(prefix.len() + suffix.len(), 40);
        // The password itself appears nowhere in what is sent.
        assert!(!prefix.contains("pass"));
    }

    /* The response is a suffix:count list. A miss has to read as zero, not as
       an error, or a clean password looks like a failed check. */
    #[test]
    fn the_response_is_matched_by_suffix() {
        let body = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:9659364\r\n\
                    0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n";
        assert_eq!(count_in(body, "1E4C9B93F3F0682250B6CF8331B7EE68FD8"), 9659364);
        // Case-insensitive: the api answers upper, nothing says it must.
        assert_eq!(count_in(body, "1e4c9b93f3f0682250b6cf8331b7ee68fd8"), 9659364);
        assert_eq!(count_in(body, "0018A45C4D1DEF81644B54AB7F969B88D65"), 1);
        assert_eq!(count_in(body, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"), 0);
        assert_eq!(count_in("", "anything"), 0);
    }

    /* The prefix is ours, not the user's, but it still goes into a url. */
    #[test]
    fn a_prefix_that_is_not_five_hex_characters_never_reaches_the_network() {
        assert!(fetch_range("../../etc").is_err());
        assert!(fetch_range("5BAA").is_err());
        assert!(fetch_range("ZZZZZ").is_err());
    }
}
