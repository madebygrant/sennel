// Google Authenticator's "export accounts" link: otpauth-migration://offline?data=<base64 protobuf>.
// Read by hand because the format is five fields, and a crate for it would be bigger than this file.

use zeroize::Zeroizing;

/// The one account in an export link, as an `otpauth://totp/...` URL. `rest` is what follows
/// `otpauth-migration://`. Exports holding several accounts are refused, since an entry holds one seed.
pub fn account(rest: &str) -> Result<Zeroizing<String>, String> {
    let payload = payload(rest)?;
    let fields = walk(&payload).ok_or("the export link is damaged")?;
    let accounts: Vec<&[u8]> = fields
        .iter()
        .filter_map(|(number, value)| match (number, value) {
            (1, Wire::Bytes(bytes)) => Some(*bytes),
            _ => None,
        })
        .collect();
    match accounts.as_slice() {
        [] => Err("no account in the export link".to_string()),
        [one] => url(one),
        many => Err(format!(
            "that export holds {} accounts · export them one at a time, since an entry holds one code",
            many.len()
        )),
    }
}

fn payload(rest: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let query = rest.split_once('?').map_or("", |(_, q)| q);
    let data = query
        .split('&')
        .find_map(|pair| pair.strip_prefix("data="))
        .ok_or("the export link has no data= part")?;
    let text = Zeroizing::new(percent_decode(data).ok_or("the export link is damaged")?);
    base64_decode(&text).ok_or_else(|| "the export link is not base64".to_string())
}

fn url(account: &[u8]) -> Result<Zeroizing<String>, String> {
    let fields = walk(account).ok_or("the account in the export link is damaged")?;
    let (mut secret, mut name, mut issuer) = (&[][..], &[][..], &[][..]);
    let (mut algorithm, mut digits, mut kind) = (0, 0, 0);
    for (number, value) in &fields {
        match (number, value) {
            (1, Wire::Bytes(b)) => secret = b,
            (2, Wire::Bytes(b)) => name = b,
            (3, Wire::Bytes(b)) => issuer = b,
            (4, Wire::Varint(v)) => algorithm = *v,
            (5, Wire::Varint(v)) => digits = *v,
            (6, Wire::Varint(v)) => kind = *v,
            _ => {}
        }
    }
    if secret.is_empty() {
        return Err("the account in the export link has no secret".to_string());
    }
    if kind == 1 {
        return Err(
            "only time-based codes (totp) are supported, and this one counts uses".to_string(),
        );
    }
    let algorithm = match algorithm {
        0 | 1 => "SHA1",
        2 => "SHA256",
        3 => "SHA512",
        _ => return Err("this account uses MD5 codes, which are not supported".to_string()),
    };
    let digits = if digits == 2 { 8 } else { 6 };
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    let (name, issuer) = (text(name), text(issuer));
    let label = if issuer.is_empty() || name.starts_with(&format!("{issuer}:")) {
        name.clone()
    } else {
        format!("{issuer}:{name}")
    };
    let mut out = format!(
        "otpauth://totp/{}?secret={}&algorithm={algorithm}&digits={digits}&period=30",
        crate::vault::urlish(&label),
        *base32(secret)
    );
    if !issuer.is_empty() {
        out.push_str(&format!("&issuer={}", crate::vault::urlish(&issuer)));
    }
    Ok(Zeroizing::new(out))
}

enum Wire<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
}

// The fields of one protobuf message, as (number, value). Fixed-width fields are skipped.
fn walk(mut buf: &[u8]) -> Option<Vec<(u64, Wire<'_>)>> {
    let mut out = Vec::new();
    while !buf.is_empty() {
        let tag = varint(&mut buf)?;
        match tag & 7 {
            0 => out.push((tag >> 3, Wire::Varint(varint(&mut buf)?))),
            2 => {
                let len = usize::try_from(varint(&mut buf)?).ok()?;
                let (bytes, rest) = buf.split_at_checked(len)?;
                out.push((tag >> 3, Wire::Bytes(bytes)));
                buf = rest;
            }
            1 => buf = buf.get(8..)?,
            5 => buf = buf.get(4..)?,
            _ => return None,
        }
    }
    Some(out)
}

fn varint(buf: &mut &[u8]) -> Option<u64> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let (&byte, rest) = buf.split_first()?;
        *buf = rest;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

fn percent_decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let pair = text.get(i + 1..i + 3)?;
                out.push(u8::from_str_radix(pair, 16).ok()?);
                i += 3;
            }
            // Some apps leave the base64 `+` bare, and a bare `+` in a query reads as a space.
            b'+' | b' ' => {
                out.push(b'+');
                i += 1;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    Some(out)
}

// Standard or URL-safe alphabet, padding optional.
fn base64_decode(text: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(text.len() * 3 / 4));
    let (mut acc, mut bits) = (0u32, 0);
    for &c in text.iter().take_while(|c| **c != b'=') {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'\r' | b'\n' => continue,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

// RFC 4648 base32 without padding, which is how authenticator apps print a secret.
fn base32(bytes: &[u8]) -> Zeroizing<String> {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = Zeroizing::new(String::with_capacity(bytes.len() * 8 / 5 + 1));
    let (mut acc, mut bits) = (0u32, 0);
    for &byte in bytes {
        acc = (acc << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(ALPHABET[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes_field(number: u8, bytes: &[u8]) -> Vec<u8> {
        let mut out = vec![number << 3 | 2, bytes.len() as u8];
        out.extend_from_slice(bytes);
        out
    }

    fn varint_field(number: u8, value: u8) -> Vec<u8> {
        vec![number << 3, value]
    }

    fn account_bytes(name: &str, issuer: &str, algorithm: u8, digits: u8, kind: u8) -> Vec<u8> {
        [
            bytes_field(1, b"Hello!\xde\xad\xbe\xef"),
            bytes_field(2, name.as_bytes()),
            bytes_field(3, issuer.as_bytes()),
            varint_field(4, algorithm),
            varint_field(5, digits),
            varint_field(6, kind),
        ]
        .concat()
    }

    fn link(accounts: &[Vec<u8>]) -> String {
        let mut payload: Vec<u8> = accounts.iter().flat_map(|a| bytes_field(1, a)).collect();
        payload.extend(varint_field(2, 1)); // version, which is skipped
        const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut text = String::new();
        for chunk in payload.chunks(3) {
            let n =
                chunk.iter().fold(0u32, |n, b| n << 8 | u32::from(*b)) << (8 * (3 - chunk.len()));
            for i in 0..=chunk.len() {
                text.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
            }
            text.push_str(&"=".repeat(3 - chunk.len()));
        }
        let escaped = text
            .replace('+', "%2B")
            .replace('/', "%2F")
            .replace('=', "%3D");
        format!("offline?data={escaped}")
    }

    #[test]
    fn one_account_becomes_an_otpauth_url_that_makes_codes() {
        let url = account(&link(&[account_bytes(
            "Example:alice@example.com",
            "Example",
            1,
            1,
            2,
        )]))
        .unwrap();
        assert!(
            url.starts_with("otpauth://totp/Example:alice%40example.com?secret=JBSWY3DPEHPK3PXP"),
            "{}",
            *url
        );
        assert!(
            url.contains("&algorithm=SHA1&digits=6&period=30&issuer=Example"),
            "{}",
            *url
        );
        let code = crate::vault::totp_url(
            &format!(
                "otpauth-migration://{}",
                link(&[account_bytes("a", "B", 1, 1, 2)])
            ),
            "t",
            "u",
        );
        let stored = code.unwrap();
        let totp: keepass::db::TOTP = stored.parse().unwrap();
        assert_eq!(totp.value_now().unwrap().code.len(), 6);
    }

    #[test]
    fn algorithm_and_digits_survive() {
        let url = account(&link(&[account_bytes("a", "", 3, 2, 2)])).unwrap();
        assert!(url.contains("algorithm=SHA512&digits=8"), "{}", *url);
        assert!(!url.contains("issuer="), "{}", *url);
    }

    #[test]
    fn several_accounts_hotp_and_md5_are_refused_by_name() {
        let two = link(&[
            account_bytes("a", "A", 1, 1, 2),
            account_bytes("b", "B", 1, 1, 2),
        ]);
        assert!(account(&two).unwrap_err().contains("2 accounts"));
        assert!(
            account(&link(&[account_bytes("a", "A", 1, 1, 1)]))
                .unwrap_err()
                .contains("totp")
        );
        assert!(
            account(&link(&[account_bytes("a", "A", 4, 1, 2)]))
                .unwrap_err()
                .contains("MD5")
        );
    }

    #[test]
    fn damaged_links_are_errors_not_panics() {
        for bad in [
            "",
            "offline",
            "offline?data=",
            "offline?data=%ZZ",
            "offline?data=!!!!",
            "offline?data=AAAA",
        ] {
            assert!(account(bad).is_err(), "{bad}");
        }
        assert!(walk(&[0x0a, 0x7f, 0x01]).is_none(), "a length past the end");
        assert!(walk(&[0x0f]).is_none(), "an unknown wire type");
        assert!(
            varint(&mut &[0x80u8; 11][..]).is_none(),
            "an endless varint"
        );
    }

    #[test]
    fn base32_matches_the_rfc_vectors() {
        assert_eq!(*base32(b""), "");
        assert_eq!(*base32(b"f"), "MY");
        assert_eq!(*base32(b"fo"), "MZXQ");
        assert_eq!(*base32(b"foobar"), "MZXW6YTBOI");
        assert_eq!(*base32(b"Hello!\xde\xad\xbe\xef"), "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn base64_reads_both_alphabets_with_or_without_padding() {
        assert_eq!(&**base64_decode(b"Zm9vYg==").unwrap(), b"foob");
        assert_eq!(&**base64_decode(b"Zm9vYg").unwrap(), b"foob");
        assert_eq!(
            &**base64_decode(b"-_-_").unwrap(),
            &**base64_decode(b"+/+/").unwrap()
        );
        assert!(base64_decode(b"Zm9v*g").is_none());
    }
}
