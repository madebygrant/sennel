// A one-time code's QR, read from a screenshot on the clipboard or a saved image. What comes out
// goes through `totp_url`, the same checks a typed seed gets.

use std::path::Path;

use arboard::Clipboard;

use crate::vault::totp_url;

const NONE_FOUND: &str = "no QR code in that image · crop closer to the code";
// A 5K screenshot is about 60 MB of pixels; past this a dropped file is refused, not decoded.
const MAX_SIDE: u32 = 8192;
const MAX_BYTES: u64 = 128 * 1024 * 1024;

// A setup page can hold other codes, such as an app store link, so a one-time code wins over
// whatever was found first. A code drawn light on dark is tried inverted.
pub fn decode(width: usize, height: usize, rgba: &[u8]) -> Result<String, String> {
    if width == 0 || height == 0 || rgba.len() < width * height * 4 {
        return Err(NONE_FOUND.into());
    }
    let mut found = texts(width, height, rgba, false);
    if found.is_empty() {
        found = texts(width, height, rgba, true);
    }
    let first = found.first().cloned();
    found
        .into_iter()
        .find(|t| t.trim().starts_with("otpauth"))
        .or(first)
        .ok_or_else(|| NONE_FOUND.into())
}

fn texts(width: usize, height: usize, rgba: &[u8], invert: bool) -> Vec<String> {
    let mut prepared = rqrr::PreparedImage::prepare_from_greyscale(width, height, |x, y| {
        let at = (y * width + x) * 4;
        let [r, g, b, a] = [0, 1, 2, 3].map(|i| u32::from(rgba[at + i]));
        // Over white, since a transparent PNG's clear pixels would otherwise read as black.
        let luma = ((r * 299 + g * 587 + b * 114) / 1000 * a / 255 + (255 - a)) as u8;
        if invert { 255 - luma } else { luma }
    });
    prepared
        .detect_grids()
        .into_iter()
        .filter_map(|grid| grid.decode().ok().map(|(_, text)| text))
        .collect()
}

/// A QR's text as the URL an entry stores, refusing anything that is not a time-based code.
pub fn seed(text: &str, title: &str, username: &str) -> Result<String, String> {
    let text = text.trim();
    if !text.starts_with("otpauth") {
        return Err("that QR code is not a one-time code".into());
    }
    totp_url(text, title, username)
}

/// The image on the clipboard. Left in place: only once it proves to hold a one-time code is it a
/// secret, and then the caller clears it with `clear_clipboard`.
pub fn from_clipboard() -> Result<String, String> {
    let image = Clipboard::new()
        .map_err(|e| format!("no clipboard to read · {e}"))?
        .get_image()
        .map_err(|_| {
            "no image on the clipboard · copy a screenshot of the QR code first".to_string()
        })?;
    decode(image.width, image.height, &image.bytes)
}

pub fn clear_clipboard() {
    if let Ok(mut board) = Clipboard::new() {
        let _ = board.clear();
    }
}

pub fn from_file(path: &Path) -> Result<String, String> {
    let unreadable =
        |e: &dyn std::fmt::Display| format!("cannot read {} as an image · {e}", path.display());
    let mut reader = image::ImageReader::open(path)
        .map_err(|e| unreadable(&e))?
        .with_guessed_format()
        .map_err(|e| unreadable(&e))?;
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(MAX_SIDE);
    limits.max_image_height = Some(MAX_SIDE);
    limits.max_alloc = Some(MAX_BYTES);
    reader.limits(limits);
    let image = reader
        .decode()
        .map_err(|e| match e {
            image::ImageError::Limits(_) => "image too large · crop it to the QR code".to_string(),
            e => unreadable(&e),
        })?
        .into_rgba8();
    decode(
        image.width() as usize,
        image.height() as usize,
        image.as_raw(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_blank_image_has_no_code() {
        let white = vec![255; 40 * 40 * 4];
        assert_eq!(decode(40, 40, &white), Err(NONE_FOUND.to_string()));
        assert_eq!(decode(0, 0, &[]), Err(NONE_FOUND.to_string()));
        assert_eq!(decode(10, 10, &[0; 8]), Err(NONE_FOUND.to_string()));
    }

    const SCANNED: &str =
        "otpauth://totp/Example:ada@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";

    fn fixture(name: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(name)
    }

    #[test]
    fn a_saved_qr_reads_back_its_url() {
        assert_eq!(from_file(&fixture("otp-qr.png")).as_deref(), Ok(SCANNED));
        // Clear pixels read as white, not black, or the code's quiet zone disappears.
        assert_eq!(
            from_file(&fixture("otp-qr-clear.png")).as_deref(),
            Ok(SCANNED)
        );
    }

    fn pixels(name: &str) -> (usize, usize, Vec<u8>) {
        let image = image::open(fixture(name)).unwrap().into_rgba8();
        (
            image.width() as usize,
            image.height() as usize,
            image.into_raw(),
        )
    }

    #[test]
    fn a_code_drawn_light_on_dark_is_read_too() {
        let (w, h, mut rgba) = pixels("otp-qr.png");
        for px in rgba.chunks_mut(4) {
            for c in &mut px[..3] {
                *c = 255 - *c;
            }
        }
        assert_eq!(decode(w, h, &rgba).as_deref(), Ok(SCANNED));
    }

    #[test]
    fn a_one_time_code_wins_over_another_code_beside_it() {
        // Another code to the left of the one-time code, so it is the one found first.
        let (w, h, code) = pixels("otp-qr.png");
        let (lw, lh, link) = pixels("link-qr.png");
        let (width, height) = (lw + w, lh.max(h));
        let mut both = vec![255; width * height * 4];
        for (src, sw, sh, left) in [(&link, lw, lh, 0), (&code, w, h, lw)] {
            for y in 0..sh {
                let from = y * sw * 4;
                let to = (y * width + left) * 4;
                both[to..to + sw * 4].copy_from_slice(&src[from..from + sw * 4]);
            }
        }
        assert_eq!(decode(width, height, &both).as_deref(), Ok(SCANNED));
    }

    #[test]
    fn an_oversized_image_is_refused_before_decoding() {
        let path = std::env::temp_dir().join(format!("sennel-wide-{}.png", std::process::id()));
        image::RgbaImage::new(MAX_SIDE + 1, 1).save(&path).unwrap();
        let why = from_file(&path).unwrap_err();
        let _ = std::fs::remove_file(&path);
        assert!(why.starts_with("image too large"), "{why}");
    }

    #[test]
    fn a_file_that_is_not_an_image_says_so() {
        let why = from_file(&fixture("keyfile4.key")).unwrap_err();
        assert!(why.starts_with("cannot read"), "{why}");
    }

    #[test]
    fn only_a_time_based_code_is_a_seed() {
        assert!(seed("https://example.com", "", "").is_err());
        assert!(seed("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1", "", "").is_err());
        let url = seed(
            "otpauth://totp/Site:ada?secret=JBSWY3DPEHPK3PXP&issuer=Site",
            "",
            "",
        )
        .unwrap();
        assert!(
            url.starts_with("otpauth://totp/") && url.contains("JBSWY3DPEHPK3PXP"),
            "{url}"
        );
    }
}
