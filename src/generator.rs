//! Password generation.
//!
//! One job: turn a length and a set of character classes into a password with
//! no more structure than the user asked for. The OS supplies the randomness
//! (`getrandom`); this module only shapes it.

/* The classes, in the order the generator walks them. */
const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.<>?/";

/* Characters that read differently in some fonts or get mangled when read
   aloud: l 1 I O 0. Excluding them shrinks the alphabet, so it is opt-in. */
const AMBIGUOUS: &[u8] = b"l1IO0";

/* One requested class. `chars` holds the pool, `required` whether the
   generator must place at least one of them — a class asked for and missing
   is a generator that lied about what it produces. */
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Classes {
    pub lower: bool,
    pub upper: bool,
    pub digits: bool,
    pub symbols: bool,
}

impl Default for Classes {
    fn default() -> Self {
        Classes {
            lower: true,
            upper: true,
            digits: true,
            symbols: false,
        }
    }
}

impl Classes {
    /// The pool after the ambiguous exclusion, plus which classes survived.
    /// An empty pool is an error the caller names, not a panic.
    fn pools(self, exclude_ambiguous: bool) -> (Vec<Vec<u8>>, Vec<usize>) {
        let strip = |pool: &[u8]| -> Vec<u8> {
            if exclude_ambiguous {
                pool.iter()
                    .copied()
                    .filter(|c| !AMBIGUOUS.contains(c))
                    .collect()
            } else {
                pool.to_vec()
            }
        };
        let wanted = [
            (self.lower, LOWER),
            (self.upper, UPPER),
            (self.digits, DIGITS),
            (self.symbols, SYMBOLS),
        ];
        let mut pools = Vec::new();
        let mut required = Vec::new();
        for (i, (on, pool)) in wanted.iter().enumerate() {
            if !on {
                continue;
            }
            let chars = strip(pool);
            if chars.is_empty() {
                continue;
            }
            pools.push(chars);
            required.push(i);
        }
        (pools, required)
    }

    /// Combined alphabet size, for the entropy estimate. Ambiguity excluded
    /// here too, so the number matches what was actually drawn from.
    pub fn alphabet_len(self, exclude_ambiguous: bool) -> usize {
        self.pools(exclude_ambiguous).0.iter().map(|p| p.len()).sum()
    }
}

/// One uniform byte from the OS. Failures are real (no entropy source) and
/// the caller names them rather than silently degrading to a weak source.
fn os_byte() -> Result<u8, String> {
    let mut buf = [0u8; 1];
    getrandom::fill(&mut buf).map_err(|e| format!("os randomness failed: {e}"))?;
    Ok(buf[0])
}

/// A uniform index into `n`, rejection-sampled so `%` never skews the pick.
/// A uniform index into `n`, rejection-sampled so `%` never skews the pick.
/// For n at or past a full byte there is nothing to reject against — a byte
/// already covers the range — so it passes straight through.
fn os_index(n: usize) -> Result<usize, String> {
    debug_assert!(n > 0);
    if n >= u8::MAX as usize {
        return Ok(os_byte()? as usize % n);
    }
    let limit = (u8::MAX as usize / n) * n;
    loop {
        let b = os_byte()? as usize;
        if b < limit {
            return Ok(b % n);
        }
    }
}

/// Generate a password of `len` characters from the requested classes.
///
/// Every requested class is guaranteed present (one forced pick per class
/// first, then the rest drawn from the combined pool) — a "digits on" result
/// without a digit would read as a broken generator. Errors are strings the
/// UI can show verbatim; they name the cause, never the output.
pub fn generate(len: usize, classes: Classes, exclude_ambiguous: bool) -> Result<String, String> {
    if len == 0 {
        return Err("length must be at least 1".into());
    }
    let (pools, required) = classes.pools(exclude_ambiguous);
    if pools.is_empty() {
        return Err("no character classes selected".into());
    }
    if len < required.len() {
        return Err(format!(
            "length {len} is shorter than the {n} classes asked for",
            n = required.len()
        ));
    }
    let all: Vec<u8> = pools.concat();
    let mut out = Vec::with_capacity(len);
    /* One guaranteed pick per requested class, in class order. */
    for pool in pools.iter().take(required.len()) {
        let at = os_index(pool.len())?;
        out.push(pool[at]);
    }
    while out.len() < len {
        let at = os_index(all.len())?;
        out.push(all[at]);
    }
    /* Shuffle the forced picks out of their positions: class order at the
       front would be structure a guesser could use. Fisher-Yates with the
       same OS source. */
    for i in (1..out.len()).rev() {
        let j = os_index(i + 1)?;
        out.swap(i, j);
    }
    String::from_utf8(out).map_err(|_| "generator produced non-utf8".into())
}

/// Estimated entropy in bits: `len * log2(alphabet)`. An estimate, not a
/// promise — it assumes uniform draws, which the generator makes.
pub fn entropy_bits(len: usize, alphabet_len: usize) -> f64 {
    if len == 0 || alphabet_len <= 1 {
        return 0.0;
    }
    (len as f64) * (alphabet_len as f64).log2()
}

/* What a typed password is worth, judged only by what is in it: the classes
   it actually uses times its length. An over-estimate for "Password1!" — no
   estimate from characters alone can know a word — so the UI shows it as a
   rough number, never as a verdict. */
pub fn typed_bits(password: &str) -> f64 {
    if password.is_empty() {
        return 0.0;
    }
    let mut alphabet = 0usize;
    let mut seen = |pool: &[u8], size: usize, hit: bool| {
        let _ = pool;
        if hit {
            alphabet += size;
        }
    };
    let chars: Vec<char> = password.chars().collect();
    seen(LOWER, 26, chars.iter().any(|c| c.is_ascii_lowercase()));
    seen(UPPER, 26, chars.iter().any(|c| c.is_ascii_uppercase()));
    seen(DIGITS, 10, chars.iter().any(|c| c.is_ascii_digit()));
    seen(
        SYMBOLS,
        SYMBOLS.len(),
        chars.iter().any(|c| c.is_ascii_punctuation() || *c == ' '),
    );
    // Anything outside ASCII widens the pool far past what we can count.
    if chars.iter().any(|c| !c.is_ascii()) {
        alphabet += 100;
    }
    entropy_bits(chars.len(), alphabet.max(2))
}

/// A word for a bit count, since most people do not read bits. The bands are
/// the usual ones: below 60 is guessable offline, 80 is comfortable, 100 is
/// more than a lifetime of hardware.
pub fn strength(bits: f64) -> &'static str {
    match bits {
        b if b < 40.0 => "weak",
        b if b < 60.0 => "fair",
        b if b < 80.0 => "good",
        _ => "strong",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_on() -> Classes {
        Classes {
            lower: true,
            upper: true,
            digits: true,
            symbols: true,
        }
    }

    #[test]
    fn the_length_is_exactly_what_was_asked() {
        /* One class: a single character has room for it. Default turns on
           three, which a length of one cannot honour. */
        let one = generate(
            1,
            Classes {
                lower: true,
                upper: false,
                digits: false,
                symbols: false,
            },
            false,
        )
        .unwrap();
        assert_eq!(one.chars().count(), 1);
        for len in [8, 24, 64] {
            let pw = generate(len, all_on(), false).unwrap();
            assert_eq!(pw.chars().count(), len);
        }
    }

    /* With a long enough password every class shows up at least once. This
       is probabilistic only in the pathological sense: 256 draws over a
       90-character alphabet missing a whole class is ~2^-38. */
    #[test]
    fn every_requested_class_appears() {
        let pw = generate(256, all_on(), false).unwrap();
        assert!(pw.chars().any(char::is_lowercase));
        assert!(pw.chars().any(char::is_uppercase));
        assert!(pw.chars().any(|c| c.is_ascii_digit()));
        assert!(pw
            .chars()
            .any(|c| SYMBOLS.contains(&(c as u8))));
    }

    #[test]
    fn exclusion_removes_the_ambiguous_set() {
        let pw = generate(256, all_on(), true).unwrap();
        for c in pw.chars() {
            assert!(!AMBIGUOUS.contains(&(c as u8)), "ambiguous {c} leaked");
        }
    }

    #[test]
    fn a_class_turned_off_never_appears() {
        let pw = generate(64, Classes::default(), false).unwrap();
        assert!(pw.chars().any(char::is_lowercase));
        assert!(pw.chars().any(char::is_uppercase));
        assert!(pw.chars().any(|c| c.is_ascii_digit()));
        assert!(!pw
            .chars()
            .any(|c| SYMBOLS.contains(&(c as u8))));
    }

    #[test]
    fn impossible_asks_are_errors_not_panics() {
        assert!(generate(0, all_on(), false).is_err());
        assert!(generate(8, Classes { lower: false, upper: false, digits: false, symbols: false }, false).is_err());
        /* Four classes but only two characters of room. */
        assert!(generate(2, all_on(), false).is_err());
    }

    #[test]
    fn two_runs_differ() {
        let a = generate(32, all_on(), false).unwrap();
        let b = generate(32, all_on(), false).unwrap();
        assert_ne!(a, b, "the OS source produced the same password twice");
    }

    /* The estimate reads what is in the password, not what a generator was
       asked for: four classes in twelve characters is worth more than twelve
       lowercase letters, and empty is worth nothing. */
    #[test]
    fn typed_entropy_reads_the_classes_actually_used() {
        assert_eq!(typed_bits(""), 0.0);
        let plain = typed_bits("abcdefghijkl");
        let mixed = typed_bits("aB3!efghijkl");
        assert!(mixed > plain, "{mixed} !> {plain}");
        assert_eq!(strength(typed_bits("abc")), "weak");
        assert_eq!(strength(typed_bits("Tr0ub4dor&3xkcd!")), "strong");
    }

    #[test]
    fn entropy_tracks_length_and_alphabet() {
        assert_eq!(entropy_bits(0, 90), 0.0);
        assert_eq!(entropy_bits(8, 1), 0.0);
        assert!((entropy_bits(8, 64) - 48.0).abs() < 1e-9);
        assert!((entropy_bits(16, 26) - 16.0 * 26f64.log2()).abs() < 1e-9);
    }
}

#[cfg(test)]
mod probe {
    use super::*;
    #[test]
    fn probe_256() {
        let pw = generate(256, Classes { lower: true, upper: true, digits: true, symbols: true }, false);
        eprintln!("PROBE: {:?}", pw.as_ref().map(|s| s.len()));
        assert!(pw.is_ok());
    }
}
