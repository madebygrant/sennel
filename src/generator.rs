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

/* The passphrase list: the EFF large wordlist, minus its four hyphenated
   entries (`drop-down`, `felt-tip`, `t-shirt`, `yo-yo`), which would read as
   separators rather than words. CC-BY, eff.org. One file rather than an
   array: 7772 words as source would bury the module that reads it. */
const WORDS_TXT: &str = include_str!("words.txt");

/// The wordlist, parsed once. A `Vec` rather than a sorted table: draws are
/// by uniform index, so nothing ever searches it.
static WORDS: std::sync::LazyLock<Vec<&'static str>> =
    std::sync::LazyLock::new(|| WORDS_TXT.lines().collect());

/// How many words a passphrase draws from.
pub fn word_count() -> usize {
    WORDS.len()
}

/* What a password is shaped like. `Complex` is the historical generator —
   character classes over a length. `Passphrase` is words off the list.
   `Pin` is digits, for the screens that only accept those. */
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Kind {
    #[default]
    Complex,
    Passphrase,
    Pin,
}

impl Kind {
    /// The config file and `--kind` spellings. Lowercase, like every other
    /// value Sennel reads.
    pub fn parse(text: &str) -> Option<Kind> {
        match text.trim().to_lowercase().as_str() {
            "complex" => Some(Kind::Complex),
            "passphrase" => Some(Kind::Passphrase),
            "pin" => Some(Kind::Pin),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Kind::Complex => "complex",
            Kind::Passphrase => "passphrase",
            Kind::Pin => "pin",
        }
    }

    /// For the `t` cycle in the popup: complex, passphrase, pin, back round.
    pub fn next(self) -> Kind {
        match self {
            Kind::Complex => Kind::Passphrase,
            Kind::Passphrase => Kind::Pin,
            Kind::Pin => Kind::Complex,
        }
    }
}

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

/// Eight uniform bytes from the OS, as one number. Failures are real (no
/// entropy source) and the caller names them rather than silently degrading
/// to a weak source.
fn os_draw() -> Result<u64, String> {
    let mut buf = [0u8; 8];
    getrandom::fill(&mut buf).map_err(|e| format!("os randomness failed: {e}"))?;
    Ok(u64::from_le_bytes(buf))
}

/// A uniform index into `n`, rejection-sampled so `%` never skews the pick.
/* Drawn from the whole 64-bit range rather than from one byte. The byte
   version passed n = 255 straight through to `% n` — 256 values over 255
   slots, which handed index 0 twice the weight of every other one, in the one
   function here whose whole job is not doing that. It was reachable: the
   shuffle asks for `i + 1`, and LENGTH_RANGE tops out at 256. A wider draw
   has no such edge to get wrong and no ceiling for a future caller to cross,
   and at one syscall per character the extra seven bytes cost nothing. */
fn os_index(n: usize) -> Result<usize, String> {
    if n == 0 {
        return Err("nothing to draw from".to_string());
    }
    let n = n as u64;
    /* The largest multiple of n that fits, so everything at or above it is
       redrawn rather than folded onto the low indices. */
    let limit = (u64::MAX / n) * n;
    loop {
        let draw = os_draw()?;
        if draw < limit {
            return Ok((draw % n) as usize);
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

/// A passphrase's worth: one uniform word per slot, so words times the
/// list's own width. Six off this list is ~78 bits.
pub fn passphrase_bits(words: usize) -> f64 {
    if words == 0 {
        return 0.0;
    }
    (words as f64) * (word_count() as f64).log2()
}

/// A PIN's worth: one of ten digits per slot. Six is ~20 bits — fine for a
/// screen that locks after three tries, nothing more.
pub fn pin_bits(len: usize) -> f64 {
    entropy_bits(len, DIGITS.len())
}

/// The separator between passphrase words. A dash: spaces get trimmed by
/// sites and underscores need the shift key on most layouts.
pub const WORD_SEPARATOR: &str = "-";

/// Words off the list, joined with dashes. Each slot is a uniform index, so
/// a six-word result holds ~78 bits — and reads as words, not noise.
pub fn generate_passphrase(words: usize) -> Result<String, String> {
    if words == 0 {
        return Err("a passphrase needs at least one word".into());
    }
    if WORDS.is_empty() {
        return Err("the wordlist is empty".into());
    }
    let mut out = Vec::with_capacity(words);
    for _ in 0..words {
        out.push(WORDS[os_index(WORDS.len())?]);
    }
    Ok(out.join(WORD_SEPARATOR))
}

/// Digits only, for the screens that accept nothing else. The full ten, even
/// with ambiguous exclusion on: a PIN missing 0 and 1 would read as broken,
/// and nobody confuses digits on a phone pad.
pub fn generate_pin(len: usize) -> Result<String, String> {
    if len == 0 {
        return Err("length must be at least 1".into());
    }
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(DIGITS[os_index(DIGITS.len())?]);
    }
    String::from_utf8(out).map_err(|_| "generator produced non-utf8".into())
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

    /* The list survived embedding: thousands of words, all lowercase ASCII,
       none hyphenated (they would read as separators). */
    #[test]
    fn the_wordlist_is_what_the_passphrase_draws_from() {
        assert_eq!(word_count(), 7772, "only {} words", word_count());
        let mut seen = std::collections::HashSet::new();
        for w in WORDS.iter() {
            assert!(
                !w.is_empty() && w.bytes().all(|c| c.is_ascii_lowercase()),
                "bad word {w:?}"
            );
            assert!(seen.insert(*w), "duplicate word {w:?}");
        }
    }

    /* Six words, five dashes, all off the list. */
    #[test]
    fn a_passphrase_is_words_joined_with_dashes() {
        let made = generate_passphrase(6).unwrap();
        let words: Vec<&str> = made.split(WORD_SEPARATOR).collect();
        assert_eq!(words.len(), 6, "{made:?}");
        for w in words {
            assert!(WORDS.contains(&w), "{w:?} is not off the list");
        }
        assert!(generate_passphrase(0).is_err());
    }

    #[test]
    fn two_passphrases_differ() {
        let a = generate_passphrase(6).unwrap();
        let b = generate_passphrase(6).unwrap();
        assert_ne!(a, b, "the OS source produced the same passphrase twice");
    }

    /* Six words hold ~78 bits; a dragged-out PIN holds barely twenty. */
    #[test]
    fn passphrase_and_pin_bits_price_what_they_draw_from() {
        let six = passphrase_bits(6);
        assert!(six > 70.0 && six < 85.0, "{six}");
        assert_eq!(passphrase_bits(0), 0.0);
        assert!((pin_bits(6) - 6.0 * 10f64.log2()).abs() < 1e-9);
        assert_eq!(strength(passphrase_bits(6)), "good");
    }

    /* Digits and only digits, at exactly the length asked. */
    #[test]
    fn a_pin_is_digits_at_the_length_asked() {
        let pin = generate_pin(6).unwrap();
        assert_eq!(pin.chars().count(), 6);
        assert!(pin.bytes().all(|c| c.is_ascii_digit()));
        assert!(generate_pin(0).is_err());
    }

    /* The kind spellings round-trip, and the popup cycles all three. */
    #[test]
    fn kinds_parse_and_cycle() {
        assert_eq!(Kind::parse("complex"), Some(Kind::Complex));
        assert_eq!(Kind::parse(" Passphrase "), Some(Kind::Passphrase));
        assert_eq!(Kind::parse("PIN"), Some(Kind::Pin));
        assert_eq!(Kind::parse("words"), None);
        assert_eq!(Kind::Complex.next(), Kind::Passphrase);
        assert_eq!(Kind::Passphrase.next(), Kind::Pin);
        assert_eq!(Kind::Pin.next(), Kind::Complex);
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
