// How much key-derivation work a vault file asks for, read from its header before any of it is
// done. keepass runs the derivation before it checks the header's HMAC, so whoever can write the
// file, with no key, chooses how long an unlock spends and how much memory it takes.

use keepass::Database;
use keepass::config::KdfConfig;

pub const MAX_AES_ROUNDS: u64 = 1_000_000_000;
pub const MAX_ARGON2_MEMORY: u64 = 2 << 30;
pub const MAX_ARGON2_PASSES: u64 = 10_000;
// Memory in MiB times passes: 256 GiB of memory traffic in all.
pub const MAX_ARGON2_WORK: u64 = 262_144;
pub const MAX_ARGON2_LANES: u64 = 64;

/// What a header asks for. All `None` when the header does not parse, and then the crate's own
/// open reports why.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Work {
    pub aes_rounds: Option<u64>,
    pub argon2_memory: Option<u64>,
    pub argon2_passes: Option<u64>,
    pub argon2_lanes: Option<u64>,
}

// Read by keepass's own header parser (a patch in vendor/keepass), so a field it would use is
// never one this skipped. That parser can panic on a damaged header, as opening one can.
pub fn work(file: &[u8]) -> Work {
    let config = crate::quiet::quietly(|| Database::kdf_config_of(file)).flatten();
    match config {
        Some(KdfConfig::Aes { rounds }) => Work {
            aes_rounds: Some(rounds),
            ..Work::default()
        },
        Some(
            KdfConfig::Argon2 {
                iterations,
                memory,
                parallelism,
                ..
            }
            | KdfConfig::Argon2id {
                iterations,
                memory,
                parallelism,
                ..
            },
        ) => Work {
            argon2_memory: Some(memory),
            argon2_passes: Some(iterations),
            argon2_lanes: Some(u64::from(parallelism)),
            ..Work::default()
        },
        _ => Work::default(),
    }
}

/// Why a file asks for too much, or `None` when it is within every limit.
pub fn refusal(file: &[u8]) -> Option<String> {
    let w = work(file);
    let over = |what: &str, asked: u64, most: u64| {
        (asked > most).then(|| format!("{what} {asked}, and Sennel does {most} at most"))
    };
    let mib = w.argon2_memory.map(|m| m >> 20);
    let total = mib.zip(w.argon2_passes).map(|(m, p)| m.saturating_mul(p));
    [
        w.aes_rounds
            .and_then(|r| over("AES rounds", r, MAX_AES_ROUNDS)),
        mib.and_then(|m| over("Argon2 MiB", m, MAX_ARGON2_MEMORY >> 20)),
        w.argon2_passes
            .and_then(|p| over("Argon2 passes", p, MAX_ARGON2_PASSES)),
        total.and_then(|t| over("Argon2 MiB × passes", t, MAX_ARGON2_WORK)),
        w.argon2_lanes
            .and_then(|l| over("Argon2 lanes", l, MAX_ARGON2_LANES)),
    ]
    .into_iter()
    .flatten()
    .next()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> Vec<u8> {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
        std::fs::read(dir.join(name)).unwrap()
    }

    // A KDBX header as its fields, `width` being the length field's size (2 for KDBX 3, 4 for 4),
    // and everything after the end field.
    #[allow(clippy::type_complexity)]
    fn split(file: &[u8], width: usize) -> (Vec<(u8, Vec<u8>)>, Vec<u8>) {
        let mut fields = Vec::new();
        let mut at = 12;
        loop {
            let id = file[at];
            let mut len = [0u8; 8];
            len[..width].copy_from_slice(&file[at + 1..at + 1 + width]);
            let len = u64::from_le_bytes(len) as usize;
            let data = at + 1 + width;
            fields.push((id, file[data..data + len].to_vec()));
            at = data + len;
            if id == 0 {
                return (fields, file[at..].to_vec());
            }
        }
    }

    fn join(file: &[u8], width: usize, fields: &[(u8, Vec<u8>)], rest: &[u8]) -> Vec<u8> {
        let mut out = file[..12].to_vec();
        for (id, data) in fields {
            out.push(*id);
            out.extend(&(data.len() as u64).to_le_bytes()[..width]);
            out.extend(data);
        }
        out.extend(rest);
        out
    }

    fn dict(items: &[(u8, Vec<u8>, Vec<u8>)]) -> Vec<u8> {
        let mut out = 0x100u16.to_le_bytes().to_vec();
        for (kind, key, value) in items {
            out.push(*kind);
            out.extend((key.len() as u32).to_le_bytes());
            out.extend(key);
            out.extend((value.len() as u32).to_le_bytes());
            out.extend(value);
        }
        out.push(0);
        out
    }

    // keepassxc4.kdbx, which uses AES, given Argon2d settings with one value replaced and stored
    // as `value`.
    fn kdbx4_with(key: &str, value: Vec<u8>) -> Vec<u8> {
        let argon2d = [
            0xef, 0x63, 0x6d, 0xdf, 0x8c, 0x29, 0x44, 0x4b, 0x91, 0xf7, 0xa9, 0xa4, 0x03, 0xe3,
            0x0a, 0x0c,
        ];
        let mut set: Vec<(u8, Vec<u8>, Vec<u8>)> = vec![
            (0x42, b"$UUID".to_vec(), argon2d.to_vec()),
            (0x42, b"S".to_vec(), vec![7; 32]),
            (0x05, b"M".to_vec(), (64u64 << 20).to_le_bytes().to_vec()),
            (0x05, b"I".to_vec(), 3u64.to_le_bytes().to_vec()),
            (0x04, b"P".to_vec(), 4u32.to_le_bytes().to_vec()),
            (0x04, b"V".to_vec(), 0x13u32.to_le_bytes().to_vec()),
        ];
        set.iter_mut()
            .find(|(_, k, _)| k == key.as_bytes())
            .unwrap()
            .2 = value;
        let file = fixture("keepassxc4.kdbx");
        let (mut fields, rest) = split(&file, 4);
        fields.iter_mut().find(|(id, _)| *id == 11).unwrap().1 = dict(&set);
        join(&file, 4, &fields, &rest)
    }

    fn keepass_1(rounds: u32) -> Vec<u8> {
        let mut out = vec![0x03, 0xd9, 0xa2, 0x9a, 0x65, 0xfb, 0x4b, 0xb5];
        out.resize(120, 0);
        out.extend(rounds.to_le_bytes());
        out
    }

    #[test]
    fn the_fixtures_ask_for_ordinary_work() {
        for name in ["keepassxc3.kdbx", "keepassxc4.kdbx", "keyfile4.kdbx"] {
            let file = fixture(name);
            let w = work(&file);
            assert!(
                w.aes_rounds.is_some() || w.argon2_memory.is_some(),
                "{name}: {w:?}"
            );
            assert_eq!(refusal(&file), None, "{name}");
        }
    }

    #[test]
    fn a_keepass_1_header_is_held_to_the_aes_limit() {
        assert!(refusal(&keepass_1(u32::MAX)).is_some());
        // The 2026-11-12 fuzz timeout. Real work within the limit: it opens slowly, not refused.
        assert_eq!(work(&keepass_1(0x04BA_DB00)).aes_rounds, Some(79_354_624));
        assert_eq!(refusal(&keepass_1(0x04BA_DB00)), None);
    }

    #[test]
    fn a_kdbx3_round_count_is_read_the_way_keepass_reads_it() {
        let file = fixture("keepassxc3.kdbx");
        let (fields, rest) = split(&file, 2);
        let with = |rounds: Vec<u8>, twice: bool| {
            let mut fields = fields.clone();
            let at = fields.iter().position(|(id, _)| *id == 6).unwrap();
            if twice {
                fields.insert(at, (6, 1000u64.to_le_bytes().to_vec()));
                fields[at + 1].1 = rounds;
            } else {
                fields[at].1 = rounds;
            }
            join(&file, 2, &fields, &rest)
        };
        let max = u64::MAX.to_le_bytes().to_vec();
        assert!(refusal(&with(max.clone(), false)).is_some());
        // keepass reads the first eight bytes of a longer field, and the last field of a kind.
        let mut long = max.clone();
        long.push(0);
        assert!(refusal(&with(long, false)).is_some(), "a nine-byte field");
        assert!(refusal(&with(max, true)).is_some(), "a second field 6");
        let fine = with(MAX_AES_ROUNDS.to_le_bytes().to_vec(), false);
        assert_eq!(refusal(&fine), None);
    }

    #[test]
    fn argon2_is_held_to_memory_passes_their_product_and_lanes() {
        let gib = 1u64 << 30;
        let m = |bytes: u64| kdbx4_with("M", bytes.to_le_bytes().to_vec());
        let i = |passes: u64| kdbx4_with("I", passes.to_le_bytes().to_vec());
        assert_eq!(refusal(&m(64 << 20)), None, "the baseline itself");
        assert_eq!(refusal(&m(2 * gib)), None);
        assert!(refusal(&m(2 * gib + (1 << 20))).is_some());
        assert!(refusal(&i(MAX_ARGON2_PASSES + 1)).is_some());
        assert!(refusal(&kdbx4_with("P", 65u32.to_le_bytes().to_vec())).is_some());
        let w = work(&m(2 * gib));
        assert_eq!(w.argon2_memory, Some(2 * gib));
    }

    #[test]
    fn a_kdbx4_header_cannot_hide_its_real_settings() {
        // A value longer than eight bytes, of which keepass reads the first eight.
        let mut long = u64::MAX.to_le_bytes().to_vec();
        long.extend([0; 8]);
        assert!(
            refusal(&kdbx4_with("M", long)).is_some(),
            "a 16-byte memory value"
        );

        // A harmless settings field followed by a second one, which keepass uses.
        let hostile = kdbx4_with("M", u64::MAX.to_le_bytes().to_vec());
        let file = fixture("keepassxc4.kdbx");
        let (mut fields, rest) = split(&file, 4);
        let (bad, _) = split(&hostile, 4);
        let second = bad.into_iter().find(|(id, _)| *id == 11).unwrap();
        let at = fields.iter().position(|(id, _)| *id == 11).unwrap();
        fields.insert(at + 1, second);
        assert!(refusal(&join(&file, 4, &fields, &rest)).is_some());
    }

    #[test]
    fn truncated_or_strange_headers_are_left_to_the_crate() {
        let file = fixture("keepassxc4.kdbx");
        for cut in [0, 4, 12, 20, 60, 120] {
            assert_eq!(refusal(&file[..cut]), None, "cut at {cut}");
        }
        let mut huge = file[..12].to_vec();
        huge.push(2);
        huge.extend(u32::MAX.to_le_bytes());
        assert_eq!(refusal(&huge), None);
    }
}
