use demesne_gocompat::{json, quote};

struct Fnv(u64);

impl Fnv {
    fn new() -> Self {
        Fnv(14_695_981_039_346_656_037)
    }
    fn write(&mut self, s: &str) {
        for b in s.bytes() {
            self.0 ^= u64::from(b);
            self.0 = self.0.wrapping_mul(1_099_511_628_211);
        }
    }
}

fn expected(kind: &str) -> (usize, String) {
    let text = include_str!("../../../testdata/parity/gocompat_vectors.txt");
    let line = text.lines().find(|l| l.starts_with(kind)).expect("vector line");
    let mut parts = line.split(' ').skip(1);
    let count = parts.next().and_then(|n| n.parse().ok()).expect("a vector line carries its count");
    let digest = parts.next().expect("a vector line carries its digest").to_string();
    (count, digest)
}

fn runes() -> impl Iterator<Item = char> {
    (0u32..=0x0010_FFFF).filter_map(char::from_u32)
}

#[test]
fn quote_matches_strconv_for_every_rune() {
    let mut h = Fnv::new();
    let mut count = 0;
    for r in runes() {
        h.write(&quote(&r.to_string()));
        count += 1;
    }
    h.write(&quote("mixed \"quote\" \\ \n\t é 日本 \u{200b} \u{1F600} \u{0}"));
    assert_eq!((count, format!("{:016x}", h.0)), expected("quote"));
}

#[test]
fn json_strings_match_encoding_json_for_every_rune() {
    let mut h = Fnv::new();
    let mut count = 0;
    for r in runes() {
        h.write(&json::marshal(&json::Value::Str(r.to_string())));
        count += 1;
    }
    assert_eq!((count, format!("{:016x}", h.0)), expected("json"));
}
