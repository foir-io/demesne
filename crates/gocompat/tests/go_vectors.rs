use demesne_gocompat::{json, quote, sort_slice};
use std::fmt::Write as _;

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

struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
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

fn id_list(items: &[(usize, usize)]) -> String {
    let mut s = String::new();
    for (_, id) in items {
        write!(s, "{id},").expect("fmt::Write for String never fails");
    }
    s.push(';');
    s
}

fn case_key(r: &mut Lcg, pattern: usize, i: usize, n: usize, k: usize) -> usize {
    match pattern {
        0 => usize::try_from(r.next() % k as u64).expect("a remainder below k fits in usize"),
        1 => i % k,
        2 => (n - i) % k,
        3 => (i / 3) % k,
        _ => usize::try_from((i as u64 * 2_654_435_761) % k as u64).expect("a remainder below k fits in usize"),
    }
}

#[test]
fn sort_slice_reproduces_go_tie_order() {
    let mut r = Lcg(42);
    let mut sizes: Vec<usize> = (0..=300).collect();
    sizes.extend([511, 512, 513, 1000, 4096, 5000]);
    let mut h = Fnv::new();
    let mut cases = 0;
    for &n in &sizes {
        for k in [1usize, 2, 3, 7, 50, n + 1] {
            for pattern in 0..5 {
                let mut items: Vec<(usize, usize)> = (0..n).map(|i| (case_key(&mut r, pattern, i, n, k), i)).collect();
                sort_slice(&mut items, |a, b| a.0 < b.0);
                h.write(&id_list(&items));
                cases += 1;
            }
        }
    }
    assert_eq!((cases, format!("{:016x}", h.0)), expected("sort"));
}
