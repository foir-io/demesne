use demesne_gocompat::{json, quote, sort_slice};

struct Fnv(u64);

impl Fnv {
    fn new() -> Self {
        Fnv(14695981039346656037)
    }
    fn write(&mut self, s: &str) {
        for b in s.bytes() {
            self.0 ^= b as u64;
            self.0 = self.0.wrapping_mul(1099511628211);
        }
    }
}

struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 >> 33
    }
}

fn expected(kind: &str) -> (usize, String) {
    let text = include_str!("../../../testdata/parity/gocompat_vectors.txt");
    let line = text.lines().find(|l| l.starts_with(kind)).expect("vector line");
    let mut parts = line.split(' ').skip(1);
    (parts.next().unwrap().parse().unwrap(), parts.next().unwrap().to_string())
}

fn runes() -> impl Iterator<Item = char> {
    (0u32..=0x10FFFF).filter_map(char::from_u32)
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
                let mut items: Vec<(usize, usize)> = (0..n)
                    .map(|i| {
                        let key = match pattern {
                            0 => (r.next() % k as u64) as usize,
                            1 => i % k,
                            2 => (n - i) % k,
                            3 => (i / 3) % k,
                            _ => ((i as u64 * 2654435761) % k as u64) as usize,
                        };
                        (key, i)
                    })
                    .collect();
                sort_slice(&mut items, |a, b| a.0 < b.0);
                let mut s = String::new();
                for (_, id) in &items {
                    s.push_str(&id.to_string());
                    s.push(',');
                }
                s.push(';');
                h.write(&s);
                cases += 1;
            }
        }
    }
    assert_eq!((cases, format!("{:016x}", h.0)), expected("sort"));
}
