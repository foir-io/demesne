pub(crate) enum Elem {
    Pair { key: String, value: String },
    Multi(String),
    Item(String),
}

fn pad(key: &str, width: usize) -> String {
    let n = key.chars().count();
    let mut s = String::from(key);
    s.extend(std::iter::repeat_n(' ', width + 1 - n));
    s
}

pub(crate) fn struct_fields(indent: &str, fields: &[(String, String)]) -> String {
    let width = fields.iter().map(|(n, _)| n.chars().count()).max().unwrap_or(0);
    let mut b = String::new();
    for (n, t) in fields {
        b.push_str(indent);
        b.push_str(&pad(n, width));
        b.push_str(t);
        b.push('\n');
    }
    b
}

#[expect(clippy::cast_precision_loss, reason = "go/printer takes this ratio in float64; line sizes and counts are far below 2^52")]
fn section_breaks(elems: &[Elem]) -> Vec<bool> {
    let mut out = vec![false; elems.len()];
    let mut size = 0usize;
    let mut lnsum = 0.0f64;
    let mut count = 0usize;
    for (i, e) in elems.iter().enumerate() {
        let prev_size = size;
        size = match e {
            Elem::Pair { key, .. } => key.chars().count(),
            Elem::Item(s) => s.chars().count(),
            Elem::Multi(_) => 0,
        };
        let mut use_ff = true;
        if prev_size > 0 && size > 0 {
            const SMALL: usize = 40;
            if count == 0 || (prev_size <= SMALL && size <= SMALL) {
                use_ff = false;
            } else {
                let geomean = (lnsum / count as f64).exp();
                let ratio = size as f64 / geomean;
                use_ff = 2.5 * ratio <= 1.0 || 2.5 <= ratio;
            }
        }
        out[i] = i == 0 || use_ff;
        if size > 0 {
            lnsum += (size as f64).ln();
            count += 1;
        }
    }
    out
}

pub(crate) fn kv_block(indent: &str, elems: &[Elem]) -> String {
    let breaks = section_breaks(elems);
    let aligned = elems.len() > 1;
    let mut b = String::new();
    let mut i = 0;
    while i < elems.len() {
        let mut j = i + 1;
        while j < elems.len() && !breaks[j] && matches!(elems[j], Elem::Pair { .. }) && matches!(elems[j - 1], Elem::Pair { .. }) {
            j += 1;
        }
        let width = elems[i..j]
            .iter()
            .filter_map(|e| match e {
                Elem::Pair { key, .. } => Some(key.chars().count() + 1),
                _ => None,
            })
            .max()
            .unwrap_or(0);
        for e in &elems[i..j] {
            b.push_str(&kv_line(indent, e, aligned, width));
        }
        i = j;
    }
    b
}

fn kv_line(indent: &str, e: &Elem, aligned: bool, width: usize) -> String {
    match e {
        Elem::Pair { key, value } => {
            let k = format!("{key}:");
            let key_col = if aligned { pad(&k, width) } else { format!("{k} ") };
            format!("{indent}{key_col}{value},\n")
        }
        Elem::Multi(text) | Elem::Item(text) => format!("{indent}{text},\n"),
    }
}
