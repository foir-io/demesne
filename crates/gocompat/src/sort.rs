#![expect(
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation,
    clippy::many_single_char_names,
    reason = "a line-for-line port of Go's pdqsort, which works in signed int with Go's names, so the tie order stays exactly Go's"
)]

#[derive(PartialEq, Eq, Clone, Copy)]
enum Hint {
    Unknown,
    Increasing,
    Decreasing,
}

struct Data<'a, T, F: FnMut(&T, &T) -> bool> {
    v: &'a mut [T],
    less: F,
}

impl<T, F: FnMut(&T, &T) -> bool> Data<'_, T, F> {
    fn less(&mut self, i: usize, j: usize) -> bool {
        (self.less)(&self.v[i], &self.v[j])
    }
    fn swap(&mut self, i: usize, j: usize) {
        self.v.swap(i, j);
    }
}

fn bits_len(x: usize) -> usize {
    x.bit_width() as usize
}

pub fn sort_slice<T, F: FnMut(&T, &T) -> bool>(v: &mut [T], less: F) {
    let n = v.len();
    let limit = bits_len(n);
    let mut d = Data { v, less };
    pdqsort(&mut d, 0, n as isize, limit);
}

fn insertion_sort<T, F: FnMut(&T, &T) -> bool>(d: &mut Data<T, F>, a: isize, b: isize) {
    let mut i = a + 1;
    while i < b {
        let mut j = i;
        while j > a && d.less(j as usize, (j - 1) as usize) {
            d.swap(j as usize, (j - 1) as usize);
            j -= 1;
        }
        i += 1;
    }
}

fn sift_down<T, F: FnMut(&T, &T) -> bool>(d: &mut Data<T, F>, lo: isize, hi: isize, first: isize) {
    let mut root = lo;
    loop {
        let mut child = 2 * root + 1;
        if child >= hi {
            break;
        }
        if child + 1 < hi && d.less((first + child) as usize, (first + child + 1) as usize) {
            child += 1;
        }
        if !d.less((first + root) as usize, (first + child) as usize) {
            return;
        }
        d.swap((first + root) as usize, (first + child) as usize);
        root = child;
    }
}

fn heap_sort<T, F: FnMut(&T, &T) -> bool>(d: &mut Data<T, F>, a: isize, b: isize) {
    let first = a;
    let lo = 0;
    let hi = b - a;
    let mut i = (hi - 1) / 2;
    while i >= 0 {
        sift_down(d, i, hi, first);
        i -= 1;
    }
    let mut i = hi - 1;
    while i >= 0 {
        d.swap(first as usize, (first + i) as usize);
        sift_down(d, lo, i, first);
        i -= 1;
    }
}

fn pdqsort<T, F: FnMut(&T, &T) -> bool>(d: &mut Data<T, F>, mut a: isize, mut b: isize, mut limit: usize) {
    const MAX_INSERTION: isize = 12;
    let mut was_balanced = true;
    let mut was_partitioned = true;
    loop {
        let length = b - a;
        if length <= MAX_INSERTION {
            insertion_sort(d, a, b);
            return;
        }
        if limit == 0 {
            heap_sort(d, a, b);
            return;
        }
        if !was_balanced {
            break_patterns(d, a, b);
            limit -= 1;
        }
        let (mut pivot, mut hint) = choose_pivot(d, a, b);
        if hint == Hint::Decreasing {
            reverse_range(d, a, b);
            pivot = (b - 1) - (pivot - a);
            hint = Hint::Increasing;
        }
        if was_balanced && was_partitioned && hint == Hint::Increasing && partial_insertion_sort(d, a, b) {
            return;
        }
        if a > 0 && !d.less((a - 1) as usize, pivot as usize) {
            let mid = partition_equal(d, a, b, pivot);
            a = mid;
            continue;
        }
        let (mid, already) = partition(d, a, b, pivot);
        was_partitioned = already;
        let (left_len, right_len) = (mid - a, b - mid);
        let balance_threshold = length / 8;
        if left_len < right_len {
            was_balanced = left_len >= balance_threshold;
            pdqsort(d, a, mid, limit);
            a = mid + 1;
        } else {
            was_balanced = right_len >= balance_threshold;
            pdqsort(d, mid + 1, b, limit);
            b = mid;
        }
    }
}

fn partition<T, F: FnMut(&T, &T) -> bool>(d: &mut Data<T, F>, a: isize, b: isize, pivot: isize) -> (isize, bool) {
    d.swap(a as usize, pivot as usize);
    let (mut i, mut j) = (a + 1, b - 1);
    while i <= j && d.less(i as usize, a as usize) {
        i += 1;
    }
    while i <= j && !d.less(j as usize, a as usize) {
        j -= 1;
    }
    if i > j {
        d.swap(j as usize, a as usize);
        return (j, true);
    }
    d.swap(i as usize, j as usize);
    i += 1;
    j -= 1;
    loop {
        while i <= j && d.less(i as usize, a as usize) {
            i += 1;
        }
        while i <= j && !d.less(j as usize, a as usize) {
            j -= 1;
        }
        if i > j {
            break;
        }
        d.swap(i as usize, j as usize);
        i += 1;
        j -= 1;
    }
    d.swap(j as usize, a as usize);
    (j, false)
}

fn partition_equal<T, F: FnMut(&T, &T) -> bool>(d: &mut Data<T, F>, a: isize, b: isize, pivot: isize) -> isize {
    d.swap(a as usize, pivot as usize);
    let (mut i, mut j) = (a + 1, b - 1);
    loop {
        while i <= j && !d.less(a as usize, i as usize) {
            i += 1;
        }
        while i <= j && d.less(a as usize, j as usize) {
            j -= 1;
        }
        if i > j {
            break;
        }
        d.swap(i as usize, j as usize);
        i += 1;
        j -= 1;
    }
    i
}

fn partial_insertion_sort<T, F: FnMut(&T, &T) -> bool>(d: &mut Data<T, F>, a: isize, b: isize) -> bool {
    const MAX_STEPS: usize = 5;
    const SHORTEST_SHIFTING: isize = 50;
    let mut i = a + 1;
    for _ in 0..MAX_STEPS {
        while i < b && !d.less(i as usize, (i - 1) as usize) {
            i += 1;
        }
        if i == b {
            return true;
        }
        if b - a < SHORTEST_SHIFTING {
            return false;
        }
        d.swap(i as usize, (i - 1) as usize);
        if i - a >= 2 {
            let mut j = i - 1;
            while j >= 1 && d.less(j as usize, (j - 1) as usize) {
                d.swap(j as usize, (j - 1) as usize);
                j -= 1;
            }
        }
        if b - i >= 2 {
            let mut j = i + 1;
            while j < b && d.less(j as usize, (j - 1) as usize) {
                d.swap(j as usize, (j - 1) as usize);
                j += 1;
            }
        }
    }
    false
}

fn break_patterns<T, F: FnMut(&T, &T) -> bool>(d: &mut Data<T, F>, a: isize, b: isize) {
    let length = b - a;
    if length >= 8 {
        let mut random = length as u64;
        let modulus = 1usize << bits_len(length as usize);
        let mut idx = a + (length / 4) * 2 - 1;
        while idx <= a + (length / 4) * 2 + 1 {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            let mut other = ((random as usize) & (modulus - 1)) as isize;
            if other >= length {
                other -= length;
            }
            d.swap(idx as usize, (a + other) as usize);
            idx += 1;
        }
    }
}

fn choose_pivot<T, F: FnMut(&T, &T) -> bool>(d: &mut Data<T, F>, a: isize, b: isize) -> (isize, Hint) {
    const SHORTEST_NINTHER: isize = 50;
    const MAX_SWAPS: usize = 4 * 3;
    let l = b - a;
    let mut swaps = 0usize;
    let mut i = a + l / 4;
    let mut j = a + l / 4 * 2;
    let mut k = a + l / 4 * 3;
    if l >= 8 {
        if l >= SHORTEST_NINTHER {
            i = median_adjacent(d, i, &mut swaps);
            j = median_adjacent(d, j, &mut swaps);
            k = median_adjacent(d, k, &mut swaps);
        }
        j = median(d, i, j, k, &mut swaps);
    }
    match swaps {
        0 => (j, Hint::Increasing),
        MAX_SWAPS => (j, Hint::Decreasing),
        _ => (j, Hint::Unknown),
    }
}

fn order2<T, F: FnMut(&T, &T) -> bool>(d: &mut Data<T, F>, a: isize, b: isize, swaps: &mut usize) -> (isize, isize) {
    if d.less(b as usize, a as usize) {
        *swaps += 1;
        return (b, a);
    }
    (a, b)
}

fn median<T, F: FnMut(&T, &T) -> bool>(d: &mut Data<T, F>, a: isize, b: isize, c: isize, swaps: &mut usize) -> isize {
    let (a, b) = order2(d, a, b, swaps);
    let (b, c) = order2(d, b, c, swaps);
    let _ = c;
    let (_a, b) = order2(d, a, b, swaps);
    b
}

fn median_adjacent<T, F: FnMut(&T, &T) -> bool>(d: &mut Data<T, F>, a: isize, swaps: &mut usize) -> isize {
    median(d, a - 1, a, a + 1, swaps)
}

fn reverse_range<T, F: FnMut(&T, &T) -> bool>(d: &mut Data<T, F>, a: isize, b: isize) {
    let (mut i, mut j) = (a, b - 1);
    while i < j {
        d.swap(i as usize, j as usize);
        i += 1;
        j -= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::sort_slice;

    #[test]
    fn sorts_by_key_and_keeps_go_tie_order_on_known_input() {
        let mut v: Vec<(u32, u32)> = (0..200).map(|i| ((i * 7919) % 13, i)).collect();
        sort_slice(&mut v, |a, b| a.0 < b.0);
        for w in v.windows(2) {
            assert!(w[0].0 <= w[1].0);
        }
    }
}
