package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

type fnv struct{ h uint64 }

func (f *fnv) write(s string) {
	for i := 0; i < len(s); i++ {
		f.h ^= uint64(s[i])
		f.h *= 1099511628211
	}
}

func newFnv() *fnv { return &fnv{h: 14695981039346656037} }

type lcg struct{ x uint64 }

func (l *lcg) next() uint64 {
	l.x = l.x*6364136223846793005 + 1442695040888963407
	return l.x >> 33
}

type item struct{ key, id int }

func sortCases(emit func(n int, items []item)) {
	r := &lcg{x: 42}
	sizes := []int{}
	for n := 0; n <= 300; n++ {
		sizes = append(sizes, n)
	}
	sizes = append(sizes, 511, 512, 513, 1000, 4096, 5000)
	for _, n := range sizes {
		for _, k := range []int{1, 2, 3, 7, 50, n + 1} {
			for pattern := 0; pattern < 5; pattern++ {
				items := make([]item, n)
				for i := range items {
					var key int
					switch pattern {
					case 0:
						key = int(r.next() % uint64(k))
					case 1:
						key = i % k
					case 2:
						key = (n - i) % k
					case 3:
						key = (i / 3) % k
					default:
						key = int((uint64(i)*2654435761)%uint64(k))
					}
					items[i] = item{key, i}
				}
				emit(k, items)
			}
		}
	}
}

func main() {
	q := newFnv()
	count := 0
	for r := rune(0); r <= utf8.MaxRune; r++ {
		if r >= 0xD800 && r <= 0xDFFF {
			continue
		}
		q.write(strconv.Quote(string(r)))
		count++
	}
	q.write(strconv.Quote("mixed \"quote\" \\ \n\t é 日本 ​ \U0001F600 \x00"))
	fmt.Printf("quote %d %016x\n", count, q.h)

	j := newFnv()
	for r := rune(0); r <= utf8.MaxRune; r++ {
		if r >= 0xD800 && r <= 0xDFFF {
			continue
		}
		b, _ := json.Marshal(string(r))
		j.write(string(b))
	}
	fmt.Printf("json %d %016x\n", count, j.h)

	s := newFnv()
	cases := 0
	sortCases(func(k int, items []item) {
		sort.Slice(items, func(a, b int) bool { return items[a].key < items[b].key })
		var sb strings.Builder
		for _, it := range items {
			sb.WriteString(strconv.Itoa(it.id))
			sb.WriteByte(',')
		}
		sb.WriteByte(';')
		s.write(sb.String())
		cases++
	})
	fmt.Printf("sort %d %016x\n", cases, s.h)
}
