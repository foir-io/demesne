package demesne

import (
	"strings"
	"testing"
)

func TestAffordance_ComposeMapping(t *testing.T) {
	wm := ZookieFromXid(100)

	a := ComposeAffordance(true, wm, MinimizeLatency())
	if a.Hint != HintLikely || a.Source != SourceAsyncIndex || a.Freshness != FreshnessUnknown {
		t.Errorf("MinimizeLatency allowed: %+v", a)
	}
	if a := ComposeAffordance(false, wm, MinimizeLatency()); a.Hint != HintUnlikely {
		t.Errorf("MinimizeLatency not-allowed must be HintUnlikely: %+v", a)
	}

	if a := ComposeAffordance(true, wm, AtLeastAsFresh(ZookieFromXid(50))); a.Hint != HintLikely || a.Freshness != CaughtUp {
		t.Errorf("AtLeastAsFresh fresh: %+v", a)
	}

	for _, z := range []uint64{100, 150} {
		a := ComposeAffordance(true, wm, AtLeastAsFresh(ZookieFromXid(z)))
		if a.Hint != HintUnknown || a.Freshness != Stale {
			t.Errorf("AtLeastAsFresh stale (z=%d) must be Unknown/Stale, got %+v", z, a)
		}
	}
}

func TestZookie_ReflectsAndRoundTrip(t *testing.T) {

	if !ZookieFromXid(101).Reflects(ZookieFromXid(100)) {
		t.Error("watermark 101 must reflect writer 100")
	}
	if ZookieFromXid(100).Reflects(ZookieFromXid(100)) {
		t.Error("watermark 100 must NOT reflect writer 100 (strict)")
	}
	if ZookieFromXid(99).Reflects(ZookieFromXid(100)) {
		t.Error("watermark 99 must NOT reflect writer 100")
	}
	z, err := ParseZookie(ZookieFromXid(42).String())
	if err != nil || z != ZookieFromXid(42) {
		t.Errorf("round-trip: %v %v", z, err)
	}
	if _, err := ParseZookie("not-a-number"); err == nil {
		t.Error("ParseZookie must reject a non-numeric token")
	}
}

func TestAffordance_RenderIsNotBool(t *testing.T) {
	var rh RenderHint = Affordance{Hint: HintLikely}.Render()
	if rh != RenderHint(true) {
		t.Error("HintLikely must render true")
	}
	if (Affordance{Hint: HintUnlikely}).Render() != RenderHint(false) {
		t.Error("HintUnlikely must render false")
	}
	if (Affordance{Hint: HintUnknown}).Render() != RenderHint(false) {
		t.Error("HintUnknown must render false (don't optimistically show on no answer)")
	}
}

func TestAsyncCheckSQL_EmitsForAsyncObjectOnly(t *testing.T) {
	s, err := Parse(asyncGrantSpec)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	surf, err := s.EmitAppSurface()
	if err != nil {
		t.Fatalf("emit app surface: %v", err)
	}
	o, _ := surf.Object("doc")
	for _, want := range []string{"auth.docs_grantee_async_affordance($1, 'customer'", "customer_id", "as_of::text"} {
		if !strings.Contains(o.AsyncCheckSQL, want) {
			t.Errorf("AsyncCheckSQL missing %q; got %q", want, o.AsyncCheckSQL)
		}
	}

	plain, _ := Parse(strings.Replace(asyncGrantSpec, `"doc" tracked async`, `"doc"`, 1))
	psurf, _ := plain.EmitAppSurface()
	po, _ := psurf.Object("doc")
	if po.AsyncCheckSQL != "" {
		t.Errorf("non-async object must have empty AsyncCheckSQL, got %q", po.AsyncCheckSQL)
	}
}
