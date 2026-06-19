package demesne

import (
	"fmt"
	"strconv"
)

// Async-affordance runtime types (WS4, EID-345) — the consistency choice, the zookie, and the
// AFFORDANCE-TYPED return. These are the call-site half of the fail-closed asymmetry (the V12
// validator is the floor half): a cached authorization HINT is a different Go type than an
// enforcement Decision, with NO bare bool and no conversion between them, so a cached "yes"
// can never be coerced into an enforcement Allow. FullyConsistent is the only compliance
// answer and runs the floor (PointCheckSQL / ComposeCan), unchanged.

// Consistency selects an affordance read's freshness/latency tradeoff. It is a closed sum (the
// unexported marker method) so callers must use the constructors:
//   - MinimizeLatency: read the async cache, return whatever it has (+ its as-of).
//   - AtLeastAsFresh(z): answer from the cache iff it reflects everything committed up to z,
//     else the caller falls back to the floor (fail-closed).
//   - FullyConsistent: the floor — the only compliance answer (CheckSQL / PointCheckSQL).
type Consistency interface{ isConsistency() }

type minimizeLatency struct{}
type atLeastAsFresh struct{ z Zookie }
type fullyConsistent struct{}

func (minimizeLatency) isConsistency() {}
func (atLeastAsFresh) isConsistency()  {}
func (fullyConsistent) isConsistency() {}

// MinimizeLatency reads the async cache and returns its current hint + as-of, no floor round-trip.
func MinimizeLatency() Consistency { return minimizeLatency{} }

// AtLeastAsFresh answers from the cache only if it reflects everything committed up to z.
func AtLeastAsFresh(z Zookie) Consistency { return atLeastAsFresh{z: z} }

// FullyConsistent is the floor — the only compliance answer.
func FullyConsistent() Consistency { return fullyConsistent{} }

// Zookie is an opaque freshness token — a Postgres transaction id (xid8) watermark. A writer
// gets its own zookie from its grant (the write's pg_current_xact_id); a reader passes it to
// AtLeastAsFresh. It is a transaction id, NOT the changelog seq, because freshness is about
// commit SETTLEMENT ("the cache reflects everything committed before T") — which a seq, that
// commits out of order and gaps on rollback, cannot express.
type Zookie struct{ xid uint64 }

// ZookieFromXid builds a zookie from a raw transaction id.
func ZookieFromXid(x uint64) Zookie { return Zookie{xid: x} }

// String encodes the zookie for transport (the opaque token a caller round-trips).
func (z Zookie) String() string { return strconv.FormatUint(z.xid, 10) }

// ParseZookie decodes a transported zookie (e.g. the as_of text an affordance read returns).
func ParseZookie(s string) (Zookie, error) {
	x, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return Zookie{}, fmt.Errorf("invalid zookie %q: %w", s, err)
	}
	return Zookie{xid: x}, nil
}

// Reflects reports whether a cache at this watermark reflects a write at `writer` — i.e. the
// writer's transaction has settled below the cache's commit horizon (strict: horizon > writer,
// matching the _apply contract that applied_horizon excludes still-in-flight transactions).
func (watermark Zookie) Reflects(writer Zookie) bool { return watermark.xid > writer.xid }

// ZookieNowSQL mints the current transaction-id head — what a writer reads to get a zookie for
// its own just-committed write (read-your-writes), or a caller uses as "now".
func ZookieNowSQL() string { return "SELECT pg_current_xact_id()::text" }

// AffordanceHint is a deliberately non-enforcement vocabulary (Likely/Unlikely/Unknown, never
// Allow/Deny), so enforcement habits (`if h == Allow`) do not compile against an affordance.
type AffordanceHint int

const (
	HintUnknown  AffordanceHint = iota // cache cold / behind the requested zookie / no answer
	HintLikely                         // the cache shows the grant — render optimistically
	HintUnlikely                       // the cache shows no grant
)

// Freshness records how a hint relates to the requested consistency.
type Freshness int

const (
	FreshnessUnknown Freshness = iota
	Stale                      // cache behind the requested zookie → the caller must use the floor
	CaughtUp                   // cache reflects the requested zookie
	FloorBacked                // the answer came from the floor fallback (authoritative)
)

// AffordanceSource is provenance for audit — proving an enforcement decision was never async.
type AffordanceSource int

const (
	SourceAsyncIndex AffordanceSource = iota
	SourceFloor
)

// RenderHint is a UI render decision derived from an Affordance. It is a DEFINED type, not
// `bool`, so it is NOT assignable to a bool parameter (e.g. ComposeCan's pointAllow) without an
// explicit, lint-visible conversion — the structural firewall (adversary must-fix #1) that
// stops a cached hint from being coerced into an enforcement Allow.
type RenderHint bool

// Affordance is the result of a CACHED authorization HINT — never an enforcement decision. It
// is structurally disjoint from Decision (runtime.go): no Allowed bool, no conversion to
// Decision, and its only render accessor returns RenderHint, not bool. So a compliance /
// enforcement code path that consumes Decision cannot, at compile time, be handed an
// Affordance, and ComposeCan's bare-bool pointAllow cannot be fed Affordance.Render().
type Affordance struct {
	Hint      AffordanceHint
	AsOf      Zookie
	Freshness Freshness
	Source    AffordanceSource
}

// Render is the only accessor yielding a render decision, and it returns RenderHint (a defined
// type, not bool) so it cannot be passed where an enforcement bool is expected.
func (a Affordance) Render() RenderHint { return RenderHint(a.Hint == HintLikely) }

// ComposeAffordance maps a raw async-index read (allowed, the cache's as-of watermark) under a
// requested consistency into an Affordance. It is a PURE mapping (no DB, no policy) — the
// affordance sibling of ComposeCan. For AtLeastAsFresh, a cache behind the requested zookie
// yields Hint=Unknown / Freshness=Stale: the caller must fall back to the floor (the engine
// returns the builders; the consumer orchestrates the fallback and stamps Source=SourceFloor /
// Freshness=FloorBacked). FullyConsistent never reaches here — it is the Decision path.
func ComposeAffordance(allowed bool, asOf Zookie, c Consistency) Affordance {
	hint := HintUnlikely
	if allowed {
		hint = HintLikely
	}
	if alf, ok := c.(atLeastAsFresh); ok {
		if !asOf.Reflects(alf.z) {
			// The cache has NOT caught up to the requested zookie — do not answer from it.
			return Affordance{Hint: HintUnknown, AsOf: asOf, Freshness: Stale, Source: SourceAsyncIndex}
		}
		return Affordance{Hint: hint, AsOf: asOf, Freshness: CaughtUp, Source: SourceAsyncIndex}
	}
	return Affordance{Hint: hint, AsOf: asOf, Freshness: FreshnessUnknown, Source: SourceAsyncIndex}
}
