package demesne

import (
	"fmt"
	"strconv"
)

type Consistency interface {
	isConsistency()

	Level() ConsistencyLevel
}

type ConsistencyLevel int

const (
	LevelMinimizeLatency ConsistencyLevel = iota
	LevelAtLeastAsFresh
	LevelFullyConsistent
)

type minimizeLatency struct{}
type atLeastAsFresh struct{ z Zookie }
type fullyConsistent struct{}

func (minimizeLatency) isConsistency() {}
func (atLeastAsFresh) isConsistency()  {}
func (fullyConsistent) isConsistency() {}

func (minimizeLatency) Level() ConsistencyLevel { return LevelMinimizeLatency }
func (atLeastAsFresh) Level() ConsistencyLevel  { return LevelAtLeastAsFresh }
func (fullyConsistent) Level() ConsistencyLevel { return LevelFullyConsistent }

func MinimizeLatency() Consistency { return minimizeLatency{} }

func AtLeastAsFresh(z Zookie) Consistency { return atLeastAsFresh{z: z} }

func FullyConsistent() Consistency { return fullyConsistent{} }

type Zookie struct{ xid uint64 }

func ZookieFromXid(x uint64) Zookie { return Zookie{xid: x} }

func (z Zookie) String() string { return strconv.FormatUint(z.xid, 10) }

func ParseZookie(s string) (Zookie, error) {
	x, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return Zookie{}, fmt.Errorf("invalid zookie %q: %w", s, err)
	}
	return Zookie{xid: x}, nil
}

func (watermark Zookie) Reflects(writer Zookie) bool { return watermark.xid > writer.xid }

func ZookieNowSQL() string { return "SELECT pg_current_xact_id()::text" }

type AffordanceHint int

const (
	HintUnknown AffordanceHint = iota
	HintLikely
	HintUnlikely
)

type Freshness int

const (
	FreshnessUnknown Freshness = iota
	Stale
	CaughtUp
	FloorBacked
)

type AffordanceSource int

const (
	SourceAsyncIndex AffordanceSource = iota
	SourceFloor
)

type RenderHint bool

type Affordance struct {
	Hint      AffordanceHint
	AsOf      Zookie
	Freshness Freshness
	Source    AffordanceSource
}

func (a Affordance) Render() RenderHint { return RenderHint(a.Hint == HintLikely) }

func ComposeAffordance(allowed bool, asOf Zookie, c Consistency) Affordance {
	hint := HintUnlikely
	if allowed {
		hint = HintLikely
	}
	if alf, ok := c.(atLeastAsFresh); ok {
		if !asOf.Reflects(alf.z) {

			return Affordance{Hint: HintUnknown, AsOf: asOf, Freshness: Stale, Source: SourceAsyncIndex}
		}
		return Affordance{Hint: hint, AsOf: asOf, Freshness: CaughtUp, Source: SourceAsyncIndex}
	}
	return Affordance{Hint: hint, AsOf: asOf, Freshness: FreshnessUnknown, Source: SourceAsyncIndex}
}
