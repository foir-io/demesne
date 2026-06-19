package demesne

// Async-affordance tier (WS4, EID-345) — naming contract + the floor-asymmetry surface set.
//
// An `async` via-grant relation gains an eventually-consistent affordance INDEX, maintained
// off the changelog and read ONLY by the affordance Check path — NEVER the RLS floor. The
// floor keeps reading the SYNC grant definer; `async` only adds the cache. This file owns the
// single source of the async-surface NAMES so the V12 floor-asymmetry oracle (validate.go)
// and the index emitter (added in the next increment) agree by construction.
//
// Surface, per async relation, all in the definer schema:
//   table  <schema>.<objTable>_<relName>_async            (resource_id, principal_kind, principal_id)
//   fns    <table>_apply / <table>_rebuild / <table>_affordance
// + the shared cursor <schema>._authz_async_cursor.
// Every name shares the <schema>.<objTable>_<relName>_async PREFIX, so that one base token
// substring-matches the whole surface for the asymmetry scan.

// relationIsAsync reports whether a relation carries the `async` affordance-index modifier.
func relationIsAsync(r *Relation) bool {
	g, ok := r.Repr.(ViaGrant)
	return ok && g.Async
}

// asyncIndexBase is the qualified base name for an async relation's surface
// (<schema>.<objTable>_<relName>_async) — a prefix of the table and every fn it emits.
func (s *Spec) asyncIndexBase(objTable, relName string) string {
	return s.definerSchema() + "." + objTable + "_" + relName + "_async"
}

// hasAsync reports whether any relation in the spec is `async`.
func (s *Spec) hasAsync() bool {
	for _, obj := range s.Objects {
		for _, r := range obj.Relations {
			if relationIsAsync(r) {
				return true
			}
		}
	}
	return false
}

// asyncSurfaceTokens returns the qualified base name of every async relation's index surface
// — the tokens the RLS floor must NEVER reference (the V12 floor-asymmetry invariant). Each
// base is a prefix of its table + apply/rebuild/affordance fns, so a substring match on the
// base catches any floor reference to the index or its readers. Empty when no async relation
// exists (so the oracle is a no-op and emission stays byte-identical).
func (s *Spec) asyncSurfaceTokens() []string {
	var toks []string
	for _, obj := range s.Objects {
		for _, r := range obj.Relations {
			if relationIsAsync(r) {
				toks = append(toks, s.asyncIndexBase(obj.Table, r.Name))
			}
		}
	}
	return toks
}
