// Demesne — the reusable RLS-compiled ReBAC + topology authorization engine.
//
// Borrow Zanzibar's declarative schema; reject its runtime. Demesne compiles one
// platform-agnostic spec (the §8.2 grammar) into BOTH a Postgres RLS policy set
// (Layer 1 — row reachability, the moat: authorization lives in the database)
// and a Go policy-decision point (Layer 2 — verb capability), plus the JWT
// claims contract and the SECURITY DEFINER kernel the policies call.
//
// This module is PURE: standard library only, no platform dependencies. A
// platform's actual spec, the generated migrations, and the differential-
// equivalence oracle (generated == live pg_policies/pg_proc) live in the
// platform repo, where the database is — verification belongs where it can run.
module github.com/foir-io/demesne

go 1.26.1
