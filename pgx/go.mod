// The demesne/pgx adapter is a SEPARATE module so the engine stays stdlib-pure: only this
// adapter links pgx. It turns a pgx connection/pool/tx into a demesne.Querier for the
// generated framework (EmitFramework) — the dominant Go Postgres driver, so its adapter
// ships rather than being hand-rewritten by every adopter (EID-371 §3).
module github.com/eidestudio/demesne/pgx

go 1.26.1

require (
	github.com/eidestudio/demesne v0.0.0
	github.com/jackc/pgx/v5 v5.9.1
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	golang.org/x/text v0.29.0 // indirect
)

replace github.com/eidestudio/demesne => ..
