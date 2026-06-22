// The demesne CLI is a SEPARATE module so the engine
// (github.com/eidestudio/demesne) stays stdlib-pure: only this CLI links a
// Postgres driver, for the live-database subcommands.
module github.com/eidestudio/demesne/cmd/demesne

go 1.26.1

require (
	github.com/eidestudio/demesne v0.18.0
	github.com/eidestudio/demesne/pgx v0.0.0
	github.com/jackc/pgx/v5 v5.9.1
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/sync v0.17.0 // indirect
	golang.org/x/text v0.29.0 // indirect
)

replace github.com/eidestudio/demesne => ../..

replace github.com/eidestudio/demesne/pgx => ../../pgx
