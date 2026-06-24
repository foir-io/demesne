module github.com/foir-io/demesne/cmd/demesne

go 1.26.1

require (
	github.com/foir-io/demesne v0.59.0
	github.com/foir-io/demesne/pgx v0.0.0
	github.com/jackc/pgx/v5 v5.9.1
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/sync v0.17.0 // indirect
	golang.org/x/text v0.29.0 // indirect
)

replace github.com/foir-io/demesne => ../..

replace github.com/foir-io/demesne/pgx => ../../pgx
