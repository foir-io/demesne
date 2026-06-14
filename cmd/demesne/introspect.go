package main

import (
	"database/sql"

	demesne "github.com/eidestudio/demesne"
	_ "github.com/jackc/pgx/v5/stdlib" // database/sql driver "pgx"
)

type introspectMeta struct{ tables, columns, fks int }

// introspect reads the target database's public schema (columns + foreign keys)
// into the engine's plain-data Schema. This is the ONLY place the CLI touches a
// database; the engine itself stays pure.
func introspect(dsn string) (*demesne.Schema, introspectMeta, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, introspectMeta{}, err
	}
	defer db.Close()

	sc := demesne.NewSchema()
	var meta introspectMeta
	tset := map[string]bool{}

	cols, err := db.Query(`
		SELECT table_name, column_name, data_type, (is_nullable = 'YES')
		FROM information_schema.columns WHERE table_schema = 'public'`)
	if err != nil {
		return nil, introspectMeta{}, err
	}
	for cols.Next() {
		var table, col, typ string
		var nullable bool
		if err := cols.Scan(&table, &col, &typ, &nullable); err != nil {
			cols.Close()
			return nil, introspectMeta{}, err
		}
		sc.AddColumn(table, col, typ, nullable)
		meta.columns++
		tset[table] = true
	}
	cols.Close()
	if err := cols.Err(); err != nil {
		return nil, introspectMeta{}, err
	}
	meta.tables = len(tset)

	fks, err := db.Query(`
		SELECT tc.table_name, kcu.column_name, ccu.table_name, ccu.column_name
		FROM information_schema.table_constraints tc
		JOIN information_schema.key_column_usage kcu
		  ON tc.constraint_name = kcu.constraint_name AND tc.table_schema = kcu.table_schema
		JOIN information_schema.constraint_column_usage ccu
		  ON tc.constraint_name = ccu.constraint_name
		WHERE tc.constraint_type = 'FOREIGN KEY' AND tc.table_schema = 'public'`)
	if err != nil {
		return nil, introspectMeta{}, err
	}
	for fks.Next() {
		var table, col, refTable, refCol string
		if err := fks.Scan(&table, &col, &refTable, &refCol); err != nil {
			fks.Close()
			return nil, introspectMeta{}, err
		}
		sc.AddForeignKey(table, col, refTable, refCol)
		meta.fks++
	}
	fks.Close()
	if err := fks.Err(); err != nil {
		return nil, introspectMeta{}, err
	}
	return sc, meta, nil
}

// livePolicySurface returns the set of "<table>.<policy>" RLS policies live on the
// given governed tables (for the diff surface check).
func livePolicySurface(dsn string, governed []string) (map[string]bool, error) {
	tset := map[string]bool{}
	for _, t := range governed {
		tset[t] = true
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query(`SELECT tablename, policyname FROM pg_policies WHERE schemaname = 'public'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var table, pol string
		if err := rows.Scan(&table, &pol); err != nil {
			return nil, err
		}
		if tset[table] {
			out[table+"."+pol] = true
		}
	}
	return out, rows.Err()
}
