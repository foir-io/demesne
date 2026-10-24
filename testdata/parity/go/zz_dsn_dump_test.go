package main

import (
	"crypto/x509"
	"fmt"
	"os"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var dsnEnvNames = []string{
	"PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD", "PGPASSFILE", "PGAPPNAME", "PGCONNECT_TIMEOUT",
	"PGSSLMODE", "PGSSLKEY", "PGSSLCERT", "PGSSLSNI", "PGSSLROOTCERT", "PGSSLPASSWORD", "PGSSLNEGOTIATION",
	"PGTARGETSESSIONATTRS", "PGSERVICE", "PGSERVICEFILE", "PGTZ", "PGOPTIONS", "PGMINPROTOCOLVERSION", "PGMAXPROTOCOLVERSION",
}

type dsnCase struct {
	name string
	env  [][2]string
	dsn  string
}

func dsnParseCases(text string) []dsnCase {
	var out []dsnCase
	for _, line := range strings.Split(text, "\n") {
		switch {
		case strings.HasPrefix(line, "--- "):
			out = append(out, dsnCase{name: strings.TrimPrefix(line, "--- ")})
		case len(out) == 0 || line == "" || strings.HasPrefix(line, "#"):
		case strings.HasPrefix(line, "env "):
			k, v, _ := strings.Cut(strings.TrimPrefix(line, "env "), "=")
			out[len(out)-1].env = append(out[len(out)-1].env, [2]string{k, v})
		case line == "dsn":
			out[len(out)-1].dsn = ""
		case strings.HasPrefix(line, "dsn "):
			out[len(out)-1].dsn = strings.TrimPrefix(line, "dsn ")
		}
	}
	return out
}

func dsnTLSKind(c *pgconn.FallbackConfig) string {
	t := c.TLSConfig
	if t == nil {
		return fmt.Sprintf("fallback host=%s port=%d tls=none\n", strconv.Quote(c.Host), c.Port)
	}
	kind := "full"
	if t.VerifyPeerCertificate != nil {
		kind = "chain"
	} else if t.InsecureSkipVerify {
		kind = "noverify"
	}
	roots := "system"
	if t.RootCAs != nil {
		sys, err := x509.SystemCertPool()
		if err == nil && t.RootCAs.Equal(sys) {
			roots = "system"
		} else {
			roots = fmt.Sprintf("pem:%d", len(t.RootCAs.Subjects()))
		}
	}
	return fmt.Sprintf("fallback host=%s port=%d tls=%s sni=%s direct=%t roots=%s client=%t\n",
		strconv.Quote(c.Host), c.Port, kind, strconv.Quote(t.ServerName), len(t.NextProtos) > 0, roots, len(t.Certificates) > 0)
}

func dsnDump(dsn string) string {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return "err: " + err.Error() + "\n"
	}
	c := &cfg.Config
	tsa := "Any"
	if c.ValidateConnect != nil {
		name := runtime.FuncForPC(reflect.ValueOf(c.ValidateConnect).Pointer()).Name()
		tsa = strings.TrimPrefix(name[strings.LastIndex(name, ".")+1:], "ValidateConnectTargetSessionAttrs")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "user=%s password=%s database=%s connect_timeout=%d tsa=%s channel_binding=%s min=%s max=%s\n",
		strconv.Quote(c.User), strconv.Quote(c.Password), strconv.Quote(c.Database), int64(c.ConnectTimeout/time.Second),
		tsa, c.ChannelBinding, c.MinProtocolVersion, c.MaxProtocolVersion)
	keys := make([]string, 0, len(c.RuntimeParams))
	for k := range c.RuntimeParams {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "runtime %s=%s\n", k, strconv.Quote(c.RuntimeParams[k]))
	}
	b.WriteString(dsnTLSKind(&pgconn.FallbackConfig{Host: c.Host, Port: c.Port, TLSConfig: c.TLSConfig}))
	for _, f := range c.Fallbacks {
		b.WriteString(dsnTLSKind(f))
	}
	return b.String()
}

func TestZZDSNDump(t *testing.T) {
	casesPath, work, outPath := os.Getenv("DSN_CASES"), os.Getenv("DSN_WORK"), os.Getenv("DSN_OUT")
	if casesPath == "" || work == "" || outPath == "" {
		t.Skip("DSN_CASES, DSN_WORK and DSN_OUT are unset")
	}
	text, err := os.ReadFile(casesPath)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, c := range dsnParseCases(string(text)) {
		for _, n := range dsnEnvNames {
			os.Unsetenv(n)
		}
		os.Setenv("PGPASSFILE", work+"/no-passfile")
		os.Setenv("PGSERVICEFILE", work+"/no-servicefile")
		for _, kv := range c.env {
			os.Setenv(kv[0], kv[1])
		}
		fmt.Fprintf(&b, "--- %s\n%s", c.name, dsnDump(c.dsn))
	}
	if err := os.WriteFile(outPath, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}
