# demesne-cli

The `demesne` command line: validate a spec, emit its SQL and TypeScript, and check it against a live Postgres (`introspect`, `scaffold`, `check`, `diff`, `coverage`).

```
cargo install demesne-cli
demesne validate authz.demesne
demesne emit authz.demesne all
```

Prebuilt binaries are on the GitHub releases page and in the `@foir/demesne-cli` npm package.

Part of [demesne](https://github.com/foir-io/demesne).
