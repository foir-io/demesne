# Demesne — VS Code language support

Syntax highlighting and live validation for Demesne authorization specs (`.demesne`).

## Live validation

The extension runs demesne's compiler, built to WebAssembly from `crates/wasm`, inside VS
Code, with no CLI and no network. It checks an open spec as you type, after a 200 ms pause:

- Every parse and validation error is underlined on the line it names, with the same
  wording `demesne validate` prints.
- A valid spec shows the warnings the CLI prints, such as a `blind` write that the select
  permission can't reach.
- An error that names no line sits on the first line.

A spec written in several files is checked as one when the `demesne.specs` setting lists
its files, in order, relative to the workspace folder:

```json
"demesne.specs": [["authz/core.demesne", "authz/extra.demesne"]]
```

A file in such a list is checked together with the others, using the editor's text for an
open file and the saved file otherwise, and each finding shows in the file it names. A file
in no list is checked on its own.

Highlights: top-level blocks (`topology`, `vocabulary`, `subject`, `object`,
`template`, `procedures`, `ungoverned`, `fieldscopes`, `rolestore`, `grant`,
`claims`, `definers`, `tables`); clause keywords; `@`-prefixed terms
(`@rls`, `@pdp`, `@scoped`, `@session`, `@app_scope`, `@store_manage`, `@kind`, `@claim`, …);
`via <repr>` relation kinds (`role`/`edge`/`grant`/`closure`/`group`/`object`/`memberin`);
permission/scope keys (`content:write`, `records:read:*`); operators (`->`, `+`, `|`,
`>=`, `*`); strings and `//` comments.

## Install (local / unpublished)

Build the compiler's WebAssembly first. It needs the Rust toolchain and the `wasm-bindgen`
version `Cargo.lock` pins:

```sh
cd editors/vscode && npm run build:wasm
# symlink (or copy) into your VS Code extensions dir, then reload VS Code
ln -s "$PWD" ~/.vscode/extensions/demesne-0.1.0
```

Or package with [`vsce`](https://github.com/microsoft/vscode-vsce):

```sh
cd editors/vscode && npx @vscode/vsce package   # → demesne-0.1.0.vsix
code --install-extension demesne-0.1.0.vsix
```

## Tests

- `npm test` runs the validation and the diagnostics logic in Node, against the real
  WebAssembly build and a stand-in for the VS Code API.
- `npm run test:vscode` opens an invalid spec in a real VS Code and checks its diagnostics,
  then edits the spec and checks they follow. CI runs it under `xvfb`.

## Files

- `package.json` — extension manifest (language + grammar contribution).
- `extension.js` — checks open `.demesne` documents and publishes their diagnostics.
- `lint.js` — runs the compiler's `diagnostics` export over a document's text, and its
  `diagnostics_files` export over the files of a spec in several files.
- `language-configuration.json` — comments, brackets, auto-closing pairs.
- `syntaxes/demesne.tmLanguage.json` — the TextMate grammar.
