# Demesne — VS Code language support

Syntax highlighting for Demesne authorization specs (`.demesne`).

Highlights: top-level blocks (`topology`, `vocabulary`, `subject`, `object`,
`template`, `procedures`, `ungoverned`, `fieldscopes`, `rolestore`, `grant`,
`claims`, `definers`, `tables`); clause keywords; `@`-prefixed terms
(`@rls`, `@pdp`, `@scoped`, `@session`, `@app_scope`, `@store_manage`, `@kind`, …);
`via <repr>` relation kinds (`role`/`edge`/`grant`/`closure`/`group`/`object`/`memberin`);
permission/scope keys (`content:write`, `records:read:*`); operators (`->`, `+`, `|`,
`>=`, `*`); strings and `//` comments.

## Install (local / unpublished)

This is a standard TextMate-grammar extension. No build step.

```sh
# symlink (or copy) into your VS Code extensions dir, then reload VS Code
ln -s "$PWD/editors/vscode" ~/.vscode/extensions/demesne-0.1.0
```

Or package with [`vsce`](https://github.com/microsoft/vscode-vsce):

```sh
cd editors/vscode && npx @vscode/vsce package   # → demesne-0.1.0.vsix
code --install-extension demesne-0.1.0.vsix
```

## Files

- `package.json` — extension manifest (language + grammar contribution).
- `language-configuration.json` — comments, brackets, auto-closing pairs.
- `syntaxes/demesne.tmLanguage.json` — the TextMate grammar.
