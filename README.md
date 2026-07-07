# SiglusSS Support

VS Code extension for SiglusSceneScript powered by `siglus-ssu` (https://github.com/Jirehlov/SiglusSceneScriptUtility).

## Features

- Starts `siglus-ssu -lsp` for `.ss` and `.inc`
- Uses the language server for diagnostics, completion, hover, go to definition, references, rename, document symbols, and semantic tokens
- Uses `siglus-ssu` textmap semantics to classify strings so dialogue and speaker-name text can be colored separately from other strings
- Highlights unused macros/declarations with a dimmed italic semantic-token style when the language server reports them
- Shows `siglus-ssu` language-server startup, cache loading, semantic highlighting, current-file symbol loading, and project scan progress in VS Code
- Reopens Siglus files with the detected source encoding so the editor does not get stuck on the wrong decode path
- Lets you point the extension at either a custom `siglus-ssu` executable path or a repository root; when the setting is a directory, the extension runs `uv run siglus-ssu` in that directory. If you leave the setting alone, it uses the `siglus-ssu` command from PATH, which matches a typical pip install
- Prompts you to install and initialize `siglus-ssu`, with notification progress, when the language server command is not available
- Checks PyPI for `siglus-ssu` updates after the language server starts and prompts before installing an available update

## Settings

- `siglusSS.siglusSsuPath`
- `siglusSS.serverExtraArgs`
- `siglusSS.autoUpdateSiglusSsu`

`siglusSS.siglusSsuPath` examples:

- `siglus-ssu`
- `C:\Python312\Scripts\siglus-ssu.exe`

## Development

```bash
npm install
npm run compile
```
