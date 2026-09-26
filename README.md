# SiglusSS Support

VS Code extension for SiglusSceneScript powered by `siglus-ssu` (https://github.com/Jirehlov/SiglusSceneScriptUtility).

## Features

- Starts `siglus-ssu -lsp` for `.ss` and `.inc`
- Lets you select a const profile by number from a clickable status bar item, with automatic language-server restart
- Uses the language server for diagnostics, completion, hover, go to definition, references, rename, document symbols, and semantic tokens
- Uses `siglus-ssu` textmap semantics to classify strings so dialogue and speaker-name text can be colored separately from other strings
- Highlights unused macros/declarations with a dimmed italic semantic-token style when the language server reports them
- Shows `siglus-ssu` language-server startup, cache loading, semantic highlighting, current-file symbol loading, and project scan progress in VS Code
- Reopens Siglus files with the detected source encoding so the editor does not get stuck on the wrong decode path
- Lets you point the extension at either a custom `siglus-ssu` executable path or a repository root; when the setting is a directory, the extension runs `uv run siglus-ssu` in that directory. If you leave the setting alone, it uses the `siglus-ssu` command from PATH, which matches a typical pip install
- Prompts you to install `siglus-ssu`, with notification progress, when the language server command is not available
- Checks PyPI for `siglus-ssu` updates after the language server starts and prompts before installing an available update

## Select a const profile

1. Open a SiglusSS `.ss` or `.inc` file.
2. Click **SiglusSS: Profile 0** in the status bar (it shows the current profile number).
3. Choose a profile number. The current selection is marked **Current**.

The extension saves the choice to workspace settings and restarts the language server automatically. With no workspace open, it saves to user settings. A workspace with multiple folders shares one language server and one profile. Switching profiles does not change your script files.

You can also run **SiglusSS: Select Const Profile** from the Command Palette or enter a number in **SiglusSS > Const Profile** in Settings. Each time the selector opens, it reads the accepted numbers from the configured `siglus-ssu` command's existing argument validation (`--const-profile -1 --version`) and the default number from `--help`. This works with the existing CLI without changes to `siglus-ssu`. The extension does not assign profile names, assume consecutive numbers, or maintain a fixed list. Added and removed profiles follow the installed CLI's accepted-number list. A removed selection is reported as unavailable and is left for you to change.

If the CLI's output cannot be recognized, the selector reports the error without substituting a built-in list. You can still enter a profile number in Settings or use the server's default. If the default number cannot be read, the extension leaves it to the server instead of guessing a number.

Existing `--const-profile N` and `--const-profile=N` entries in `siglusSS.serverExtraArgs` remain effective until `siglusSS.constProfile` is set to a number. An explicit number takes precedence, and the extension passes only one effective profile argument. Leave the setting unset or use `null` to use the legacy argument or the server's default. Other extra arguments are preserved.

## Settings

- `siglusSS.siglusSsuPath`
- `siglusSS.serverExtraArgs`
- `siglusSS.constProfile` (profile number, or `null` to use the legacy argument/server default)
- `siglusSS.autoUpdateSiglusSsu`

`siglusSS.siglusSsuPath` examples:

- `siglus-ssu`
- `C:\Python312\Scripts\siglus-ssu.exe`

## Development

```bash
npm install
npm run compile
```
