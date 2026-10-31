# SiglusSS Support

VS Code extension for SiglusSceneScript powered by `siglus-ssu` (https://github.com/Jirehlov/SiglusSceneScriptUtility).

## Features

- Starts `siglus-ssu -lsp` for `.ss` and `.inc`
- Lets you select a const profile by number from a clickable status bar item, with automatic language-server restart
- Uses the language server for diagnostics, completion, hover, go to definition, references, rename, document symbols, and semantic tokens
- Uses `siglus-ssu` textmap semantics to classify strings so dialogue and speaker-name text can be colored separately from other strings
- Highlights unused macros/declarations with a dimmed italic semantic-token style when the language server reports them
- Highlights precise read-flag fragments with separate read/unread backgrounds from the selected `read.sav`, without changing text colors
- Jumps to the current scene's first unread flag from the scene editor's context menu
- Controls read flags mode and save selection from a single status bar menu, keeping the selected save path when the mode is off
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

## Read flags mode

Requires a `siglus-ssu` build with `--read-sav` and `siglusReadFlags` protocol version `1` support. Read flags mode is off by default. Open the game's source project, select its const profile, then click the **Read Flags** status item and choose **Enable Read Flags Mode**. If no save has been selected, enabling the mode asks for the game's `read.sav` first; cancelling leaves the mode off. A previously selected save is reused when the mode is enabled again.

Click the **Read Flags** status item and choose **Select Read Save...** to select or replace the save at any time. You can also set `siglusSS.readSavPath` directly. Selecting a save does not toggle the mode or move the cursor. The extension saves the path to workspace settings, or user settings when no workspace is open. Changing the save restarts the server only while read flags mode is enabled.

Light blue backgrounds indicate flags marked as read; stronger red backgrounds indicate flags not marked as read. These backgrounds cover the exact fragments returned by the compiler, including separate flags on one line and macro source origins. Where read and unread flags overlap, such as one macro call producing several flags, the background is violet. Hover the fragment to see the individual flag indices and states. Text colors are unchanged. You can customize `siglusSS.readFlagBackground`, `siglusSS.unreadFlagBackground`, and `siglusSS.mixedFlagBackground` through `workbench.colorCustomizations`.

The status bar shows read/total counts or a mapping error. Scene names and flag counts must match the save before backgrounds are applied. A mismatch, unavailable save, or source analysis error clears the backgrounds instead of applying incompatible states. Scenes absent from the save have no saved-state backgrounds; the engine initializes those scenes as unread. A zero-valued saved flag means not marked as read and does not prove the player has never seen the content.

With read flags mode enabled, right-click in a scene editor and select **SiglusSS: Go to First Unread Flag**. This navigation action is available only in the editor's context menu. Each jump reads the save again and selects the lowest-numbered unread flag in the entire current scene, regardless of the cursor position. A flag with several source fragments jumps to its earliest fragment. If the first unread flag has no precise source location, the extension reports that flag without substituting a later one. All-read scenes and incompatible saved data are reported without moving the cursor.

The **Read Flags** status menu provides **Enable Read Flags Mode** or **Disable Read Flags Mode**, plus **Select Read Save...**. Mode controls and save selection are not placed in the editor context menu or Command Palette. Disabling the mode immediately clears backgrounds and pending flag requests, keeps the selected save path, and restarts the language server without `--read-sav`. Saved-flag analysis, counts, hover details, and navigation are disabled together. Diagnostics, completion, and other normal language-server features work with the mode off. Enabling the mode restarts the server with the selected save and restores all read-flag features together. The mode is saved to workspace settings, or user settings when no workspace is open, and can also be changed through `siglusSS.readFlagsMode`.

While the mode is enabled, backgrounds refresh when you edit a Siglus source file, change visible editors, return focus to VS Code, or change the selected save file on disk. Run **SiglusSS: Refresh Read Flags** to refresh manually. Old document versions and cancelled requests cannot restore stale highlights or move the cursor. An existing `--read-sav PATH` in `siglusSS.serverExtraArgs` is honored only while the mode is enabled and `siglusSS.readSavPath` is empty; a selected path overrides that argument. Disabling the mode also suppresses the extra argument without deleting it.

`siglusSS.readSavPath` supports `${workspaceFolder}`, `${workspaceFolderBasename}`, `${userHome}`, `${env:NAME}`, and `~`. Relative paths are resolved against the workspace directory. One server and one selected save are shared by all folders in a multi-folder workspace. Original source and decompiled source can have different flag counts; a source count mismatch is reported explicitly.

## Settings

- `siglusSS.siglusSsuPath`
- `siglusSS.serverExtraArgs`
- `siglusSS.constProfile` (profile number, or `null` to use the legacy argument/server default)
- `siglusSS.readFlagsMode` (enable or disable all read-flag features; off by default)
- `siglusSS.readSavPath` (selected `read.sav` path, retained when the mode is off; an empty path uses the extra argument only while the mode is on)
- `siglusSS.autoUpdateSiglusSsu`

`siglusSS.siglusSsuPath` examples:

- `siglus-ssu`
- `C:\Python312\Scripts\siglus-ssu.exe`

## Development

```bash
npm install
npm run compile
```
