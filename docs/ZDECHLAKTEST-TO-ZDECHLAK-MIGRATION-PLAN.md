# Migration plan: ZDECHLAKTEST → ZDECHLAK

**Do not run this migration without explicit user approval.**

## Goal

Move isolated test profiles from `%APPDATA%\ZDECHLAKTEST\` to the future production root `%APPDATA%\ZDECHLAK\` (or the final PHYSFS layout chosen for production), without losing bot configs or settings.

## Preconditions

1. Explicit operator approval in writing for this chat/task.
2. Stable package already shipping `APP_NAME` / launcher config for `ZDECHLAK` (not TEST).
3. Backup created successfully.
4. Rollback drill verified on a throwaway copy.

## Backup

1. Quit all ZDECHLAK / OTC processes.
2. Copy recursively:

```text
%APPDATA%\ZDECHLAKTEST\  →  %APPDATA%\ZDECHLAKTEST-backup-<UTC-timestamp>\
```

3. Record SHA256 of a zip of that backup.
4. If `%APPDATA%\ZDECHLAK\` already exists, also back it up before any write.

## Migration steps (proposed)

1. Create `%APPDATA%\ZDECHLAK\` if missing.
2. Copy (not move) from `ZDECHLAKTEST` into the production layout expected by the new `APP_NAME` / launcher junction.
3. Launch new client once; confirm `config.otml`, hotkeys, `/bot`, `/settings` load.
4. Only after confirmation, optionally rename `ZDECHLAKTEST` to `ZDECHLAKTEST-migrated-<timestamp>`.

## Rollback

1. Quit client.
2. Restore from `ZDECHLAKTEST-backup-<timestamp>` (and previous `ZDECHLAK` backup if production dir was modified).
3. Reinstall / point launcher at the last known-good package.
4. Confirm markers and a bot profile file match the backup hashes.

## Non-goals

- No silent migration on first start.
- No deletion of `ZDECHLAKTEST` without backup + approval.
- No changes to other OTC AppData trees.
