# READY FOR REAL WINDOWS TEST — ZDECHLAK 1.0.3 → 1.0.4

## What this tests
Automatic update of **both OTC client and launcher** from 1.0.3 → 1.0.4 over real HTTPS,
using an **isolated test channel**. Your stable install is not touched.

## What this does NOT do
- Does **not** change stable `/updates/v2` (still 1.0.3)
- Does **not** force-update your normal 1.0.3 folder
- Does **not** delete GitHub release v1.0.3
- Does **not** modify the game server

## Why a test bootstrap?
The official v1.0.3 package is hard-wired to stable `updates/v2` + channel `prototype`.
It cannot select the test channel. This bootstrap is a **separate copy** of a 1.0.3 install
configured only for:
`https://raw.githubusercontent.com/wojewodzki12/zdechlak-client/updates/v1-test-104`

## Download
https://github.com/wojewodzki12/zdechlak-client/releases/tag/v1.0.4-test

Asset: `ZDECHLAK-OTC-1.0.3-to-1.0.4-TEST-BOOTSTRAP.zip`

## Exact Windows steps

1. Create a **new** folder, e.g. `C:\ZDECHLAK-TEST-104\`
   (Do not unpack into your stable ZDECHLAK folder.)

2. Extract the TEST BOOTSTRAP zip into that folder.
   You should see `ZDECHLAK Launcher.exe` and `TEST-README.txt`.

3. Confirm baseline before updating:
   - Open `runtime\releases\<active>\update-marker.txt`
   - It should say: `ZDECHLAK-UPDATE-1.0.3`
   - Open `runtime\launcher-state.json` → `"version": "1.0.3"`

4. Optional profile marker (already included):
   - Keep `TEST-PROFILE-MARKER.txt` (`keep-me`)
   - Keep `userdata-sim\bot-profile.cfg` and `hotkeys.cfg`

5. Run: `ZDECHLAK Launcher.exe`
   - Wait for update check / download / launcher self-update
   - If the window closes once for launcher replace, that is expected; it should relaunch

6. Verify success:
   - `runtime\releases\<new-active>\update-marker.txt` = `ZDECHLAK-UPDATE-1.0.4`
   - `runtime\releases\<new-active>\build-info.json` → `"version": "1.0.4"`
   - `runtime\launcher-state.json` → `"version": "1.0.4"`
   - Launcher window title shows `ZDECHLAK OTC 1.0.4` (after self-update)
   - `TEST-PROFILE-MARKER.txt` still contains `keep-me`
   - Previous release folder still exists under `runtime\releases\` (rollback safety)

7. Confirm game target unchanged:
   - `build-info.json` still has host `146.59.52.154`, login_port `7171`, protocol `860`
   - Log into the server from the updated client

8. Optional offline verify:
   ```
   ZDECHLAK Launcher.exe --cli --offline --check-only
   ```

## Pass / fail
PASS = markers show 1.0.4 for client + launcher, profile marker preserved, login still works.
FAIL = still 1.0.3 after relaunch, missing DLL, or profile marker gone.

## Cleanup
Delete `C:\ZDECHLAK-TEST-104\` when finished. Stable install stays as-is.
