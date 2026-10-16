@echo off
rem Launch the recompiled Tekken 3 (builds first if needed; the first build takes a while).
rem The disc image defaults to E:\Decompilation\Game\Tekken 3 (USA).cue (all three tracks:
rem tracks 2 and 3 are CD audio); set T3_DISC to use another .cue.
rem The memory card is saved to rust\memcard\slot1.mcd.
rem (No parenthesized blocks below: the ")" in "(USA)" would end them early.)
setlocal
if not defined T3_DISC set "T3_DISC=E:\Decompilation\Game\Tekken 3 (USA).cue"
if exist "%T3_DISC%" goto disc_ok
echo Disc image not found: "%T3_DISC%"
echo Set T3_DISC to the path of the Tekken 3 .cue file.
pause
exit /b 1
:disc_ok
cd /d "%~dp0"
if exist "rust\Cargo.toml" goto generated
echo Generating the Rust code from the sheets...
python tools\gen_rust.py
if errorlevel 1 goto failed
:generated
cd /d "%~dp0rust"
cargo run -p t3-bevy %*
if errorlevel 1 goto failed
exit /b 0
:failed
pause
exit /b 1
