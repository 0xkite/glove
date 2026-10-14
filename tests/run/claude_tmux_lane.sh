#!/usr/bin/env bash
# Stock-tmux frontend lane for the actual admitted Claude executable.
#
# Topology: private tmux server (-S, -f /dev/null, no ambient TMUX) -> pane runs
# native_session_fixture serve (host Glove supervisor) -> owned contained Claude
# generation -> fixture responder. Barriers are tmux wait-for channels and the
# fixture's bounded C++ waits; the only sleeps are single bounded TUI renders.
set -euo pipefail

FIXTURE="$1"; EXECUTABLE="$2"; SHA256="$3"; VERSION="$4"; ROOT="$5"
TMUX_EXE="${TMUX_BIN:-tmux}"
if [ -d "$ROOT" ]; then chmod -R u+w "$ROOT"; rm -rf "$ROOT"; fi; mkdir -p "$ROOT"; chmod 700 "$ROOT"
SOCK="$ROOT/t.sock"; LOG="$ROOT/lane.log"
unset TMUX TMUX_PANE
T() { "$TMUX_EXE" -S "$SOCK" -f /dev/null "$@"; }
log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$LOG"; }
cleanup() { T kill-server 2>/dev/null || true; }
trap cleanup EXIT

log "tmux=$("$TMUX_EXE" -V) fixture=$FIXTURE executable=$EXECUTABLE sha256=$SHA256"

# ---- headless held-stream generation inside a stock pane -------------------
T new-session -d -s lane -x 140 -y 40 \
  "$FIXTURE serve --root $ROOT/s --executable $EXECUTABLE --sha256 $SHA256 --version $VERSION \
     --mode headless --hold-first --release-file $ROOT/release --auto-start --announce $ROOT/announce \
     2>$ROOT/serve.err; echo \$? >$ROOT/serve.exit; $TMUX_EXE -S $SOCK wait-for -S served"
T set-option -t lane remain-on-exit on
log "pane_pid=$(T display -p -t lane '#{pane_pid}') clients=$(T list-clients | wc -l | tr -d ' ')"

"$FIXTURE" wait --announce "$ROOT/announce" --state running --timeout-ms 90000 | tee -a "$LOG"
SESSION=$(sed -n 1p "$ROOT/announce"); EPOCH=$(sed -n 2p "$ROOT/announce"); CONTROL=$(sed -n 3p "$ROOT/announce"); SUPERVISOR_PID=$(sed -n 4p "$ROOT/announce")
log "session=$SESSION epoch=$EPOCH supervisor_pid=$SUPERVISOR_PID (pid is diagnostic, not identity)"
ctl() { "$FIXTURE" ctl --control "$CONTROL" --session "$SESSION" "$@"; }
PANE_PID=$(T display -p -t lane '#{pane_pid}')
CHILDREN_BEFORE=$(pgrep -lP "$SUPERVISOR_PID" | tr '\n' ';' || true)
log "owned child before detach: $CHILDREN_BEFORE"

# Attach a stock control-mode client, then detach it; the generation survives.
# Attachment/detachment are observed through tmux hooks signalling wait-for
# channels, never by sleeping.
T set-hook -t lane client-attached "wait-for -S attached"
T set-hook -t lane client-detached "wait-for -S detached"
mkfifo "$ROOT/client.in"
( exec 3<>"$ROOT/client.in"; "$TMUX_EXE" -S "$SOCK" -f /dev/null -C attach-session -t lane <&3 >"$ROOT/client1.out" 2>&1 ) &
CLIENT1=$!
T wait-for attached
log "clients_after_attach=$(T list-clients | wc -l | tr -d ' ')"
[ "$(T list-clients | wc -l | tr -d ' ')" = "1" ]
T detach-client -s lane
T wait-for detached
wait "$CLIENT1" 2>/dev/null || true
log "clients_after_detach=$(T list-clients | wc -l | tr -d ' ')"
[ "$(T list-clients | wc -l | tr -d ' ')" = "0" ]
STATUS1=$(ctl --op status --generation 1); log "status after detach: $STATUS1"
echo "$STATUS1" | grep -q '"state":"running"' && echo "$STATUS1" | grep -q "\"epoch\":\"$EPOCH\"" && echo "$STATUS1" | grep -q '"generation":1'
CHILDREN_AFTER=$(pgrep -lP "$SUPERVISOR_PID" | tr '\n' ';' || true)
log "owned child after detach: $CHILDREN_AFTER"
[ "$CHILDREN_BEFORE" = "$CHILDREN_AFTER" ]
[ "$(T display -p -t lane '#{pane_pid}')" = "$PANE_PID" ]

# Reattach (wake) with a second client: same owned execution, no respawn.
( exec 3<>"$ROOT/client.in"; "$TMUX_EXE" -S "$SOCK" -f /dev/null -C attach-session -t lane <&3 >"$ROOT/client2.out" 2>&1 ) &
CLIENT2=$!
T wait-for attached
log "clients_after_reattach=$(T list-clients | wc -l | tr -d ' ')"
[ "$(T list-clients | wc -l | tr -d ' ')" = "1" ]
STATUS2=$(ctl --op status --generation 1); log "status after reattach: $STATUS2"
echo "$STATUS2" | grep -q '"state":"running"' && echo "$STATUS2" | grep -q '"generation":1'
[ "$(pgrep -lP "$SUPERVISOR_PID" | tr '\n' ';' || true)" = "$CHILDREN_BEFORE" ]
log "pane screen during reattach: $(T capture-pane -p -t lane | grep -c . ) non-empty lines"
T detach-client -s lane
T wait-for detached
wait "$CLIENT2" 2>/dev/null || true

# Release the held reply: the real process completes, history is published.
touch "$ROOT/release"
"$FIXTURE" wait --control "$CONTROL" --session "$SESSION" --state stopped --timeout-ms 120000 | tee -a "$LOG"
STATUS3=$(ctl --op status --generation 1); log "status after completion: $STATUS3"
CHECKPOINT=$(echo "$STATUS3" | sed -n 's/.*"checkpoint":"\([0-9a-f]\{64\}\)".*/\1/p')
[ -n "$CHECKPOINT" ] && echo "$STATUS3" | grep -q '"history":"published"'
log "checkpoint=$CHECKPOINT"

# Stop/wake: resume the exact checkpoint in a fresh generation.
RESUME=$(ctl --op resume --generation 1 --checkpoint "$CHECKPOINT"); log "resume: $RESUME"
echo "$RESUME" | grep -q '"code":"accepted"' && echo "$RESUME" | grep -q '"generation":2'
"$FIXTURE" wait --control "$CONTROL" --session "$SESSION" --state stopped --timeout-ms 120000 | tee -a "$LOG"
STATUS4=$(ctl --op status --generation 2); log "status after wake: $STATUS4"
CHECKPOINT2=$(echo "$STATUS4" | sed -n 's/.*"checkpoint":"\([0-9a-f]\{64\}\)".*/\1/p')
[ -n "$CHECKPOINT2" ] && [ "$CHECKPOINT2" != "$CHECKPOINT" ] && echo "$STATUS4" | grep -q '"generation":2'
# Exact-retry of the settled resume returns the recorded snapshot; stale observation refuses.
REQ=$(echo "$RESUME" | sed -n 's/.*"request":"\([0-9a-f]\{32\}\)".*/\1/p')
REPLAY=$(ctl --op resume --generation 1 --checkpoint "$CHECKPOINT" --request "$REQ"); log "resume replay: $REPLAY"
echo "$REPLAY" | grep -q '"code":"ok"' && echo "$REPLAY" | grep -q '"final":true'
STALE=$(ctl --op stop --generation 1); log "stale stop: $STALE"; echo "$STALE" | grep -q '"code":"stale_generation"'
RUNS=$(ls "$ROOT/s/rt/claude/runs" | wc -l | tr -d ' '); log "retained run dirs=$RUNS"; [ "$RUNS" = "0" ]

# Shutdown: the supervisor leaves its pane; a stale pathname refuses afterwards.
SHUT=$(ctl --op shutdown --generation 2); log "shutdown: $SHUT"; echo "$SHUT" | grep -q '"code":"ok"'
T wait-for served
log "serve exit=$(cat "$ROOT/serve.exit")"
if ctl --op status --generation 2 >"$ROOT/stale.out" 2>&1; then log "ERROR: stale control accepted"; exit 1; fi
log "stale control refused: $(cat "$ROOT/stale.out")"
grep -E "^\[serve\]|^\[responder\]|^\[supervisor\]" "$ROOT/serve.err" | tee -a "$LOG"
grep -q "refusals=0" "$ROOT/serve.err"

# ---- interactive TUI smoke (separate, best-effort; not headless parity) -----
T new-window -t lane -n tui \
  "$FIXTURE serve --root $ROOT/i --executable $EXECUTABLE --sha256 $SHA256 --version $VERSION \
     --mode interactive --auto-start --announce $ROOT/announce-i 2>$ROOT/serve-i.err; echo \$? >$ROOT/serve-i.exit; $TMUX_EXE -S $SOCK wait-for -S served-i"
if "$FIXTURE" wait --announce "$ROOT/announce-i" --state running --timeout-ms 60000 | tee -a "$LOG"; then
  ISESSION=$(sed -n 1p "$ROOT/announce-i"); ICONTROL=$(sed -n 3p "$ROOT/announce-i")
  sleep 6  # single bounded TUI render wait, not a polling loop
  T capture-pane -p -t lane:tui | tee "$ROOT/tui-1.txt" | tail -25 | tee -a "$LOG"
  T send-keys -t lane:tui "Reply with exactly the single word pong." Enter
  sleep 6
  T capture-pane -p -t lane:tui | tee "$ROOT/tui-2.txt" | tail -25 | tee -a "$LOG"
  ISTOP=$("$FIXTURE" ctl --control "$ICONTROL" --session "$ISESSION" --op stop --generation 1); log "tui stop: $ISTOP"
  "$FIXTURE" wait --control "$ICONTROL" --session "$ISESSION" --state stopped --timeout-ms 60000 | tee -a "$LOG" || true
  "$FIXTURE" ctl --control "$ICONTROL" --session "$ISESSION" --op status --generation 1 | tee -a "$LOG" || true
  "$FIXTURE" ctl --control "$ICONTROL" --session "$ISESSION" --op shutdown --generation 1 | tee -a "$LOG" || true
  T wait-for served-i || true
  log "interactive serve exit=$(cat "$ROOT/serve-i.exit" 2>/dev/null || echo unknown)"
  grep -E "^\[serve\]|^\[responder\]|^\[supervisor\]" "$ROOT/serve-i.err" | tee -a "$LOG" || true
else
  log "interactive lane: supervisor did not reach running (see $ROOT/serve-i.err)"
fi
log "lane complete"
