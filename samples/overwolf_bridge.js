// Paste into Overwolf Warzone Stats / custom app — append one JSON line per event
// to ~/.warzone-sentinel/live_events.ndjson (or pipe via file watcher).

// On lobby load (player list from companion API):
function emitLobby(players) {
  const ev = { type: "lobby", players: players.map(p => ({
    name: p.name,
    lifetime_kd: p.kd,
    headshot_pct: p.headshotPct,
    rank_tier: p.rank,
    session_kd: p.sessionKd,
  }))};
  appendEvent(ev);
}

// On kill feed event:
function emitKill(killer, victim, matchTimeSec, extra) {
  appendEvent({
    type: "kill",
    killer, victim,
    match_time_sec: matchTimeSec,
    headshot: extra.headshot || false,
    killer_ping_ms: extra.killerPing,
    victim_ping_ms: extra.victimPing,
    killer_x: extra.killerX,
    killer_y: extra.killerY,
    victim_visible_ms: extra.visibleMs,
  });
}

// On scoreboard ping refresh:
function emitPing(player, pingMs) {
  appendEvent({ type: "ping", player, ping_ms: pingMs });
}

// Prefire / ESP signal (manual hotkey or heuristics):
function emitPrefire(player, beforeLos) {
  appendEvent({ type: "prefire", player, before_los: beforeLos });
}

function appendEvent(ev) {
  // POST to LXC ingest (replace CT IP):
  // fetch('http://192.0.2.x:8098/v1/events', {
  //   method: 'POST',
  //   headers: { 'Content-Type': 'application/json' },
  //   body: JSON.stringify(ev),
  // });
}
