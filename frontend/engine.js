// Browser port of backend/app/{parser,features,model}.py so the dashboard works
// fully offline on GitHub Pages. tests/engine.test.mjs checks parity with Python.
const MONTHS = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };
const SYSLOG_TS = /^([A-Z][a-z]{2})\s+(\d{1,2})\s(\d{2}):(\d{2}):(\d{2})\s/;
const ISO_TS = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})/;
const PATTERNS = [
  ["failed", /Failed (?:password|publickey) for (invalid user )?(\S+) from ([0-9a-fA-F:.]+)/],
  ["accepted", /Accepted (?:password|publickey|keyboard-interactive\/pam) for ()(\S+) from ([0-9a-fA-F:.]+)/],
  ["invalid", /Invalid user ()(\S*) from ([0-9a-fA-F:.]+)/],
];

export const FEATURES = ["failed_count", "unique_users", "invalid_user_count", "success_count",
  "fail_ratio", "attempts_per_min", "root_attempts"];

function parseTs(line, year) {
  let m = line.match(ISO_TS);
  if (m) return new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]));
  m = line.match(SYSLOG_TS);
  if (m && m[1] in MONTHS) return new Date(Date.UTC(year, MONTHS[m[1]], +m[2], +m[3], +m[4], +m[5]));
  return null;
}

export function parseLine(line, year = 2026) {
  if (!line.includes("sshd")) return null;
  const ts = parseTs(line, year);
  if (!ts) return null;
  for (const [kind, re] of PATTERNS) {
    const m = line.match(re);
    if (m) return { ts, kind, user: m[2] || "?", ip: m[3], invalid: kind === "invalid" || Boolean(m[1]) };
  }
  return null;
}

export const parseLog = (text, year = 2026) => text.split(/\r?\n/).map((l) => parseLine(l, year)).filter(Boolean);

export function ipFeatures(events) {
  const byIp = new Map();
  for (const e of events) (byIp.get(e.ip) || byIp.set(e.ip, []).get(e.ip)).push(e);
  const out = {};
  for (const [ip, evs] of byIp) {
    const failed = evs.filter((e) => e.kind === "failed").length;
    const success = evs.filter((e) => e.kind === "accepted").length;
    const invalid = evs.filter((e) => e.kind === "failed" && e.invalid).length ||
      evs.filter((e) => e.kind === "invalid").length;
    const times = evs.map((e) => e.ts.getTime()).sort((a, b) => a - b);
    const spanMin = Math.max((times[times.length - 1] - times[0]) / 60000, 1);
    const attempts = failed + success;
    out[ip] = {
      failed_count: failed,
      unique_users: new Set(evs.map((e) => e.user)).size,
      invalid_user_count: invalid,
      success_count: success,
      fail_ratio: attempts ? failed / attempts : 0,
      attempts_per_min: attempts / spanMin,
      root_attempts: evs.filter((e) => e.user === "root" && e.kind === "failed").length,
      first_seen: new Date(times[0]).toISOString().slice(0, 19),
      last_seen: new Date(times[times.length - 1]).toISOString().slice(0, 19),
    };
  }
  return out;
}

export function score(model, f) {
  let z = model.intercept;
  model.features.forEach((name, i) => {
    const x = model.log_features.includes(name) ? Math.log1p(f[name]) : f[name];
    z += model.coef[i] * (x - model.mean[i]) / model.scale[i];
  });
  return 1 / (1 + Math.exp(-z));
}

export const verdict = (model, p) => (p >= 0.85 ? "block" : p >= model.threshold ? "suspicious" : "ok");

export function analyze(model, text, year = 2026) {
  const events = parseLog(text, year);
  const results = Object.entries(ipFeatures(events)).map(([ip, f]) => {
    const p = score(model, f);
    return { ip, score: Math.round(p * 1e4) / 1e4, verdict: verdict(model, p), ...f };
  }).sort((a, b) => b.score - a.score);
  return {
    summary: {
      events: events.length,
      ips: results.length,
      blocked: results.filter((r) => r.verdict === "block").length,
      suspicious: results.filter((r) => r.verdict === "suspicious").length,
      failed_logins: events.filter((e) => e.kind === "failed").length,
      successful_logins: events.filter((e) => e.kind === "accepted").length,
    },
    results,
    events,
  };
}
