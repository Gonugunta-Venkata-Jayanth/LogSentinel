// Parity test: the browser engine must score the sample log exactly like the Python API.
// Run: node --test frontend/tests/
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { analyze, parseLine } from "../engine.js";

const root = new URL("../../", import.meta.url);
const model = JSON.parse(readFileSync(new URL("frontend/model.json", root)));
const sample = readFileSync(new URL("samples/auth.log", root), "utf8");
const golden = JSON.parse(readFileSync(new URL("samples/expected_scores.json", root)));

test("parses an invalid-user failure", () => {
  const e = parseLine("Oct  5 10:15:01 host sshd[1]: Failed password for invalid user admin from 1.2.3.4 port 5 ssh2");
  assert.equal(e.kind, "failed");
  assert.equal(e.user, "admin");
  assert.equal(e.invalid, true);
});

test("matches Python scores on the sample log", () => {
  const { results } = analyze(model, sample);
  assert.equal(results.length, Object.keys(golden).length);
  for (const r of results) {
    const [score, verdict] = golden[r.ip];
    assert.ok(Math.abs(r.score - score) < 1e-3, `${r.ip}: js=${r.score} py=${score}`);
    assert.equal(r.verdict, verdict, r.ip);
  }
});
