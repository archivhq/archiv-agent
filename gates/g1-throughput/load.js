// G1 — Agent throughput (docs/engineering/05-quality-gates.md §2).
//
// Open-loop OTLP/HTTP load against a running archiv-agent. POSTs a real,
// pre-encoded ExportLogsServiceRequest (written by the perf harness's
// ARCHIV_PERF_DUMP mode) to /v1/logs and asserts sustained throughput.
//
// Env:
//   ARCHIV_AGENT_URL   base URL of the agent      (default http://127.0.0.1:4318)
//   ARCHIV_OTLP_FILE   path to the binary payload (default /tmp/archiv-otlp.bin)
//   ARCHIV_RECORDS     records per request         (default 10) — for EPS math
//
// Pass criteria are checked by run.sh from the summary (req/s × records ≥ 10k EPS).

import http from 'k6/http';
import { check } from 'k6';
import { Counter } from 'k6/metrics';

const URL = (__ENV.ARCHIV_AGENT_URL || 'http://127.0.0.1:4318') + '/v1/logs';
const PAYLOAD = open(__ENV.ARCHIV_OTLP_FILE || '/tmp/archiv-otlp.bin', 'b');
const RECORDS = parseInt(__ENV.ARCHIV_RECORDS || '10', 10);

export const events = new Counter('archiv_events');

export const options = {
  scenarios: {
    // Open-loop arrival (constant rate) — guards against coordinated omission
    // (G2 §2). Ramp the rate in run.sh if the target box needs more pressure.
    steady: {
      executor: 'constant-arrival-rate',
      rate: parseInt(__ENV.ARCHIV_RATE || '2000', 10), // requests/s offered
      timeUnit: '1s',
      duration: __ENV.ARCHIV_DURATION || '30s',
      preAllocatedVUs: 50,
      maxVUs: 500,
    },
  },
  thresholds: {
    // Governance must never turn a valid request into an error.
    http_req_failed: ['rate<0.001'],
  },
};

const PARAMS = { headers: { 'Content-Type': 'application/x-protobuf' } };

export default function () {
  const res = http.post(URL, PAYLOAD, PARAMS);
  check(res, { 'status is 200': (r) => r.status === 200 });
  events.add(RECORDS);
}
