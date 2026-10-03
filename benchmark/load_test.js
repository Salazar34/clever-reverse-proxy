import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Counter } from 'k6/metrics';

// ============================================================================
// SecLab DoS Mitigation - High-Fidelity Asymmetric DoS Benchmark
// ============================================================================
// Target URL configured via environment variable (default: Reverse Proxy on :8080)
const TARGET_URL = __ENV.TARGET_URL || 'http://localhost:8080';

// Custom Telemetry Metrics
export const legitReqDuration = new Trend('legit_req_duration', true);
export const attackerReqDuration = new Trend('attacker_req_duration', true);
export const http200Counter = new Counter('status_http_200');
export const http428Counter = new Counter('status_http_428');
export const http429Counter = new Counter('status_http_429');
export const http5xxCounter = new Counter('status_http_5xx');

// Concurrent Scenario Definition
export const options = {
  scenarios: {
    // Scenario 1: Legitimate Background Traffic
    // 30 concurrent VUs executing lightweight, indexed operations over 180 seconds
    legitimate_users: {
      executor: 'constant-vus',
      vus: 30,
      duration: '180s',
      exec: 'runLegitimateUser',
      tags: { scenario: 'legitimate_users' },
    },

    // Scenario 2: Asymmetric Complexity DoS Attack
    // 3 malicious VUs active between t=30s and t=140s (110s duration)
    // Sending pathological queries (unindexed Seq Scan + deep OFFSET + disk sort)
    attacker_dos: {
      executor: 'constant-vus',
      vus: 3,
      startTime: '30s',
      duration: '110s',
      exec: 'runAttackerDoS',
      tags: { scenario: 'attacker_dos' },
    },
  },
  thresholds: {
    // Quality assurance guardrails
    'status_http_5xx': ['count<500'],
  },
};

function trackStatus(statusCode) {
  if (statusCode === 200) {
    http200Counter.add(1);
  } else if (statusCode === 428) {
    http428Counter.add(1);
  } else if (statusCode === 429) {
    http429Counter.add(1);
  } else if (statusCode >= 500 && statusCode < 600) {
    http5xxCounter.add(1);
  }
}

// ----------------------------------------------------------------------------
// Worker Function: Legitimate User (Symmetric / Low Computational Cost)
// ----------------------------------------------------------------------------
export function runLegitimateUser() {
  const isLookup = Math.random() < 0.5;
  let targetEndpoint;

  if (isLookup) {
    // O(1) Key-Lookup: /api/v1/orders/{id}
    const orderId = Math.floor(Math.random() * 20000) + 1;
    targetEndpoint = `${TARGET_URL}/api/v1/orders/${orderId}`;
  } else {
    // Shallow indexed pagination: /api/v1/orders?limit=20&sort_by=id
    targetEndpoint = `${TARGET_URL}/api/v1/orders?limit=20&offset=0&sort_by=id`;
  }

  const res = http.get(targetEndpoint, {
    headers: {
      'X-Forwarded-For': `192.168.1.${__VU}`,
      'Accept': 'application/json',
    },
    tags: { traffic_type: 'legitimate' },
  });

  legitReqDuration.add(res.timings.duration);
  trackStatus(res.status);

  check(res, {
    'legit status is 200': (r) => r.status === 200,
  });

  // Physiological think time: 100ms - 300ms
  sleep(0.1 + Math.random() * 0.2);
}

// ----------------------------------------------------------------------------
// Worker Function: Malicious Attacker (Asymmetric / High Computational Cost)
// ----------------------------------------------------------------------------
export function runAttackerDoS() {
  // Pathological query forcing PostgreSQL to execute:
  // 1. Seq Scan on 500,000 unindexed notes tuples (ILIKE '%urgent%')
  // 2. External Sort on unindexed TEXT notes
  // 3. Scan & Discard 40,000 matching tuples
  const pathologicalEndpoint = `${TARGET_URL}/api/v1/orders?search=urgent&offset=40000&limit=50&sort_by=notes`;

  const res = http.get(pathologicalEndpoint, {
    headers: {
      'X-Forwarded-For': `10.0.66.${__VU}`,
      'Accept': 'application/json',
    },
    tags: { traffic_type: 'attacker' },
  });

  attackerReqDuration.add(res.timings.duration);
  trackStatus(res.status);

  // Aggressive repeat cycle: 500ms sleep
  sleep(0.5);
}

// ----------------------------------------------------------------------------
// Summary Exporter
// ----------------------------------------------------------------------------
export function handleSummary(data) {
  const summaryFile = __ENV.SUMMARY_FILE || 'benchmark/data/k6_summary.json';
  return {
    stdout: textSummary(data, { indent: ' ', enableColors: true }),
    [summaryFile]: JSON.stringify(data, null, 2),
  };
}

function textSummary(data, options) {
  return `\n=== Benchmark Execution Complete ===\nTotal Requests: ${data.metrics.http_reqs ? data.metrics.http_reqs.values.count : 'N/A'}\n`;
}
