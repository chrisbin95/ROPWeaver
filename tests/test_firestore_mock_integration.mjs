/**
 * tests/test_firestore_mock_integration.mjs
 *
 * Automated Integration Test Suite for Task 5.9B5:
 * Local Firestore Mock Integration for ROPWeaver CLI
 *
 * Uses ONLY Node.js built-in modules (http, child_process, fs, path, os, crypto, assert).
 *
 * Verifies:
 * 1. Safe local Firestore loopback routing via FIRESTORE_EMULATOR_HOST.
 * 2. Report documents exclude the full gadgets array while preserving metadata and total_gadgets.
 * 3. Deterministic collision-resistant gadget document IDs (<binary>_<hashPart>_0x<address>).
 * 4. Commit batching strictly respects <= 400 writes per commit request.
 * 5. Idempotent upload handling (report existence check skips without --force, updates with --force).
 * 6. Partial gadget upload failure propagation to CLI non-zero exit code (exit code 1).
 * 7. Simulated HTTP 503 error handling and graceful failure.
 * 8. Strict validation of FIRESTORE_EMULATOR_HOST (rejecting remote hosts, schemes, paths, malformed ports).
 * 9. Guaranteed shutdown of mock server and complete protection of repository artifacts.
 */

import http from 'node:http';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import assert from 'node:assert';

console.log('=== ROPWeaver Task 5.9C4: Cross-Platform Firestore Mock Integration Test Suite ===\n');

let passCount = 0;
let failCount = 0;
let skipCount = 0;
let activeEmulatorHost = null;

function runTest(name, fn) {
  try {
    fn();
    console.log(`  [PASS] ${name}`);
    passCount++;
  } catch (err) {
    console.error(`  [FAIL] ${name}`);
    console.error(`         ${err.message}`);
    failCount++;
  }
}

async function runAsyncTest(name, fn) {
  try {
    const res = await fn();
    if (res && res.skipped) {
      console.log(`  [SKIP] ${name}`);
      console.log(`         ${res.reason}`);
      skipCount++;
      return;
    }
    console.log(`  [PASS] ${name}`);
    passCount++;
  } catch (err) {
    console.error(`  [FAIL] ${name}`);
    console.error(`         ${err.message}`);
    failCount++;
  }
}

// ---------------------------------------------------------------------------
// Protected File Hash Verifier
// ---------------------------------------------------------------------------
const PROTECTED_HASHES = {
  'reports/output.json': '0CBAF3B45823E96EC56E4C7AAF27B54FB51EE648FC8EDE32CB6C925975928EDE',
  'payload.bin': '7D8913B516C83E29AE83F75D42BF619DBCB3D6FA1545ABBED570D826BE39960E',
  'reports/payload.bin': '7D8913B516C83E29AE83F75D42BF619DBCB3D6FA1545ABBED570D826BE39960E'
};

function verifyProtectedArtifacts(label) {
  for (const [relPath, expectedHash] of Object.entries(PROTECTED_HASHES)) {
    const fullPath = path.resolve(relPath);
    if (!fs.existsSync(fullPath)) {
      throw new Error(`Protected file missing at ${label}: ${relPath}`);
    }
    const fileBytes = fs.readFileSync(fullPath);
    const actualHash = crypto.createHash('sha256').update(fileBytes).digest('hex').toUpperCase();
    if (actualHash !== expectedHash) {
      throw new Error(`Protected file ${relPath} checksum modified at ${label}! Expected: ${expectedHash}, Actual: ${actualHash}`);
    }
  }
}

// ---------------------------------------------------------------------------
// Mock Firestore HTTP Server
// ---------------------------------------------------------------------------
class MockFirestoreServer {
  constructor() {
    this.server = null;
    this.port = 0;
    this.requests = [];
    this.handler = null;
  }

  async start() {
    return new Promise((resolve, reject) => {
      this.server = http.createServer((req, res) => {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', () => {
          let parsedBody = null;
          if (body && req.headers['content-type']?.includes('application/json')) {
            try {
              parsedBody = JSON.parse(body);
            } catch {
              parsedBody = body;
            }
          }
          // Handle Auth Emulator login if requested
          if (req.url.includes('identitytoolkit') || req.url.includes('signInWithPassword')) {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              idToken: 'mock-valid-id-token',
              refreshToken: 'mock-valid-refresh-token',
              expiresIn: '3600',
              localId: 'CqiPQGv339cgbMzULJHKWLz67j93',
              email: 'ropweaver@gmail.com'
            }));
            return;
          }

          const record = {
            method: req.method,
            url: req.url,
            headers: req.headers,
            rawBody: body,
            body: parsedBody
          };
          this.requests.push(record);

          if (this.handler) {
            this.handler(req, res, record);
          } else {
            this.defaultHandler(req, res, record);
          }
        });
      });

      this.server.on('error', reject);
      this.server.listen(0, '127.0.0.1', () => {
        this.port = this.server.address().port;
        resolve(this.port);
      });
    });
  }

  defaultHandler(req, res, record) {
    if (req.method === 'GET') {
      // reportExists check default: document not found
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: { code: 404, message: 'Document not found' } }));
      return;
    }
    if (req.method === 'PATCH') {
      // uploadReport upsert default: success
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        name: req.url.split('?')[0],
        fields: record.body?.fields || {}
      }));
      return;
    }
    if (req.method === 'POST') {
      // Commit gadgets default: success
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        writeResults: (record.body?.writes || []).map(() => ({ updateTime: new Date().toISOString() })),
        commitTime: new Date().toISOString()
      }));
      return;
    }
    res.writeHead(405, { 'Content-Type': 'text/plain' });
    res.end('Method Not Allowed');
  }

  clear() {
    this.requests = [];
    this.handler = null;
  }

  async stop() {
    if (this.server) {
      await new Promise(resolve => this.server.close(resolve));
      this.server = null;
    }
  }
}

// ---------------------------------------------------------------------------
// Executable and Fixture Resolution
// ---------------------------------------------------------------------------
function resolveExecutable() {
  if (process.env.ROPWEAVER_EXECUTABLE) {
    const customPath = path.resolve(process.env.ROPWEAVER_EXECUTABLE);
    if (!fs.existsSync(customPath)) {
      throw new Error(`Specified ROPWEAVER_EXECUTABLE does not exist: ${customPath}`);
    }
    return customPath;
  }

  const candidates = [
    path.resolve('build-win', 'ropweaver.exe'),
    path.resolve('build', 'ropweaver'),
    path.resolve('build-mac', 'build', 'ropweaver')
  ];

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }

  throw new Error(
    `No ROPWeaver executable found. Searched paths:\n` +
    candidates.map(c => `  - ${c}`).join('\n') +
    `\nPlease build ROPWeaver or set ROPWEAVER_EXECUTABLE.`
  );
}

function resolveSingleBatchBinary() {
  const target = path.resolve('test_binaries', 'binsh_test');
  if (!fs.existsSync(target)) {
    throw new Error(`Required single-batch test fixture missing: ${target}`);
  }
  return target;
}

function resolveMultiBatchBinary() {
  if (process.env.ROPWEAVER_MULTI_BATCH_BINARY) {
    const customPath = path.resolve(process.env.ROPWEAVER_MULTI_BATCH_BINARY);
    if (!fs.existsSync(customPath)) {
      throw new Error(`Specified ROPWEAVER_MULTI_BATCH_BINARY does not exist: ${customPath}`);
    }
    return customPath;
  }

  const candidates = [
    path.resolve('build-win', 'test_endian_readers.exe'),
    path.resolve('build', 'test_endian_readers'),
    path.resolve('build-mac', 'build', 'test_endian_readers')
  ];

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }

  throw new Error(
    `No multi-batch test fixture found. Searched paths:\n` +
    candidates.map(c => `  - ${c}`).join('\n') +
    `\nPlease build test_endian_readers or set ROPWEAVER_MULTI_BATCH_BINARY.`
  );
}

async function verifyMultiBatchFixture(fixturePath) {
  if (!fs.existsSync(fixturePath)) {
    throw new Error(`Multi-batch fixture binary missing: ${fixturePath}`);
  }
  const probe = await runCli(fixturePath, ['--list-gadgets']);
  const match = probe.stdout.match(/Found\s+(\d+)\s+gadgets/);
  if (!match) {
    throw new Error(
      `Failed to determine gadget count from multi-batch fixture ${fixturePath}.\nStdout: ${probe.stdout}\nStderr: ${probe.stderr}`
    );
  }
  const count = parseInt(match[1], 10);
  if (count <= 400) {
    throw new Error(
      `Multi-batch fixture ${fixturePath} contains only ${count} gadgets; strictly requires > 400 gadgets for multi-batch testing.`
    );
  }
  return count;
}

// ---------------------------------------------------------------------------
// CLI Execution Helper (Asynchronous to keep Node HTTP event loop active)
// ---------------------------------------------------------------------------
async function runCli(binaryPath, extraArgs = [], envOverrides = {}) {
  const scratchDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ropweaver_mock_test_'));
  return new Promise((resolve) => {
    try {
      const defaultEnv = {
        ...process.env,
        ROPWEAVER_FIREBASE_PASSWORD: 'mock-test-password',
        ...(activeEmulatorHost ? { FIREBASE_AUTH_EMULATOR_HOST: activeEmulatorHost } : {}),
        ...envOverrides
      };
      const cliExe = resolveExecutable();
      const targetBinary = path.resolve(binaryPath);

      const args = [targetBinary, ...extraArgs];
      const child = spawn(cliExe, args, {
        cwd: scratchDir,
        env: defaultEnv
      });

      let stdout = '';
      let stderr = '';
      child.stdout.on('data', chunk => { stdout += chunk; });
      child.stderr.on('data', chunk => { stderr += chunk; });

      child.on('close', (status) => {
        try {
          fs.rmSync(scratchDir, { recursive: true, force: true });
        } catch {}
        resolve({
          status,
          stdout,
          stderr,
          scratchDir
        });
      });

      child.on('error', (err) => {
        try {
          fs.rmSync(scratchDir, { recursive: true, force: true });
        } catch {}
        resolve({
          status: -1,
          stdout,
          stderr: stderr + '\n' + err.message,
          scratchDir
        });
      });
    } catch (err) {
      try {
        fs.rmSync(scratchDir, { recursive: true, force: true });
      } catch {}
      resolve({
        status: -1,
        stdout: '',
        stderr: err.message,
        scratchDir
      });
    }
  });
}

// ---------------------------------------------------------------------------
// Test Execution
// ---------------------------------------------------------------------------
async function main() {
  verifyProtectedArtifacts('pre-test suite initialization');

  const cliExe = resolveExecutable();
  const singleBatchBinary = resolveSingleBatchBinary();
  const multiBatchBinary = resolveMultiBatchBinary();

  console.log(`[*] Resolved ROPWeaver executable: ${cliExe}`);
  console.log(`[*] Resolved single-batch fixture: ${singleBatchBinary}`);
  console.log(`[*] Resolved multi-batch fixture:  ${multiBatchBinary}\n`);

  // Verify multi-batch fixture meets requirements (> 400 gadgets)
  const multiBatchGadgetCount = await verifyMultiBatchFixture(multiBatchBinary);
  console.log(`[*] Verified multi-batch fixture gadget count: ${multiBatchGadgetCount} (> 400)\n`);

  const mock = new MockFirestoreServer();
  const port = await mock.start();
  const emulatorHost = `127.0.0.1:${port}`;
  activeEmulatorHost = emulatorHost;

  console.log(`[*] Mock Firestore server listening on http://${emulatorHost}\n`);

  try {
    // -----------------------------------------------------------------------
    // Test 1: Full report and gadget upload flow
    // -----------------------------------------------------------------------
    await runAsyncTest('Test 1: Normal report metadata + gadget upload flow to loopback mock', async () => {
      mock.clear();
      const res = await runCli(singleBatchBinary, ['--upload-report'], {
        FIRESTORE_EMULATOR_HOST: emulatorHost
      });

      assert.strictEqual(res.status, 0, `CLI failed with code ${res.status}. Stderr: ${res.stderr}`);

      // Check request sequence: GET (exists check) -> PATCH (report in_progress) -> POST (commit gadgets) -> PATCH (status completed)
      assert.strictEqual(mock.requests.length, 4, `Expected 4 requests, got ${mock.requests.length}`);

      const binStem = path.basename(singleBatchBinary, path.extname(singleBatchBinary));

      const getReq = mock.requests[0];
      assert.strictEqual(getReq.method, 'GET');
      assert.match(getReq.url, new RegExp(`\\/reports\\/${binStem}_[a-f0-9]{12,}\\?key=`));

      const patchReq = mock.requests[1];
      assert.strictEqual(patchReq.method, 'PATCH');
      assert.match(patchReq.url, new RegExp(`\\/reports\\/${binStem}_[a-f0-9]{12,}\\?key=`));
      const reportFields = patchReq.body?.fields;
      assert.ok(reportFields, 'Report document missing fields object');

      // Requirement 1: Report documents EXCLUDE the full gadgets array
      assert.strictEqual(reportFields.gadgets, undefined, 'Report fields must NOT contain raw gadgets array');

      // Requirement 2: Report metadata preserves total_gadgets and summary
      assert.ok(reportFields.total_gadgets?.integerValue, 'Report fields missing total_gadgets');
      assert.strictEqual(reportFields.gadgets_stored_separately?.booleanValue, true);
      assert.ok(reportFields.filename?.stringValue, 'Report fields missing filename');

      const commitReq = mock.requests[2];
      assert.strictEqual(commitReq.method, 'POST');
      assert.match(commitReq.url, /\/documents:commit\?key=/);
      const writes = commitReq.body?.writes;
      assert.ok(Array.isArray(writes), 'Commit missing writes array');
      assert.ok(writes.length > 0, 'Commit writes array is empty');
      assert.ok(writes.length <= 400, `Commit writes ${writes.length} exceeds batch limit of 400`);

      // Requirement 3: Gadget document ID format: <binary>_<hashPart>_0x<address>
      const firstWrite = writes[0];
      assert.ok(firstWrite.update?.name, 'Gadget write missing doc name');
      assert.match(
        firstWrite.update.name,
        new RegExp(`projects/rop-weaver/databases/\\(default\\)/documents/gadgets/${binStem}_[a-f0-9]{12}_0x[0-9a-fA-F]+`)
      );

      const gFields = firstWrite.update.fields;
      assert.ok(gFields.address?.stringValue, 'Gadget missing address');
      assert.ok(gFields.instructions?.stringValue, 'Gadget missing instructions');
      assert.ok(gFields.category?.stringValue, 'Gadget missing category');
      assert.ok(gFields.hash?.stringValue, 'Gadget missing hash');
      assert.ok(gFields.report_id?.stringValue, 'Gadget missing report_id');

      // Requirement 4: Final status transition to 'completed'
      const statusPatchReq = mock.requests[3];
      assert.strictEqual(statusPatchReq.method, 'PATCH');
      assert.match(statusPatchReq.url, /upload_status/);
      assert.strictEqual(statusPatchReq.body?.fields?.upload_status?.stringValue, 'completed');
    });

    // -----------------------------------------------------------------------
    // Test 2: Multi-batch gadget upload with <= 400 writes per commit
    // -----------------------------------------------------------------------
    await runAsyncTest('Test 2: Multi-batch gadget upload with <= 400 writes per batch', async () => {
      mock.clear();
      const res = await runCli(multiBatchBinary, ['--upload-report'], {
        FIRESTORE_EMULATOR_HOST: emulatorHost
      });

      assert.strictEqual(res.status, 0, `CLI failed with code ${res.status}. Stderr: ${res.stderr}`);

      // Calculate expected batches dynamically
      const expectedBatches = Math.ceil(multiBatchGadgetCount / 400);
      assert.ok(expectedBatches >= 2, `Multi-batch fixture must require at least 2 commit batches, got ${expectedBatches}`);

      // Expected request sequence: 1 GET (exists check), 1 PATCH (report metadata), followed by commit POST requests
      const commitRequests = mock.requests.filter(r => r.method === 'POST' && r.url.includes(':commit'));
      assert.strictEqual(
        commitRequests.length,
        expectedBatches,
        `Expected ${expectedBatches} commit batches, got ${commitRequests.length}`
      );
      assert.strictEqual(
        mock.requests.length,
        2 + expectedBatches + 1,
        `Expected ${2 + expectedBatches + 1} total requests (1 GET, 1 PATCH in_progress, ${expectedBatches} commits, 1 PATCH completed), got ${mock.requests.length}`
      );
      assert.strictEqual(mock.requests[0].method, 'GET');
      assert.strictEqual(mock.requests[1].method, 'PATCH');

      const seenGadgetNames = new Set();
      let totalCommittedWrites = 0;

      commitRequests.forEach((req, idx) => {
        const writes = req.body?.writes || [];
        const isLastBatch = (idx === expectedBatches - 1);
        const expectedWritesInBatch = isLastBatch
          ? (multiBatchGadgetCount % 400 === 0 ? 400 : multiBatchGadgetCount % 400)
          : 400;

        assert.strictEqual(
          writes.length,
          expectedWritesInBatch,
          `Batch ${idx + 1} should have ${expectedWritesInBatch} writes, got ${writes.length}`
        );

        for (const w of writes) {
          const docName = w.update?.name;
          assert.ok(docName, `Batch ${idx + 1} contains write without document name`);
          assert.ok(!seenGadgetNames.has(docName), `Duplicate gadget write detected: ${docName}`);
          seenGadgetNames.add(docName);
        }

        totalCommittedWrites += writes.length;
      });

      assert.strictEqual(
        totalCommittedWrites,
        multiBatchGadgetCount,
        `Total committed writes (${totalCommittedWrites}) must equal fixture gadget count (${multiBatchGadgetCount})`
      );
      assert.strictEqual(
        seenGadgetNames.size,
        multiBatchGadgetCount,
        `Unique committed gadget documents (${seenGadgetNames.size}) must equal fixture gadget count (${multiBatchGadgetCount})`
      );
    });

    // -----------------------------------------------------------------------
    // Test 3: Idempotent upload handling (reportExists deduplication)
    // -----------------------------------------------------------------------
    await runAsyncTest('Test 3a: Skipping upload when report already exists (without --force)', async () => {
      mock.clear();
      // Handler returns 200 for GET (report already exists)
      mock.handler = (req, res) => {
        if (req.method === 'GET') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ name: req.url, fields: {} }));
          return;
        }
        res.writeHead(500);
        res.end();
      };

      const res = await runCli(singleBatchBinary, ['--upload-report'], {
        FIRESTORE_EMULATOR_HOST: emulatorHost
      });

      assert.strictEqual(res.status, 0, `CLI should exit 0 on skipped duplicate. Stderr: ${res.stderr}`);
      assert.strictEqual(mock.requests.length, 1, 'Only report existence check should be performed');
      assert.strictEqual(mock.requests[0].method, 'GET');
      assert.match(res.stdout, /already exists in Firebase Firestore/);
      assert.match(res.stdout, /Skipping upload to prevent database clutter/);
    });

    await runAsyncTest('Test 3b: Overwrite existing report when --force flag is passed', async () => {
      mock.clear();
      // Handler returns 200 for GET, but because --force is set, CLI will proceed to PATCH and POST
      let getHandled = false;
      mock.handler = (req, res, record) => {
        if (req.method === 'GET') {
          getHandled = true;
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ name: req.url, fields: {} }));
          return;
        }
        mock.defaultHandler(req, res, record);
      };

      const res = await runCli(singleBatchBinary, ['--upload-report', '--force'], {
        FIRESTORE_EMULATOR_HOST: emulatorHost
      });

      assert.strictEqual(res.status, 0, `CLI should exit 0 with --force. Stderr: ${res.stderr}`);
      assert.ok(mock.requests.some(r => r.method === 'PATCH'), 'PATCH request must be sent when --force is active');
      assert.ok(mock.requests.some(r => r.method === 'POST'), 'Gadget commit request must be sent when --force is active');
    });

    // -----------------------------------------------------------------------
    // Test 4: Partial gadget upload failure propagation (Task 5.9A3)
    // -----------------------------------------------------------------------
    await runAsyncTest('Test 4: Propagate gadget batch upload failure to CLI exit status 1', async () => {
      mock.clear();
      let commitCount = 0;
      mock.handler = (req, res, record) => {
        if (req.method === 'POST' && req.url.includes(':commit')) {
          commitCount++;
          if (commitCount >= 2) {
            // Persistently fail batch 2 (exhaust retry attempts)
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: { code: 500, message: 'Simulated backend storage error' } }));
            return;
          }
        }
        mock.defaultHandler(req, res, record);
      };

      const res = await runCli(multiBatchBinary, ['--upload-report'], {
        FIRESTORE_EMULATOR_HOST: emulatorHost
      });

      assert.strictEqual(res.status, 1, `CLI must exit with code 1 on partial gadget upload failure. Got: ${res.status}`);
      assert.match(res.stderr, /Firebase gadget upload failed or was incomplete/, 'Missing partial failure error message');
      assert.match(res.stderr, /in_progress/, 'Missing in_progress recovery message');
    });

    // -----------------------------------------------------------------------
    // Test 5: Report upload failure handling (HTTP 503)
    // -----------------------------------------------------------------------
    await runAsyncTest('Test 5: Propagate report upload failure (HTTP 503) to CLI exit status 1', async () => {
      mock.clear();
      mock.handler = (req, res) => {
        if (req.method === 'PATCH') {
          res.writeHead(503, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: { code: 503, message: 'Service Unavailable' } }));
          return;
        }
        if (req.method === 'GET') {
          res.writeHead(404, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: { code: 404 } }));
          return;
        }
      };

      const res = await runCli(singleBatchBinary, ['--upload-report'], {
        FIRESTORE_EMULATOR_HOST: emulatorHost
      });

      assert.strictEqual(res.status, 1, `CLI must exit with code 1 when report upload fails. Got: ${res.status}`);
      assert.match(res.stderr, /Firebase upload failed/, 'Missing upload failure message in stderr');
      // Must NOT attempt gadget upload if report upload failed
      assert.strictEqual(mock.requests.filter(r => r.method === 'POST').length, 0, 'No gadget commits should occur after report failure');
    });

    // -----------------------------------------------------------------------
    // Test 6: Strict validation of FIRESTORE_EMULATOR_HOST
    // -----------------------------------------------------------------------
    await runAsyncTest('Test 6a: Reject remote host (evil.com:8080)', async () => {
      mock.clear();
      const res = await runCli(singleBatchBinary, ['--upload-report'], {
        FIRESTORE_EMULATOR_HOST: 'evil.com:8080'
      });

      assert.strictEqual(res.status, 1, 'CLI must exit 1 on invalid remote emulator host');
      assert.match(res.stderr, /not a permitted loopback address/);
      assert.strictEqual(mock.requests.length, 0, 'No requests should be sent to mock or remote');
    });

    await runAsyncTest('Test 6b: Reject scheme prefix (http://127.0.0.1:8080)', async () => {
      mock.clear();
      const res = await runCli(singleBatchBinary, ['--upload-report'], {
        FIRESTORE_EMULATOR_HOST: `http://${emulatorHost}`
      });

      assert.strictEqual(res.status, 1, 'CLI must exit 1 on scheme in emulator host');
      assert.match(res.stderr, /Invalid FIRESTORE_EMULATOR_HOST/);
      assert.strictEqual(mock.requests.length, 0, 'No requests should be sent');
    });

    await runAsyncTest('Test 6c: Reject URL path (127.0.0.1:8080/v1)', async () => {
      mock.clear();
      const res = await runCli(singleBatchBinary, ['--upload-report'], {
        FIRESTORE_EMULATOR_HOST: `${emulatorHost}/v1`
      });

      assert.strictEqual(res.status, 1, 'CLI must exit 1 on path in emulator host');
      assert.match(res.stderr, /Invalid FIRESTORE_EMULATOR_HOST/);
      assert.strictEqual(mock.requests.length, 0, 'No requests should be sent');
    });

    await runAsyncTest('Test 6d: Reject invalid port number (127.0.0.1:99999)', async () => {
      mock.clear();
      const res = await runCli(singleBatchBinary, ['--upload-report'], {
        FIRESTORE_EMULATOR_HOST: '127.0.0.1:99999'
      });

      assert.strictEqual(res.status, 1, 'CLI must exit 1 on out-of-range port');
      assert.match(res.stderr, /port out of range/);
      assert.strictEqual(mock.requests.length, 0, 'No requests should be sent');
    });

    await runAsyncTest('Test 6e: Reject trailing colon with empty port (127.0.0.1:)', async () => {
      mock.clear();
      const res = await runCli(singleBatchBinary, ['--upload-report'], {
        FIRESTORE_EMULATOR_HOST: '127.0.0.1:'
      });

      assert.strictEqual(res.status, 1, 'CLI must exit 1 on trailing colon without port');
      assert.match(res.stderr, /trailing colon with missing port/);
      assert.strictEqual(mock.requests.length, 0, 'No requests should be sent');
    });

    await runAsyncTest('Test 6f: Accept IPv6 loopback ([::1]:port)', async () => {
      // Create an IPv6 mock server on [::1]
      let ipv6Port = 0;
      let ipv6Server = null;
      try {
        await new Promise((resolve, reject) => {
          ipv6Server = http.createServer((req, res) => {
            if (req.method === 'GET') {
              res.writeHead(404, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ error: { code: 404 } }));
              return;
            }
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ fields: {}, writeResults: [] }));
          });
          ipv6Server.on('error', reject);
          ipv6Server.listen(0, '::1', () => {
            ipv6Port = ipv6Server.address().port;
            resolve();
          });
        });
      } catch (err) {
        const skippedCodes = ['EAFNOSUPPORT', 'EADDRNOTAVAIL', 'ENETUNREACH', 'EACCES'];
        if (skippedCodes.includes(err.code)) {
          return { skipped: true, reason: `IPv6 loopback bind unavailable on host: ${err.code} (${err.message})` };
        }
        throw err;
      }

      try {
        const res = await runCli(singleBatchBinary, ['--upload-report'], {
          FIRESTORE_EMULATOR_HOST: `[::1]:${ipv6Port}`
        });

        assert.strictEqual(res.status, 0, `CLI should accept [::1]:${ipv6Port}. Stderr: ${res.stderr}`);
      } finally {
        if (ipv6Server) {
          await new Promise(r => ipv6Server.close(r));
        }
      }
    });

  } finally {
    // Requirement: Mock server is guaranteed to shut down in finally blocks
    await mock.stop();
    console.log('[*] Mock Firestore server stopped.');
  }

  // -------------------------------------------------------------------------
  // Verify protected repository artifacts remained completely untouched
  // -------------------------------------------------------------------------
  runTest('Protected Artifact Integrity: output.json and payload.bin hashes intact', () => {
    verifyProtectedArtifacts('post-test suite completion');
  });

  console.log(`\n=== Test Summary: ${passCount} Passed, ${failCount} Failed, ${skipCount} Skipped ===\n`);
  if (failCount > 0) {
    process.exit(1);
  }
}

main().catch(err => {
  console.error('[!] Unexpected test runner error:', err);
  process.exit(1);
});
