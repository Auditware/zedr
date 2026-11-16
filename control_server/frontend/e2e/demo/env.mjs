import { execFileSync, spawn } from 'node:child_process'
import { createHash, createPrivateKey, createPublicKey, randomBytes, X509Certificate } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, rmSync } from 'node:fs'
import https from 'node:https'
import net from 'node:net'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
export const FRONTEND = path.resolve(here, '../..')
export const CONSOLE_DIST = path.join(FRONTEND, 'e2e/.out/console')
export const DEMO_DIR = path.join(FRONTEND, 'e2e/.demo')
export const CERT = path.join(DEMO_DIR, 'cert.pem')
export const KEY = path.join(DEMO_DIR, 'key.pem')
export const DEV_TENANT = tenant('dev', 7797)
export const SWEEP_TENANT = tenant('sweep', 7798)
const SERVER_BINARY = path.resolve(FRONTEND, '../backend/target/debug/zedr-control-server')
const PROVER = path.resolve(FRONTEND, '../../prover/host/target/release/zedr-prover')
const ED25519_PKCS8_PREFIX = '302e020100300506032b657004220420'

function tenant(name, port) {
  return { name, port, url: `https://localhost:${port}`, data: path.join(DEMO_DIR, name) }
}

export function ensureCertificate() {
  mkdirSync(DEMO_DIR, { recursive: true })
  if (existsSync(CERT) && existsSync(KEY)) return
  execFileSync(
    'openssl',
    [
      'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
      '-keyout', KEY, '-out', CERT, '-days', '30', '-subj', '/CN=localhost',
      '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
    ],
    { stdio: 'ignore' },
  )
}

export function certificatePin() {
  const certificate = new X509Certificate(readFileSync(CERT))
  const spki = certificate.publicKey.export({ type: 'spki', format: 'der' })
  return createHash('sha256').update(spki).digest('base64')
}

export function demoClient(url) {
  const agent = new https.Agent({ ca: readFileSync(CERT), keepAlive: true })
  return function call(method, route, { token, body, signature } = {}) {
    return new Promise((resolve, reject) => {
      const headers = {}
      if (token) headers.authorization = `Bearer ${token}`
      if (body !== undefined) {
        headers['content-type'] = 'application/json'
        headers['content-length'] = Buffer.byteLength(body)
      }
      if (signature) headers['x-zedr-signature'] = signature
      const request = https.request(url + route, { method, headers, agent }, (response) => {
        const chunks = []
        response.on('data', (chunk) => chunks.push(chunk))
        response.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8')
          let json = null
          try {
            json = JSON.parse(text)
          } catch {
            json = null
          }
          resolve({ status: response.statusCode, json })
        })
      })
      request.on('error', reject)
      if (body !== undefined) request.write(body)
      request.end()
    })
  }
}

async function waitUntilHealthy(url) {
  const call = demoClient(url)
  for (let attempt = 0; attempt < 80; attempt++) {
    try {
      const response = await call('GET', '/healthz')
      if (response.status === 200) return
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 150))
    }
  }
  throw new Error(`control server did not become healthy on ${url}`)
}

function portInUse(port) {
  return new Promise((resolve) => {
    const socket = net.connect({ host: '127.0.0.1', port })
    socket.once('connect', () => {
      socket.destroy()
      resolve(true)
    })
    socket.once('error', () => resolve(false))
  })
}

function deploymentKeyOf(signingKeyHex) {
  const signingKey = createPrivateKey({ key: Buffer.from(ED25519_PKCS8_PREFIX + signingKeyHex, 'hex'), format: 'der', type: 'pkcs8' })
  return createPublicKey(signingKey).export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex')
}

export async function startServer({ port, url, data }, { origin, consoleDist }) {
  if (!existsSync(SERVER_BINARY)) {
    throw new Error(`missing ${SERVER_BINARY}: run "cargo build" in control_server/backend first`)
  }
  if (consoleDist && !existsSync(path.join(consoleDist, 'index.html'))) {
    throw new Error(`missing ${consoleDist}: "npm run sweep" builds it`)
  }
  if (await portInUse(port)) {
    throw new Error(`port ${port} is already in use, stop the process that holds it before starting a test tenant`)
  }
  ensureCertificate()

  rmSync(data, { recursive: true, force: true })
  mkdirSync(path.join(data, 'binaries'), { recursive: true })

  const password = `Aa1!${randomBytes(12).toString('hex')}`
  const signingKey = randomBytes(32).toString('hex')
  const prover = existsSync(PROVER) ? PROVER : null
  if (!prover) console.error(`no prover at ${PROVER}: the test tenant runs without proofs, run "make guest && make prover" to have them`)
  const env = {
    PATH: process.env.PATH,
    ZEDR_SERVER_HOST: '127.0.0.1',
    ZEDR_SERVER_PORT: String(port),
    ZEDR_SERVER_URL: url,
    ZEDR_CORS_ORIGIN: origin,
    DATABASE_URL: `sqlite://${path.join(data, 'demo.sqlite')}?mode=rwc`,
    ZEDR_AGENT_VERSION: '0.1.0',
    JWT_SECRET: randomBytes(32).toString('hex'),
    ADMIN_PASSWORD: password,
    ZEDR_SIGNING_KEY_HEX: signingKey,
    ZEDR_TLS_CERT_PATH: CERT,
    ZEDR_TLS_KEY_PATH: KEY,
    ZEDR_BINARIES_DIR: path.join(data, 'binaries'),
    ZEDR_LOG_LEVEL: 'zedr_control_server=warn',
  }
  if (consoleDist) env.ZEDR_FRONTEND_DIST = consoleDist
  if (prover) env.ZEDR_GUEST_IMAGE_IDS = execFileSync(prover, ['image-id'], { encoding: 'utf8' }).trim()

  const server = spawn(SERVER_BINARY, [], { cwd: data, stdio: ['ignore', 'ignore', 'inherit'], env })
  const exited = new Promise((resolve) => {
    server.once('exit', (code, signal) => resolve(signal ? `signal ${signal}` : `code ${code}`))
  })
  const early = exited.then((how) => {
    throw new Error(`control server ended with ${how} before it was healthy`)
  })
  early.catch(() => undefined)
  await Promise.race([waitUntilHealthy(url), early])
  return { password, deploymentKey: deploymentKeyOf(signingKey), prover, exited, stop: () => server.kill('SIGTERM') }
}

export function startSimulator({ url, data }, { password, deploymentKey, prover }) {
  const child = spawn(process.execPath, [path.join(here, 'sim.mjs')], {
    stdio: ['ignore', 'pipe', 'inherit'],
    env: {
      PATH: process.env.PATH,
      HOME: process.env.HOME,
      ZEDR_DEMO_URL: url,
      ZEDR_DEMO_PASSWORD: password,
      ZEDR_DEMO_DEPLOYMENT_KEY: deploymentKey,
      ZEDR_DEMO_STATE: path.join(data, 'agents'),
      ZEDR_DEMO_PROVER: prover ?? '',
    },
  })
  let output = ''
  const said = (word) =>
    new Promise((resolve, reject) => {
      const look = () => {
        if (output.includes(word)) resolve()
      }
      child.stdout.on('data', look)
      child.on('exit', (code) => reject(new Error(`simulator exited with code ${code} before it said ${word}`)))
      look()
    })
  child.stdout.on('data', (chunk) => {
    output += chunk.toString('utf8')
  })
  const proven = said('PROVEN')
  proven.catch(() => undefined)
  return said('READY').then(() => ({ proven, stop: () => child.kill('SIGTERM') }))
}
