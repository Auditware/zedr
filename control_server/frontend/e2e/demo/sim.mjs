import { execFileSync, spawn } from 'node:child_process'
import { readFileSync } from 'node:fs'
import http from 'node:http'
import https from 'node:https'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { CERT, demoClient } from './env.mjs'
import { fleet, scenario, STORY } from './scenario.mjs'

const SPARE_KEYS = 3
const AGENT_WORKSPACE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../../agent')
const SIMULATOR = path.join(AGENT_WORKSPACE, 'target/debug/zedr-simulator')
const url = process.env.ZEDR_DEMO_URL
const call = demoClient(url)

try {
  execFileSync('cargo', ['build', '--quiet', '--package', 'zedr-simulator'], { cwd: AGENT_WORKSPACE, stdio: ['ignore', 'ignore', 'inherit'] })
} catch {
  throw new Error(`the fleet simulator did not build: run "cargo build --package zedr-simulator" in ${AGENT_WORKSPACE}`)
}

const login = await call('POST', '/api/auth/login', {
  body: JSON.stringify({ username: 'admin', password: process.env.ZEDR_DEMO_PASSWORD }),
})
if (login.status !== 200) throw new Error(`demo login failed with ${login.status}`)
const token = login.json.token
const installKey = async () => (await call('POST', '/api/admin/installers/generate', { token, body: '{}' })).json.install_key

const hosts = fleet().length
const enrollmentKeys = []
while (enrollmentKeys.length < hosts) enrollmentKeys.push(await installKey())

// The simulator speaks through the agent's own link, which trusts the system's certificate authorities and not the
// throwaway certificate of a test tenant, so its requests pass through this relay on the loopback interface.
// The relay is also the one who replays a signed request it saw go by, the way someone on the network path could.
const upstream = new https.Agent({ ca: readFileSync(CERT), keepAlive: true })
function forward(method, route, headers, body) {
  return new Promise((resolve, reject) => {
    const request = https.request(url + route, { method, headers, agent: upstream }, (response) => {
      const chunks = []
      response.on('data', (chunk) => chunks.push(chunk))
      response.on('end', () => resolve({ status: response.statusCode, body: Buffer.concat(chunks) }))
    })
    request.on('error', reject)
    request.end(body)
  })
}

let replayable = null
let replayedAgent = null
const relay = http.createServer((incoming, outgoing) => {
  const chunks = []
  incoming.on('data', (chunk) => chunks.push(chunk))
  incoming.on('end', () => {
    const body = Buffer.concat(chunks)
    const headers = { 'content-type': 'application/json', 'content-length': body.length, 'x-zedr-signature': incoming.headers['x-zedr-signature'] ?? '' }
    if (incoming.url === '/api/agents/register' && body.includes(`"hostname":"${STORY.replay}"`)) replayedAgent = JSON.parse(body).agent_id
    else if (incoming.url === '/api/events' && !replayable && replayedAgent && body.includes(replayedAgent)) replayable = { headers, body }
    forward(incoming.method, incoming.url, headers, body).then(
      (answer) => {
        outgoing.writeHead(answer.status, { 'content-type': 'application/json', 'content-length': answer.body.length })
        outgoing.end(answer.body)
      },
      () => {
        outgoing.writeHead(502)
        outgoing.end()
      },
    )
  })
})
await new Promise((resolve) => relay.listen(0, '127.0.0.1', resolve))

const simulator = spawn(SIMULATOR, [], { stdio: ['pipe', 'pipe', 'inherit'], detached: true })
const stop = () => {
  try {
    process.kill(-simulator.pid, 'SIGTERM')
  } catch {
    // the simulator and its provers are already gone
  }
  process.exit(0)
}
for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) process.on(signal, stop)
simulator.on('exit', (code) => {
  console.error(`fleet simulator ended with code ${code}`)
  process.exit(1)
})
simulator.stdin.end(
  JSON.stringify(
    scenario({
      server: `http://127.0.0.1:${relay.address().port}`,
      deploymentKey: process.env.ZEDR_DEMO_DEPLOYMENT_KEY,
      stateDir: process.env.ZEDR_DEMO_STATE,
      prover: process.env.ZEDR_DEMO_PROVER || null,
      enrollmentKeys,
      now: Math.floor(Date.now() / 1000),
    }),
  ),
)

let said = ''
let ready = false
simulator.stdout.on('data', async (chunk) => {
  said += chunk.toString('utf8')
  const lines = said.split('\n')
  said = lines.pop()
  for (const line of lines) {
    if (line.startsWith('READY') && !ready) {
      ready = true
      if (replayable) await forward('POST', '/api/events', replayable.headers, replayable.body)
      for (let spare = 0; spare < SPARE_KEYS; spare++) await installKey()
    }
    console.log(line)
  }
})
