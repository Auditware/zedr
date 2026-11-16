import { generateKeyPairSync, randomUUID, sign } from 'node:crypto'
import { demoClient } from './env.mjs'
import { fleet, pastHeartbeats, seeded, STORY, telemetry } from './scenario.mjs'

const HEARTBEAT_SECONDS = 30
const SPARE_KEYS = 3
const call = demoClient(process.env.ZEDR_DEMO_URL)
const random = seeded(20261116)
const now = () => Math.floor(Date.now() / 1000)

const login = await call('POST', '/api/auth/login', {
  body: JSON.stringify({ username: 'admin', password: process.env.ZEDR_DEMO_PASSWORD }),
})
if (login.status !== 200) throw new Error(`demo login failed with ${login.status}`)
const token = login.json.token

const agents = []
for (const endpoint of fleet()) {
  const issued = await call('POST', '/api/admin/installers/generate', { token, body: '{}' })
  const { publicKey, privateKey } = generateKeyPairSync('ed25519')
  const agent = { ...endpoint, id: randomUUID(), seq: 0, alive: true, next: now() + Math.floor(random() * HEARTBEAT_SECONDS) }
  const send = (route, body) => call('POST', route, { body, signature: sign(null, Buffer.from(body), privateKey).toString('hex') })
  const batch = (events) => JSON.stringify({ agent_id: agent.id, session: 1, seq: ++agent.seq, events })
  agent.send = send
  agent.batch = batch

  const registration = JSON.stringify({
    agent_id: agent.id,
    hostname: endpoint.host,
    platform: endpoint.platform,
    os_version: endpoint.os,
    architecture: endpoint.arch,
    version: endpoint.version,
    ip_address: endpoint.ip,
    public_key: publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex'),
    enrollment_key: issued.json.install_key,
    session: 1,
    seq: ++agent.seq,
  })
  const registered = await send('/api/agents/register', registration)
  if (registered.status !== 200) throw new Error(`enrolling ${endpoint.host} failed with ${registered.status}`)

  await send('/api/events', batch(pastHeartbeats(endpoint, now(), HEARTBEAT_SECONDS)))
  const first = batch([{ Heartbeat: { timestamp: now() } }])
  if (!STORY.quiet.includes(endpoint.host)) await send('/api/events', first)
  await send('/api/events', batch(telemetry(endpoint, now(), random)))

  if (endpoint.host === STORY.serviceStop) {
    await send('/api/events', batch([{ AgentStopping: { timestamp: now(), reason: 'ServiceStop' } }]))
    agent.alive = false
  }
  if (endpoint.host === STORY.replay) await send('/api/events', first)
  if (STORY.shutdown.includes(endpoint.host)) {
    await send('/api/events', batch([{ AgentStopping: { timestamp: now(), reason: 'SystemShutdown' } }]))
    agent.alive = false
  }
  if (STORY.quiet.includes(endpoint.host)) agent.alive = false
  agents.push(agent)
}

for (let spare = 0; spare < SPARE_KEYS; spare++) await call('POST', '/api/admin/installers/generate', { token, body: '{}' })

console.log(`READY ${agents.length} endpoints`)

setInterval(() => {
  const moment = now()
  for (const agent of agents) {
    if (!agent.alive || agent.next > moment) continue
    agent.next = moment + HEARTBEAT_SECONDS
    agent.send('/api/events', agent.batch([{ Heartbeat: { timestamp: moment } }])).catch(() => undefined)
  }
}, 1000)
