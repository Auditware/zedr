import { CONSOLE_DIST, startServer, startSimulator, SWEEP_TENANT } from './demo/env.mjs'

export default async function globalSetup() {
  const server = await startServer(SWEEP_TENANT, { origin: SWEEP_TENANT.url, consoleDist: CONSOLE_DIST })
  const simulator = await startSimulator(SWEEP_TENANT, server)
  await simulator.proven
  process.env.ZEDR_DEMO_PASSWORD = server.password
  process.env.ZEDR_DEMO_PROVER = server.prover ?? ''
  return async () => {
    simulator.stop()
    server.stop()
  }
}
