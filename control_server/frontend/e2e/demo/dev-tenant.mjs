import { readFileSync } from 'node:fs'
import https from 'node:https'
import { CERT, DEV_TENANT, demoClient, ensureCertificate, startServer, startSimulator } from './env.mjs'

const SLOT = Symbol.for('zedr.dev-tenant')

async function start(origin) {
  const server = await startServer(DEV_TENANT, { origin })
  let simulator
  try {
    simulator = await startSimulator(DEV_TENANT, server)
  } catch (error) {
    server.stop()
    throw error
  }
  const stop = () => {
    simulator.stop()
    server.stop()
  }
  process.once('exit', stop)
  server.exited.then((how) => {
    process.off('exit', stop)
    simulator.stop()
    globalThis[SLOT] = undefined
    console.error(`test tenant server ended with ${how}, the next sign-in starts a new one`)
  })
  return { password: server.password }
}

function tenant(origin) {
  globalThis[SLOT] ??= start(origin).catch((error) => {
    globalThis[SLOT] = undefined
    throw error
  })
  return globalThis[SLOT]
}

export function devTenant() {
  return {
    name: 'zedr-dev-tenant',
    config() {
      ensureCertificate()
      const upstream = {
        target: DEV_TENANT.url,
        changeOrigin: true,
        agent: new https.Agent({ ca: readFileSync(CERT), keepAlive: true }),
      }
      return { server: { proxy: { '/api': { ...upstream, ws: true }, '/api-docs': upstream } } }
    },
    async configureServer(vite) {
      const origin = `http://localhost:${vite.config.server.port}`
      await tenant(origin)
      const call = demoClient(DEV_TENANT.url)
      vite.middlewares.use('/__dev/login', (request, response) => {
        if (request.method !== 'POST' || request.headers['sec-fetch-site'] !== 'same-origin') {
          response.statusCode = 403
          response.end()
          return
        }
        tenant(origin)
          .then(({ password }) => call('POST', '/api/auth/login', { body: JSON.stringify({ username: 'admin', password }) }))
          .then(
            (login) => {
              response.statusCode = login.status
              response.setHeader('content-type', 'application/json')
              response.end(JSON.stringify(login.json))
            },
            () => {
              response.statusCode = 502
              response.end()
            },
          )
      })
    },
  }
}
