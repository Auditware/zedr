import { defineConfig } from '@playwright/test'
import { certificatePin, ensureCertificate, SWEEP_TENANT } from './e2e/demo/env.mjs'

ensureCertificate()

export default defineConfig({
  testDir: './e2e',
  outputDir: './e2e/.out/results',
  fullyParallel: false,
  workers: 1,
  timeout: 240_000,
  reporter: [['list']],
  globalSetup: './e2e/global-setup.ts',
  use: {
    baseURL: SWEEP_TENANT.url,
    channel: 'chrome',
    launchOptions: { args: [`--ignore-certificate-errors-spki-list=${certificatePin()}`] },
  },
  projects: [
    { name: 'desktop', use: { viewport: { width: 1440, height: 900 } } },
    { name: 'laptop', use: { viewport: { width: 1280, height: 720 } } },
    { name: 'pane', use: { viewport: { width: 1000, height: 900 } } },
  ],
})
