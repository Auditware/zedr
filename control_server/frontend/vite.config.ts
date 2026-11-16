import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import path from 'path'
import { devTenant } from './e2e/demo/dev-tenant.mjs'

export default defineConfig(({ command, mode, isPreview }) => {
  const developing = command === 'serve' && mode !== 'test' && !isPreview
  const sweep = mode === 'sweep'

  return {
    plugins: [react(), ...(developing ? [devTenant()] : [])],
    resolve: {
      alias: { '@': path.resolve(__dirname, 'src') },
    },
    test: {
      environment: 'node',
      include: ['src/**/*.test.ts', 'src/**/*.test.tsx'],
    },
    server: {
      port: 7771,
      strictPort: true,
      open: true,
    },
    optimizeDeps: {
      include: ['@xyflow/react', 'pixi.js', 'qrcode'],
    },
    envDir: '../../secrets',
    // The sweep serves the console from the control server it tests, as the image does, so its build calls the origin it was loaded from
    // whatever API address the developer's environment names
    define: sweep ? { 'import.meta.env.VITE_API_URL': '""' } : undefined,
  }
})
