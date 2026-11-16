import { mkdirSync, rmSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { expect, type Page, type TestInfo } from '@playwright/test'

type Point = { id: string; x: number; y: number }
type MapPoint = Point & { label: string; state: string }
type Bridge = {
  map?: { nodes: () => MapPoint[]; view: () => { scale: number; x: number; y: number } }
  canvas?: { nodes: () => Point[]; viewport: () => { x: number; y: number; zoom: number } }
}

export type Recorder = {
  shot: (name: string) => Promise<void>
  expectError: (pattern: RegExp) => void
  note: (text: string) => void
  timed: <T>(name: string, action: () => Promise<T>) => Promise<T>
  finish: () => void
  errors: string[]
}

export function record(page: Page, info: TestInfo, journey: string): Recorder {
  const folder = path.join('e2e/.out/shots', info.project.name, journey)
  rmSync(folder, { recursive: true, force: true })
  mkdirSync(folder, { recursive: true })
  const errors: string[] = []
  const notes: string[] = []
  const expected: RegExp[] = []
  page.on('console', (message) => {
    if (message.type() === 'error') errors.push(message.text())
  })
  page.on('pageerror', (error) => errors.push(error.message))
  let step = 0
  const note = (text: string) => notes.push(text)
  return {
    errors,
    note,
    timed: async (name, action) => {
      const started = Date.now()
      const result = await action()
      note(`${name}: ${Date.now() - started} ms`)
      return result
    },
    shot: async (name) => {
      step += 1
      await page.screenshot({ path: path.join(folder, `${String(step).padStart(2, '0')}-${name}.png`) })
    },
    expectError: (pattern) => expected.push(pattern),
    finish: () => {
      const surprising = errors.filter((error) => !expected.some((pattern) => pattern.test(error)))
      writeFileSync(path.join(folder, 'notes.txt'), [...notes, ...surprising.map((error) => `console error: ${error}`)].join('\n') + '\n')
      expect(surprising).toEqual([])
    },
  }
}

export async function signIn(page: Page) {
  const password = process.env.ZEDR_DEMO_PASSWORD
  if (!password) throw new Error('ZEDR_DEMO_PASSWORD is not set, the demo server did not start')
  await page.addInitScript(() => localStorage.setItem('zedr.debug', '1'))
  await page.goto('/login')
  await page.getByLabel('Username').fill('admin')
  await page.getByLabel('Password').fill(password)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page, 'checking a password is slow on a debug server').toHaveURL(/\/endpoints/, { timeout: 30_000 })
}

export async function mapNodes(page: Page): Promise<MapPoint[]> {
  await page.waitForFunction(() => ((window as unknown as { __zedr?: Bridge }).__zedr?.map?.nodes().length ?? 0) > 0)
  return page.evaluate(() => (window as unknown as { __zedr: Bridge }).__zedr.map!.nodes())
}

export async function mapView(page: Page) {
  return page.evaluate(() => (window as unknown as { __zedr: Bridge }).__zedr.map!.view())
}

export async function canvasNodes(page: Page): Promise<Point[]> {
  await page.waitForFunction(() => ((window as unknown as { __zedr?: Bridge }).__zedr?.canvas?.nodes().length ?? 0) > 0)
  return page.evaluate(() => (window as unknown as { __zedr: Bridge }).__zedr.canvas!.nodes())
}

export async function canvasView(page: Page) {
  return page.evaluate(() => (window as unknown as { __zedr: Bridge }).__zedr.canvas!.viewport())
}

export async function settle(page: Page, ms = 450) {
  await page.waitForTimeout(ms)
}

export async function openHost(page: Page, hostname: string) {
  const nodes = await mapNodes(page)
  const target = nodes.find((node) => node.label === hostname)
  if (!target) throw new Error(`${hostname} is not on the map`)
  await page.goto(`/endpoints?host=${target.id}`)
  await expect(page.getByRole('navigation', { name: 'Breadcrumb' })).toContainText(hostname)
  return target.id
}

export async function pinch(page: Page, x: number, y: number, deltaY: number) {
  await page.mouse.move(x, y)
  await page.keyboard.down('Control')
  await page.mouse.wheel(0, deltaY)
  await page.keyboard.up('Control')
}

export async function drag(page: Page, from: { x: number; y: number }, dx: number, dy: number, steps = 12) {
  await page.mouse.move(from.x, from.y)
  await page.mouse.down()
  for (let step = 1; step <= steps; step++) {
    await page.mouse.move(from.x + (dx * step) / steps, from.y + (dy * step) / steps)
  }
  await page.mouse.up()
}

export async function expectNothingCutOff(page: Page, container: string, rows: string) {
  const overflow = await page.evaluate(
    ([containerSelector, rowSelector]) => {
      const box = document.querySelector(containerSelector!)?.getBoundingClientRect()
      if (!box) return [`missing ${containerSelector}`]
      const cut: string[] = []
      for (const row of document.querySelectorAll(`${containerSelector} ${rowSelector}`)) {
        for (const cell of row.children) {
          const rect = cell.getBoundingClientRect()
          if (rect.width > 0 && (rect.right > box.right + 1 || rect.left < box.left - 1)) {
            cut.push(`${(cell.textContent ?? '').trim().slice(0, 30) || cell.tagName} ends at ${Math.round(rect.right)}, container at ${Math.round(box.right)}`)
          }
        }
      }
      return cut.slice(0, 5)
    },
    [container, rows],
  )
  expect(overflow, 'cells cut off by their container').toEqual([])
}
