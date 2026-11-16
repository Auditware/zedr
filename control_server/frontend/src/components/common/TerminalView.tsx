import type { Terminal } from '@xterm/xterm'
import { useEffect, useRef, useState } from 'react'
import type { ShellCommandResult } from '@/lib/api'
import { resolveTone } from '@/lib/palette'

const DIM = '\x1b[38;2;147;160;184m'
const ACCENT = '\x1b[38;2;143;188;255m'
const ALERT = '\x1b[38;2;255;176;122m'
const RESET = '\x1b[0m'
const CLEAR_LINE = '\r\x1b[2K'

type Props = {
  sessionId: string
  host: string
  commands: ShellCommandResult[]
  readOnly: boolean
  onRun: (command: string) => Promise<string>
}

type Live = {
  term: Terminal | null
  buffer: string
  printed: Map<string, 'queued' | 'done'>
  lastEcho: string | null
  history: string[]
  cursor: number
  started: boolean
}

export function TerminalView({ sessionId, host, commands, readOnly, onRun }: Props) {
  const hostRef = useRef<HTMLDivElement>(null)
  const live = useRef<Live>({ term: null, buffer: '', printed: new Map(), lastEcho: null, history: [], cursor: -1, started: false })
  const prompt = `${ACCENT}${host}${RESET} PS> `
  const latest = useRef({ onRun, readOnly, prompt })
  latest.current = { onRun, readOnly, prompt }
  const [ready, setReady] = useState(false)

  useEffect(() => {
    const element = hostRef.current
    if (!element) return
    let cancelled = false
    let teardown = () => undefined as void
    const state: Live = { term: null, buffer: '', printed: new Map(), lastEcho: null, history: [], cursor: -1, started: false }
    live.current = state
    setReady(false)

    void (async () => {
      const [{ Terminal: TerminalClass }, { FitAddon }] = await Promise.all([
        import('@xterm/xterm'),
        import('@xterm/addon-fit'),
        import('@xterm/xterm/css/xterm.css'),
      ])
      if (cancelled) return

      const term = new TerminalClass({
        fontFamily: '"JetBrains Mono Variable", ui-monospace, monospace',
        fontSize: 13,
        lineHeight: 1.35,
        cursorBlink: true,
        convertEol: true,
        scrollback: 5000,
        theme: {
          background: resolveTone('sunken'),
          foreground: resolveTone('text'),
          cursor: resolveTone('alert'),
          selectionBackground: `${resolveTone('text')}38`,
        },
      })
      const fit = new FitAddon()
      term.loadAddon(fit)
      term.open(element)
      fit.fit()
      state.term = term

      const redraw = () => term.write(`${CLEAR_LINE}${latest.current.prompt}${state.buffer}`)

      const input = term.onData((data) => {
        if (latest.current.readOnly) return
        if (data === '\x1b[A' || data === '\x1b[B') {
          if (state.history.length === 0) return
          const step = data === '\x1b[A' ? 1 : -1
          state.cursor = Math.max(-1, Math.min(state.history.length - 1, state.cursor + step))
          state.buffer = state.cursor === -1 ? '' : state.history[state.history.length - 1 - state.cursor]!
          redraw()
          return
        }
        if (data.startsWith('\x1b')) return
        for (const char of data) {
          if (char === '\r' || char === '\n') {
            const command = state.buffer.trim()
            state.buffer = ''
            state.cursor = -1
            term.write('\r\n')
            if (command) {
              state.history.push(command)
              void latest.current
                .onRun(command)
                .then((id) => {
                  if (!state.printed.has(id)) state.printed.set(id, 'queued')
                  state.lastEcho = id
                })
                .catch((cause: unknown) => {
                  const message = cause instanceof Error ? cause.message : 'not sent'
                  term.write(`${CLEAR_LINE}${ALERT}${message}${RESET}\r\n${latest.current.prompt}${state.buffer}`)
                })
            }
            term.write(latest.current.prompt)
          } else if (char === '\x7f') {
            if (state.buffer.length > 0) {
              state.buffer = state.buffer.slice(0, -1)
              term.write('\b \b')
            }
          } else if (char === '\x03') {
            state.buffer = ''
            term.write(`^C\r\n${latest.current.prompt}`)
          } else if (char >= ' ') {
            state.buffer += char
            term.write(char)
          }
        }
      })

      const resize = new ResizeObserver(() => fit.fit())
      resize.observe(element)

      teardown = () => {
        resize.disconnect()
        input.dispose()
        term.dispose()
        state.term = null
      }
      setReady(true)
    })()

    return () => {
      cancelled = true
      teardown()
    }
  }, [sessionId])

  useEffect(() => {
    const state = live.current
    const term = state.term
    if (!ready || !term) return
    const first = !state.started
    state.started = true
    let wrote = false
    const ordered = [...commands].sort((a, b) => a.issued_at - b.issued_at)

    for (const command of ordered) {
      const status = state.printed.get(command.id)
      const executed = command.executed_at != null
      if (status === 'done') continue
      if (status === undefined) {
        if (!wrote) term.write(CLEAR_LINE)
        term.write(`${prompt}${command.command_text}\r\n`)
        state.history.push(command.command_text)
        state.lastEcho = command.id
        wrote = true
        state.printed.set(command.id, 'queued')
      }
      if (!executed) continue
      if (!wrote) term.write(CLEAR_LINE)
      wrote = true
      if (state.lastEcho !== command.id) term.write(`${DIM}# ${command.command_text}${RESET}\r\n`)
      if (command.stdout) term.write(command.stdout.endsWith('\n') ? command.stdout : `${command.stdout}\r\n`)
      if (command.stderr) {
        const stderr = command.stderr.endsWith('\n') ? command.stderr : `${command.stderr}\r\n`
        term.write(`${ALERT}${stderr}${RESET}`)
      }
      const took = Math.max(0, (command.executed_at ?? command.issued_at) - command.issued_at)
      const color = command.exit_code === 0 ? DIM : ALERT
      term.write(`${color}[exit ${command.exit_code ?? '?'} · ${took}s]${RESET}\r\n`)
      state.printed.set(command.id, 'done')
      state.lastEcho = null
    }

    if (wrote || first) {
      if (latest.current.readOnly) term.write(`${DIM}[session ended]${RESET}\r\n`)
      else term.write(`${prompt}${state.buffer}`)
    }
    // the prompt is stable for a session, see above
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [commands, ready])

  return <div ref={hostRef} className="h-full w-full overflow-hidden" aria-label={`Terminal on ${host}`} />
}
