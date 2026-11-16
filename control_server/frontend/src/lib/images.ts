const INTERPRETERS = new Set([
  'powershell.exe',
  'pwsh.exe',
  'pwsh',
  'cmd.exe',
  'wscript.exe',
  'cscript.exe',
  'mshta.exe',
  'rundll32.exe',
  'regsvr32.exe',
  'bash',
  'sh',
  'zsh',
  'dash',
  'fish',
  'python',
  'python3',
  'perl',
  'ruby',
  'node',
  'osascript',
])

export function baseName(path: string): string {
  const parts = path.split(/[\\/]/)
  return parts[parts.length - 1] || path
}

export function isInterpreter(name: string): boolean {
  return INTERPRETERS.has(name.toLowerCase())
}
