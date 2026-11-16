export type PieceKind = 'kind' | 'keyword' | 'field' | 'operator' | 'value' | 'plain'
export type Piece = { text: string; kind: PieceKind; start: number }

const KEYWORDS = new Set(['where', 'and', 'or', 'not', 'in'])
const TOKEN = /("[^"]*"?|'[^']*'?)|(!=|!~|>=|<=|=|~|>|<)|([(),])|(\s+)|([^\s"'=!~<>(),]+)/g

export function huntPieces(source: string): Piece[] {
  const pieces: Piece[] = []
  let first = true
  let value = false
  let list = false
  for (const match of source.matchAll(TOKEN)) {
    const [text, quoted, operator, bracket, space, word] = match
    const start = match.index
    if (space !== undefined) {
      pieces.push({ text, kind: 'plain', start })
    } else if (quoted !== undefined) {
      pieces.push({ text, kind: 'value', start })
      value = false
    } else if (operator !== undefined) {
      pieces.push({ text, kind: 'operator', start })
      value = true
    } else if (bracket !== undefined) {
      pieces.push({ text, kind: 'operator', start })
      if (bracket === ')') list = false
    } else if (word !== undefined) {
      const lowered = word.toLowerCase()
      if (first) pieces.push({ text, kind: 'kind', start })
      else if (value || list) pieces.push({ text, kind: 'value', start })
      else if (KEYWORDS.has(lowered)) pieces.push({ text, kind: 'keyword', start })
      else pieces.push({ text, kind: 'field', start })
      if (!first && !value && !list && lowered === 'in') list = true
      value = false
      first = false
    }
  }
  return pieces
}
