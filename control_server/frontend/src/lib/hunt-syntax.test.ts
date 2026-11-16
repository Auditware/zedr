import { describe, expect, it } from 'vitest'
import { huntPieces } from './hunt-syntax'

function kinds(source: string): string[] {
  return huntPieces(source)
    .filter((piece) => piece.kind !== 'plain')
    .map((piece) => `${piece.kind}:${piece.text}`)
}

describe('huntPieces', () => {
  it('tells the kind, the fields, the operators and the values apart', () => {
    expect(kinds('process where name = rundll32.exe and not parent.name ~ "power shell"')).toEqual([
      'kind:process',
      'keyword:where',
      'field:name',
      'operator:=',
      'value:rundll32.exe',
      'keyword:and',
      'keyword:not',
      'field:parent.name',
      'operator:~',
      'value:"power shell"',
    ])
  })

  it('reads every word of a list as a value, and a word named like a keyword after an operator too', () => {
    expect(kinds('package where name in (openssl, and) or version >= 3.0.14 and name != in')).toEqual([
      'kind:package',
      'keyword:where',
      'field:name',
      'keyword:in',
      'operator:(',
      'value:openssl',
      'operator:,',
      'value:and',
      'operator:)',
      'keyword:or',
      'field:version',
      'operator:>=',
      'value:3.0.14',
      'keyword:and',
      'field:name',
      'operator:!=',
      'value:in',
    ])
  })

  it('loses nothing of what was typed, even half a query', () => {
    for (const source of ['', 'proc', 'file where path ~ "C:\\Users\\Public', '  detection   where level=high  ', "connection where dest.ip = '10.0.0.1"]) {
      const pieces = huntPieces(source)
      expect(pieces.map((piece) => piece.text).join('')).toBe(source)
      for (const piece of pieces) expect(source.slice(piece.start, piece.start + piece.text.length)).toBe(piece.text)
    }
  })
})
