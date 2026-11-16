export type Strand = { from: [number, number]; to: [number, number]; slot: [number, number] }

const THINNEST = 1.5

export function fan(values: number[], thickness: number, slot: number, gap: number): { strands: Strand[]; height: number } {
  const total = values.reduce((sum, value) => sum + value, 0)
  const widths = values.map((value) => (value > 0 ? Math.max(THINNEST, (value / total) * thickness) : 0))
  let cursor = 0
  const slots = widths.map((width) => {
    const tall = Math.max(width, slot)
    const range: [number, number] = [cursor, cursor + tall]
    cursor += tall + gap
    return range
  })
  const height = Math.max(0, cursor - gap)
  let start = (height - widths.reduce((sum, width) => sum + width, 0)) / 2
  const strands = widths.map((width, index) => {
    const middle = (slots[index]![0] + slots[index]![1]) / 2
    const strand: Strand = { from: [start, start + width], to: [middle - width / 2, middle + width / 2], slot: slots[index]! }
    start += width
    return strand
  })
  return { strands, height }
}

export function strandPath({ from, to }: Strand, left: number, right: number): string {
  const bend = (left + right) / 2
  return `M${left} ${from[0]} C${bend} ${from[0]} ${bend} ${to[0]} ${right} ${to[0]} L${right} ${to[1]} C${bend} ${to[1]} ${bend} ${from[1]} ${left} ${from[1]} Z`
}
