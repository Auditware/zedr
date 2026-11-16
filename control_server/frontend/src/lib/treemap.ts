export type Tile<T> = { item: T; x: number; y: number; width: number; height: number }

type Weighted<T> = { item: T; area: number }

function worst(row: number[], side: number): number {
  const sum = row.reduce((total, area) => total + area, 0)
  const square = side * side
  return Math.max((square * Math.max(...row)) / (sum * sum), (sum * sum) / (square * Math.min(...row)))
}

export function squarify<T>(items: { item: T; value: number }[], width: number, height: number): Tile<T>[] {
  const kept = items.filter((entry) => entry.value > 0).sort((a, b) => b.value - a.value)
  const total = kept.reduce((sum, entry) => sum + entry.value, 0)
  if (total === 0 || width <= 0 || height <= 0) return []
  const queue: Weighted<T>[] = kept.map((entry) => ({ item: entry.item, area: (entry.value / total) * width * height }))
  const tiles: Tile<T>[] = []
  let x = 0
  let y = 0
  let w = width
  let h = height
  let row: Weighted<T>[] = []

  const place = () => {
    const sum = row.reduce((sumSoFar, entry) => sumSoFar + entry.area, 0)
    if (w >= h) {
      const thick = sum / h
      let at = y
      for (const entry of row) {
        const long = entry.area / thick
        tiles.push({ item: entry.item, x, y: at, width: thick, height: long })
        at += long
      }
      x += thick
      w -= thick
    } else {
      const thick = sum / w
      let at = x
      for (const entry of row) {
        const long = entry.area / thick
        tiles.push({ item: entry.item, x: at, y, width: long, height: thick })
        at += long
      }
      y += thick
      h -= thick
    }
    row = []
  }

  for (const entry of queue) {
    const side = Math.min(w, h)
    const areas = row.map((placed) => placed.area)
    if (row.length > 0 && worst([...areas, entry.area], side) > worst(areas, side)) place()
    row.push(entry)
  }
  if (row.length > 0) place()
  return tiles
}
