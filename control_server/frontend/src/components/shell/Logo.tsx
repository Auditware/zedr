export function Logo({ size = 22 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" role="img" aria-label="zedr" className="shrink-0">
      <circle cx="32" cy="32" r="10.8" className="fill-text" />
      <circle cx="32" cy="10.4" r="7.8" className="fill-node" />
      <circle cx="50.71" cy="21.2" r="7.8" className="fill-node" />
      <circle cx="50.71" cy="42.8" r="7.8" className="fill-alert" />
      <circle cx="32" cy="53.6" r="7.8" className="fill-node" />
      <circle cx="13.29" cy="42.8" r="7.8" className="fill-node" />
      <circle cx="13.29" cy="21.2" r="7.8" className="fill-node" />
    </svg>
  )
}
