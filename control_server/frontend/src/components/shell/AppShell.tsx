import { useQueryClient } from '@tanstack/react-query'
import { Outlet } from '@tanstack/react-router'
import { useEffect } from 'react'
import { useSession } from '@/lib/auth'
import { connectLive } from '@/lib/live'
import { useUi } from '@/lib/ui'
import { Rail } from './Rail'
import { TopBar } from './TopBar'

export function AppShell() {
  const queryClient = useQueryClient()
  const token = useSession((state) => state.session?.token)
  const toggleRail = useUi((state) => state.toggleRail)

  useEffect(() => {
    if (!token) return
    return connectLive(queryClient)
  }, [queryClient, token])

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'b') {
        event.preventDefault()
        toggleRail()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [toggleRail])

  return (
    <div className="flex h-full overflow-hidden bg-ink max-md:flex-col">
      <Rail />
      <div className="flex min-h-0 min-w-0 flex-1 flex-col">
        <TopBar />
        <main className="relative min-h-0 min-w-0 flex-1">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
