import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { RouterProvider } from '@tanstack/react-router'
import * as Tooltip from '@radix-ui/react-tooltip'
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { useSession } from '@/lib/auth'
import { router } from './router'
import '@fontsource-variable/inter'
import '@fontsource-variable/jetbrains-mono'
import './styles.css'

const queryClient = new QueryClient({
  defaultOptions: { queries: { staleTime: 5_000, retry: 1, refetchOnWindowFocus: false } },
})

useSession.subscribe((state, previous) => {
  if (state.session === previous.session) return
  queryClient.clear()
  void router.invalidate()
})

const root = document.getElementById('root')
if (!root) throw new Error('Missing #root element')

createRoot(root).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <Tooltip.Provider>
        <RouterProvider router={router} />
      </Tooltip.Provider>
    </QueryClientProvider>
  </StrictMode>,
)
