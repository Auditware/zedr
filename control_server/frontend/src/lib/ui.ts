import { create } from 'zustand'

const RAIL_KEY = 'zedr.ui.rail'

type UiStore = {
  railOpen: boolean
  toggleRail: () => void
}

export const useUi = create<UiStore>((set) => ({
  railOpen: localStorage.getItem(RAIL_KEY) !== 'closed',
  toggleRail: () =>
    set((state) => {
      const railOpen = !state.railOpen
      localStorage.setItem(RAIL_KEY, railOpen ? 'open' : 'closed')
      return { railOpen }
    }),
}))
