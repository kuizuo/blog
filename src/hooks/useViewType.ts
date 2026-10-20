import { useCallback, useEffect, useState } from 'react'

export type ViewType = 'list' | 'grid'

export function useViewType() {
  const [viewType, setViewType] = useState<ViewType>('list')

  useEffect(() => {
    try {
      const savedView = localStorage.getItem('viewType')
      if (savedView === 'list' || savedView === 'grid') setViewType(savedView)
    }
    catch {
      // The layout still works when browser storage is unavailable.
    }
  }, [])

  const toggleViewType = useCallback((newViewType: ViewType) => {
    setViewType(newViewType)
    try {
      localStorage.setItem('viewType', newViewType)
    }
    catch {
      // Keep the selected layout for this visit even if it cannot be saved.
    }
  }, [])

  return {
    viewType,
    toggleViewType,
  }
}
