import { useCallback, useEffect, useState } from 'react'

type ViewType = 'list' | 'grid' | 'card'

export function useViewType() {
  const [viewType, setViewType] = useState<ViewType>('card')

  useEffect(() => {
    setViewType((localStorage.getItem('viewType') as ViewType) || 'card')
  }, [])

  const toggleViewType = useCallback((newViewType: ViewType) => {
    setViewType(newViewType)
    localStorage.setItem('viewType', newViewType)
  }, [])

  return {
    viewType,
    toggleViewType,
  }
}
