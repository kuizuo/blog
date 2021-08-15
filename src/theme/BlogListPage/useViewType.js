import { useCallback, useEffect, useState } from "react";

export function useViewType() {
  const [viewType, setViewType] = useState("card");

  useEffect(() => {
    setViewType(localStorage.getItem("viewType") || "card");
  }, []);

  const toggleViewType = useCallback((newViewType) => {
    setViewType(newViewType);
    localStorage.setItem("viewType", newViewType);
  }, []);

  return {
    viewType,
    toggleViewType,
  };
}
