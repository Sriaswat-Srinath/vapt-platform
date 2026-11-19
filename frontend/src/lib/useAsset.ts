import { useQuery } from "@tanstack/react-query";
import { useCallback, useEffect, useSyncExternalStore } from "react";
import { api, type Asset } from "../api/client";

const KEY = "vapt.asset";

/** The selected asset lives in ONE module-level store, not in each component's
 *  state. The first version used `useState` inside the hook, which gave every
 *  screen its own private copy: the switcher in the sidebar changed the sidebar
 *  and nothing else. `useSyncExternalStore` makes one value that every consumer
 *  sees and re-renders on. */
let selectedId: string | null = (() => {
  try {
    return sessionStorage.getItem(KEY);
  } catch {
    return null;
  }
})();
const listeners = new Set<() => void>();

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

function snapshot() {
  return selectedId;
}

function setSelected(id: string | null, persist: boolean) {
  if (selectedId === id) return;
  selectedId = id;
  if (persist && id) {
    try {
      sessionStorage.setItem(KEY, id);
    } catch {
      /* a per-tab convenience; the dashboard works without it */
    }
  }
  listeners.forEach((l) => l());
}

export function useAssets() {
  return useQuery({ queryKey: ["assets"], queryFn: api.assets });
}

/** Every screen operates on the selected asset. */
export function useSelectedAsset() {
  const assets = useAssets();
  const current = useSyncExternalStore(subscribe, snapshot, snapshot);
  const list = assets.data ?? [];

  // Default to the first asset, and recover if a remembered selection no
  // longer exists (archived, or a fresh database).
  useEffect(() => {
    if (!list.length) return;
    if (!current || !list.some((a) => a.id === current)) {
      setSelected(list[0].id, false);
    }
  }, [list, current]);

  const select = useCallback((id: string) => setSelected(id, true), []);
  const asset: Asset | undefined = list.find((a) => a.id === current) ?? list[0];
  return { ...assets, asset, assets: list, select };
}

/** Kept for screens not yet converted; the same single selection. */
export function usePrimaryAsset() {
  const { asset, ...rest } = useSelectedAsset();
  return { ...rest, asset };
}
