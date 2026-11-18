import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";

/** Every screen operates on the registered asset. The MVP has exactly one. */
export function useAssets() {
  return useQuery({ queryKey: ["assets"], queryFn: api.assets });
}

export function usePrimaryAsset() {
  const assets = useAssets();
  return { ...assets, asset: assets.data?.[0] };
}
