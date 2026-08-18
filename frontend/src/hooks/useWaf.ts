"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  fetchWafAudit,
  fetchWafStatus,
  toggleWaf,
  type WafStatus,
} from "@/lib/api";

export function useWafStatus() {
  return useQuery({
    queryKey: ["waf-status"],
    queryFn: fetchWafStatus,
    refetchInterval: 5_000,
  });
}

export function useWafAudit(limit = 50) {
  return useQuery({
    queryKey: ["waf-audit", limit],
    queryFn: () => fetchWafAudit(limit),
    refetchInterval: 5_000,
  });
}

export function useToggleWaf() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ enabled, note }: { enabled: boolean; note?: string }) =>
      toggleWaf(enabled, note),
    onSuccess: (s: WafStatus) => {
      qc.invalidateQueries({ queryKey: ["waf-status"] });
      qc.invalidateQueries({ queryKey: ["waf-audit"] });
      if (s.enabled) {
        toast.success("WAF enabled", { description: "Protection is active." });
      } else {
        toast.warning("WAF disabled", {
          description: "Traffic is no longer inspected — attacks will execute.",
        });
      }
    },
    onError: (e: Error) => toast.error("Toggle failed", { description: e.message }),
  });
}
