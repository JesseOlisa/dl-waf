"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  blockedByLabel,
  fetchScenarios,
  resetSim,
  runCampaign,
  runScenario,
  type CampaignResult,
  type RunResult,
} from "@/lib/api";

// Refresh the live dashboard panels the moment a simulation changes the data,
// instead of waiting for the 10s poll.
function useInvalidateDashboard() {
  const qc = useQueryClient();
  return () => {
    qc.invalidateQueries({ queryKey: ["summary"] });
    qc.invalidateQueries({ queryKey: ["traffic"] });
    qc.invalidateQueries({ queryKey: ["attacks"] });
    qc.invalidateQueries({ queryKey: ["events"] });
  };
}

export function useScenarios() {
  return useQuery({ queryKey: ["scenarios"], queryFn: fetchScenarios });
}

export function useRunScenario() {
  const invalidate = useInvalidateDashboard();
  return useMutation({
    mutationFn: (scenarioId: string) => runScenario(scenarioId),
    onSuccess: (r: RunResult) => {
      invalidate();
      if (r.verdict === "BLOCKED") {
        toast.success(`Blocked: ${r.title}`, {
          description: `Stopped by ${blockedByLabel(r.blocked_by)}.`,
        });
      } else if (r.outcome === "attack_succeeded") {
        toast.error(`Breach: ${r.title}`, {
          description: r.consequence?.title ?? "Attack executed.",
        });
      } else {
        toast.success(`Allowed: ${r.title}`, {
          description: "Legitimate request passed.",
        });
      }
    },
    onError: (e: Error) => toast.error("Run failed", { description: e.message }),
  });
}

export function useRunCampaign() {
  const invalidate = useInvalidateDashboard();
  return useMutation({
    mutationFn: (includeBaseline: boolean) => runCampaign(includeBaseline),
    onSuccess: (r: CampaignResult) => {
      invalidate();
      toast.info("Campaign complete", {
        description: `${r.summary.blocked} blocked · ${r.summary.succeeded} breached · ${r.summary.legitimate_allowed} legit allowed`,
      });
    },
    onError: (e: Error) => toast.error("Campaign failed", { description: e.message }),
  });
}

export function useResetSim() {
  const invalidate = useInvalidateDashboard();
  return useMutation({
    mutationFn: () => resetSim(),
    onSuccess: () => {
      invalidate();
      toast.success("Simulation reset", {
        description: "Bank data restored to a clean state.",
      });
    },
    onError: (e: Error) => toast.error("Reset failed", { description: e.message }),
  });
}
