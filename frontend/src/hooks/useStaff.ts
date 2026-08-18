"use client";

import { useMutation, useQuery } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  fetchStaffProtection,
  fetchStaffTasks,
  runStaffVariant,
  type RunResult,
} from "@/lib/api";

export function useStaffTasks() {
  return useQuery({ queryKey: ["staff-tasks"], queryFn: fetchStaffTasks });
}

export function useStaffProtection() {
  return useQuery({
    queryKey: ["staff-protection"],
    queryFn: fetchStaffProtection,
    refetchInterval: 4_000,
  });
}

export function useRunStaffVariant() {
  return useMutation({
    mutationFn: (variantId: string) => runStaffVariant(variantId),
    onSuccess: (r: RunResult) => {
      if (r.outcome === "attack_blocked") {
        toast.success("Protected", {
          description: `The firewall blocked ${r.title}.`,
        });
      } else if (r.outcome === "attack_succeeded") {
        toast.error("Breach!", {
          description: r.consequence?.title ?? "The attack got through.",
        });
      } else {
        toast.success("Done", { description: "Your request went through normally." });
      }
    },
    onError: (e: Error) => toast.error("Request failed", { description: e.message }),
  });
}
