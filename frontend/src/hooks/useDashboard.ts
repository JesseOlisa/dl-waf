"use client";

import { useQuery } from "@tanstack/react-query";
import {
  fetchAttacks,
  fetchEvents,
  fetchSummary,
  fetchTraffic,
  type EventFilters,
} from "@/lib/api";

const POLL_MS = 10_000;

export function useSummary() {
  return useQuery({
    queryKey: ["summary"],
    queryFn: fetchSummary,
    refetchInterval: POLL_MS,
  });
}

export function useTraffic(hours: number) {
  return useQuery({
    queryKey: ["traffic", hours],
    queryFn: () => fetchTraffic(hours),
    refetchInterval: POLL_MS,
  });
}

export function useAttacks() {
  return useQuery({
    queryKey: ["attacks"],
    queryFn: fetchAttacks,
    refetchInterval: POLL_MS,
  });
}

export function useEvents(filters: EventFilters = {}) {
  return useQuery({
    queryKey: ["events", filters],
    queryFn: () => fetchEvents(filters),
    refetchInterval: POLL_MS,
  });
}
