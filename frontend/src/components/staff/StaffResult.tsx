"use client";

import { ShieldCheck, ShieldAlert, CheckCircle2, Info } from "lucide-react";
import { cn } from "@/lib/utils";
import type { RunResult } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { ConsequenceView } from "@/components/simulation/ConsequenceView";

export function StaffResult({ result }: { result: RunResult }) {
  const modelPct = Math.round(result.model.confidence * 100);
  const blocked = result.outcome === "attack_blocked";
  const breach = result.outcome === "attack_succeeded";
  const modelOverflag =
    result.outcome === "legitimate_allowed" && result.model.label === 1;

  const banner = blocked
    ? {
        cls: "border-allow/40 bg-allow/10 text-allow",
        icon: ShieldCheck,
        title: "Firewall protected you",
        body: "That input carried an attack. The WAF blocked it before any damage.",
      }
    : breach
      ? {
          cls: "border-block/40 bg-block/10 text-block",
          icon: ShieldAlert,
          title: "Breach — the bank was hit",
          body: "The firewall was off, so the malicious input executed for real.",
        }
      : {
          cls: "border-allow/30 bg-allow/5 text-allow",
          icon: CheckCircle2,
          title: "Request completed",
          body: "A normal action — allowed through.",
        };

  return (
    <div className="mt-3 flex flex-col gap-3 border-t pt-3">
      <div className={cn("flex items-start gap-3 rounded-lg border p-3", banner.cls)}>
        <banner.icon className="mt-0.5 size-5 shrink-0" />
        <div className="flex flex-col gap-0.5">
          <span className="text-sm font-semibold">{banner.title}</span>
          <span className="text-xs opacity-80">{banner.body}</span>
        </div>
      </div>

      {/* Two-layer signals */}
      <div className="grid grid-cols-2 gap-2 text-xs">
        <div className="flex flex-col gap-1 rounded-md border p-2">
          <span className="text-muted-foreground">DL risk score</span>
          <div className="flex items-center gap-2">
            <Progress value={modelPct} className="h-1.5 flex-1" />
            <span className="font-semibold tabular-nums">{modelPct}%</span>
          </div>
        </div>
        <div className="flex flex-col gap-1 rounded-md border p-2">
          <span className="text-muted-foreground">Attack signature</span>
          {result.signature.matched ? (
            <Badge variant="destructive" className="w-fit">
              {result.signature.category}
            </Badge>
          ) : (
            <Badge variant="secondary" className="w-fit">
              None
            </Badge>
          )}
        </div>
      </div>

      {modelOverflag && (
        <div className="flex items-start gap-2 rounded-md border border-brand-gold/40 bg-brand-gold/5 p-2 text-xs">
          <Info className="mt-0.5 size-3.5 shrink-0 text-brand-gold" />
          <span className="text-muted-foreground">
            The DL model flagged this as anomalous, but no attack signature matched — so
            the layered firewall correctly let it through. That precision is why the model
            doesn&apos;t decide alone.
          </span>
        </div>
      )}

      {result.consequence && result.consequence.kind !== "none" && (
        <ConsequenceView c={result.consequence} />
      )}
    </div>
  );
}
