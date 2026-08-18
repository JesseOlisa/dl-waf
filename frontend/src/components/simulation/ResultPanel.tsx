"use client";

import {
  ShieldCheck,
  ShieldAlert,
  CheckCircle2,
  Cpu,
  FileCode,
  Fingerprint,
  Clock,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { blockedByLabel, type RunResult } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { ConsequenceView } from "@/components/simulation/ConsequenceView";

function VerdictBadge({ result }: { result: RunResult }) {
  if (result.outcome === "attack_blocked") {
    return (
      <Badge className="gap-1 bg-allow text-allow-foreground hover:bg-allow">
        <ShieldCheck className="size-3" /> Blocked
      </Badge>
    );
  }
  if (result.outcome === "attack_succeeded") {
    return (
      <Badge className="gap-1 bg-block text-block-foreground hover:bg-block">
        <ShieldAlert className="size-3" /> Breach
      </Badge>
    );
  }
  return (
    <Badge variant="secondary" className="gap-1">
      <CheckCircle2 className="size-3" /> Allowed
    </Badge>
  );
}

function SignalRow({
  icon: Icon,
  label,
  children,
  highlight,
}: {
  icon: React.ElementType;
  label: string;
  children: React.ReactNode;
  highlight?: boolean;
}) {
  return (
    <div
      className={cn(
        "flex items-center gap-3 rounded-lg border p-3",
        highlight && "border-brand-gold/50 bg-brand-gold/5"
      )}
    >
      <span className="flex size-8 shrink-0 items-center justify-center rounded-md bg-muted text-muted-foreground">
        <Icon className="size-4" />
      </span>
      <div className="flex flex-1 flex-col gap-1">
        <span className="text-xs font-medium text-muted-foreground">{label}</span>
        {children}
      </div>
    </div>
  );
}

export function ResultPanel({ result }: { result: RunResult }) {
  const modelPct = Math.round(result.model.confidence * 100);
  const modelHit = result.model.label === 1;

  return (
    <div className="flex flex-col gap-5">
      {/* Header */}
      <div className="flex flex-col gap-2">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Badge variant="outline">{result.category}</Badge>
            {result.level > 0 && (
              <Badge variant="secondary">Level {result.level}</Badge>
            )}
          </div>
          <VerdictBadge result={result} />
        </div>
        <h3 className="text-lg font-bold">{result.title}</h3>
        <div className="flex items-center gap-3 text-xs text-muted-foreground">
          <span className="flex items-center gap-1">
            <Clock className="size-3" /> {result.latency_ms} ms
          </span>
          <span>·</span>
          <span>WAF was {result.waf_enabled ? "ON" : "OFF"}</span>
        </div>
      </div>

      {/* Raw request */}
      <div className="flex flex-col gap-1.5">
        <span className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground">
          <FileCode className="size-3.5" /> Intercepted request
        </span>
        <ScrollArea className="h-40 rounded-lg border bg-muted/40">
          <pre className="p-3 font-mono text-xs leading-relaxed">{result.raw_request}</pre>
        </ScrollArea>
      </div>

      {/* Two-layer detection */}
      <div className="flex flex-col gap-2">
        <span className="text-xs font-medium text-muted-foreground">
          Detection engine
        </span>
        <SignalRow icon={Cpu} label="Layer 1 — LSTM model" highlight={modelHit}>
          <div className="flex items-center gap-2">
            <Progress value={modelPct} className="h-2 flex-1" />
            <span
              className={cn(
                "w-12 text-right text-sm font-semibold tabular-nums",
                modelHit ? "text-block" : "text-muted-foreground"
              )}
            >
              {modelPct}%
            </span>
          </div>
        </SignalRow>
        <SignalRow
          icon={Fingerprint}
          label="Layer 2 — Signature rules"
          highlight={result.signature.matched}
        >
          {result.signature.matched ? (
            <span className="text-sm font-semibold text-block">
              Matched · {result.signature.category}
            </span>
          ) : (
            <span className="text-sm text-muted-foreground">No signature match</span>
          )}
        </SignalRow>
      </div>

      {/* Consequence */}
      {result.consequence ? (
        <div className="flex flex-col gap-2">
          <span className="text-xs font-medium text-muted-foreground">Consequence</span>
          <ConsequenceView c={result.consequence} />
        </div>
      ) : result.outcome === "attack_blocked" ? (
        <Alert className="border-allow/30 bg-allow/5 text-allow">
          <ShieldCheck />
          <AlertTitle className="text-allow">Attack neutralized</AlertTitle>
          <AlertDescription className="text-allow/80">
            Stopped by {blockedByLabel(result.blocked_by)} before reaching the bank.
          </AlertDescription>
        </Alert>
      ) : null}
    </div>
  );
}
