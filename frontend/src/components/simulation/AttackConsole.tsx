"use client";

import { useState } from "react";
import {
  Play,
  Zap,
  Database,
  Code2,
  UserCheck,
  ChevronRight,
} from "lucide-react";
import { cn } from "@/lib/utils";
import type { RunResult, Scenario } from "@/lib/api";
import { useScenarios, useRunScenario, useRunCampaign } from "@/hooks/useSimulation";
import { useWafStatus } from "@/hooks/useWaf";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from "@/components/ui/sheet";
import { ResultPanel } from "@/components/simulation/ResultPanel";

const CATEGORY_META: Record<
  string,
  { icon: React.ElementType; label: string; accent: string }
> = {
  "SQL Injection": { icon: Database, label: "SQL Injection", accent: "text-chart-1" },
  XSS: { icon: Code2, label: "Cross-Site Scripting", accent: "text-chart-4" },
  Legitimate: { icon: UserCheck, label: "Legitimate Traffic", accent: "text-brand-emerald" },
};

function ScenarioCard({
  scenario,
  onFire,
  pending,
}: {
  scenario: Scenario;
  onFire: () => void;
  pending: boolean;
}) {
  const isLegit = scenario.category === "Legitimate";
  return (
    <div className="flex flex-col gap-3 rounded-xl border bg-card p-4 shadow-sm transition-shadow hover:shadow-md">
      <div className="flex items-start justify-between gap-2">
        <div className="flex flex-col gap-1">
          <div className="flex items-center gap-2">
            {scenario.level > 0 && (
              <Badge variant="secondary" className="tabular-nums">
                L{scenario.level}
              </Badge>
            )}
            <span className="text-sm font-semibold">{scenario.title}</span>
          </div>
          <p className="text-xs text-muted-foreground">{scenario.description}</p>
        </div>
      </div>

      <code className="block truncate rounded-md bg-muted px-2 py-1.5 font-mono text-xs text-muted-foreground" title={scenario.payload}>
        {scenario.payload}
      </code>

      <Button
        size="sm"
        variant={isLegit ? "outline" : "default"}
        className="w-full"
        onClick={onFire}
        disabled={pending}
      >
        <Play data-icon="inline-start" />
        {isLegit ? "Send request" : "Fire attack"}
      </Button>
    </div>
  );
}

export function AttackConsole() {
  const { data: scenarios, isLoading } = useScenarios();
  const { data: waf } = useWafStatus();
  const runScenario = useRunScenario();
  const runCampaign = useRunCampaign();

  const [result, setResult] = useState<RunResult | null>(null);
  const [open, setOpen] = useState(false);

  const fire = (id: string) => {
    runScenario.mutate(id, {
      onSuccess: (r) => {
        setResult(r);
        setOpen(true);
      },
    });
  };

  const grouped = (scenarios ?? []).reduce<Record<string, Scenario[]>>((acc, s) => {
    (acc[s.category] ??= []).push(s);
    return acc;
  }, {});
  const order = ["SQL Injection", "XSS", "Legitimate"];

  return (
    <div className="flex flex-col gap-6">
      {/* Control bar */}
      <div className="flex flex-col gap-3 rounded-xl border bg-card p-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-3">
          <span
            className={cn(
              "flex size-2.5 rounded-full",
              waf?.enabled === false ? "bg-block" : "bg-allow animate-pulse"
            )}
          />
          <div className="flex flex-col">
            <span className="text-sm font-semibold">
              Threat Simulation Console
            </span>
            <span className="text-xs text-muted-foreground">
              {waf?.enabled === false
                ? "WAF is OFF — attacks will execute against the bank."
                : "WAF is ON — attacks will be intercepted."}
            </span>
          </div>
        </div>
        <Button
          onClick={() => runCampaign.mutate(true)}
          disabled={runCampaign.isPending}
          className="gap-1.5"
        >
          <Zap data-icon="inline-start" />
          {runCampaign.isPending ? "Running campaign…" : "Run full campaign"}
        </Button>
      </div>

      {/* Scenario groups */}
      {isLoading ? (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="h-40 rounded-xl" />
          ))}
        </div>
      ) : (
        order
          .filter((cat) => grouped[cat]?.length)
          .map((cat) => {
            const meta = CATEGORY_META[cat];
            return (
              <div key={cat} className="flex flex-col gap-3">
                <div className="flex items-center gap-2">
                  {meta && <meta.icon className={cn("size-4", meta.accent)} />}
                  <h3 className="text-sm font-semibold">{meta?.label ?? cat}</h3>
                  <Badge variant="outline">{grouped[cat].length}</Badge>
                </div>
                <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                  {grouped[cat].map((s) => (
                    <ScenarioCard
                      key={s.id}
                      scenario={s}
                      pending={runScenario.isPending}
                      onFire={() => fire(s.id)}
                    />
                  ))}
                </div>
              </div>
            );
          })
      )}

      {/* Result drawer */}
      <Sheet open={open} onOpenChange={setOpen}>
        <SheetContent className="w-full gap-0 overflow-y-auto sm:max-w-2xl">
          <SheetHeader>
            <SheetTitle className="flex items-center gap-2">
              <ChevronRight className="size-4" /> Simulation Result
            </SheetTitle>
            <SheetDescription>
              Live output from the deep-learning WAF and the banking application.
            </SheetDescription>
          </SheetHeader>
          <div className="p-4">{result && <ResultPanel result={result} />}</div>
        </SheetContent>
      </Sheet>
    </div>
  );
}
