"use client";

import { useState } from "react";
import {
  LogIn,
  Search,
  Banknote,
  MessageSquare,
  Globe,
  Play,
  TriangleAlert,
  type LucideIcon,
} from "lucide-react";
import { cn } from "@/lib/utils";
import type { RunResult, StaffTask, StaffVariant } from "@/lib/api";
import { useRunStaffVariant } from "@/hooks/useStaff";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { StaffResult } from "@/components/staff/StaffResult";

const ICONS: Record<string, LucideIcon> = {
  "log-in": LogIn,
  search: Search,
  banknote: Banknote,
  "message-square": MessageSquare,
  globe: Globe,
};

export function StaffTaskCard({ task }: { task: StaffTask }) {
  const legit = task.variants.find((v) => v.kind === "legitimate")!;
  const attack = task.variants.find((v) => v.kind === "malicious")!;

  const [shown, setShown] = useState<StaffVariant>(legit);
  const [result, setResult] = useState<RunResult | null>(null);
  const run = useRunStaffVariant();

  const Icon = ICONS[task.icon] ?? Globe;

  const fire = (variant: StaffVariant) => {
    setShown(variant);
    setResult(null);
    run.mutate(variant.id, { onSuccess: (r) => setResult(r) });
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <span className="flex size-8 items-center justify-center rounded-md bg-brand-navy/10 text-brand-navy dark:bg-brand-gold/15 dark:text-brand-gold">
            <Icon className="size-4" />
          </span>
          {task.title}
        </CardTitle>
        <p className="text-sm text-muted-foreground">{task.blurb}</p>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {/* The form the staff fills in — showing the currently selected values */}
        <div className="flex flex-col gap-2.5">
          {task.fields.map((f) => (
            <div key={f.name} className="flex flex-col gap-1">
              <Label className="text-xs text-muted-foreground">{f.label}</Label>
              <div
                className={cn(
                  "min-h-8 break-all rounded-md border bg-muted/40 px-2.5 py-1.5 font-mono text-xs",
                  f.risky && shown.kind === "malicious" && "border-block/50 bg-block/5 text-block"
                )}
              >
                {shown.fields[f.name] ?? ""}
              </div>
            </div>
          ))}
        </div>

        {/* Legit vs malicious actions */}
        <div className="grid grid-cols-2 gap-2">
          <Button
            variant="outline"
            size="sm"
            disabled={run.isPending}
            onClick={() => fire(legit)}
          >
            <Play data-icon="inline-start" />
            {legit.label}
          </Button>
          <Button
            size="sm"
            disabled={run.isPending}
            onClick={() => fire(attack)}
            className="bg-block/90 text-block-foreground hover:bg-block"
          >
            <TriangleAlert data-icon="inline-start" />
            {attack.label}
          </Button>
        </div>

        {result && <StaffResult result={result} />}
      </CardContent>
    </Card>
  );
}
