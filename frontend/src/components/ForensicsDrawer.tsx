"use client";

import { useQuery } from "@tanstack/react-query";
import { ShieldAlert, ShieldCheck } from "lucide-react";
import { fetchEventById } from "@/lib/api";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";

function Field({ label, value, mono }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-xs font-medium text-muted-foreground">{label}</span>
      <span className={cn("text-sm", mono && "break-all font-mono text-xs")}>{value}</span>
    </div>
  );
}

export function ForensicsDrawer({
  eventId,
  open,
  onOpenChange,
}: {
  eventId: number | null;
  open: boolean;
  onOpenChange: (v: boolean) => void;
}) {
  const { data: ev, isLoading } = useQuery({
    queryKey: ["event", eventId],
    queryFn: () => fetchEventById(eventId as number),
    enabled: open && eventId != null,
  });

  const breach = ev && ev.classification === 1 && !ev.action_taken.startsWith("BLOCKED");

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent className="w-full overflow-y-auto sm:max-w-md">
        <SheetHeader>
          <SheetTitle>Incident #{eventId}</SheetTitle>
          <SheetDescription>Full forensic detail for this request.</SheetDescription>
        </SheetHeader>

        <div className="flex flex-col gap-4 p-4">
          {isLoading || !ev ? (
            <>
              <Skeleton className="h-16 w-full" />
              <Skeleton className="h-40 w-full" />
            </>
          ) : (
            <>
              {breach ? (
                <Alert variant="destructive">
                  <ShieldAlert />
                  <AlertTitle>Breach — attack succeeded</AlertTitle>
                  <AlertDescription>
                    A malicious request reached the application because the WAF was
                    disabled.
                  </AlertDescription>
                </Alert>
              ) : ev.classification === 1 ? (
                <Alert className="border-allow/30 bg-allow/5 text-allow">
                  <ShieldCheck />
                  <AlertTitle className="text-allow">Attack blocked</AlertTitle>
                  <AlertDescription className="text-allow/80">
                    Intercepted and rejected before reaching the application.
                  </AlertDescription>
                </Alert>
              ) : null}

              <div className="grid grid-cols-2 gap-3">
                <Field label="Timestamp" value={new Date(ev.timestamp).toLocaleString()} />
                <Field label="Source IP" value={ev.source_ip ?? "—"} mono />
                <Field label="Method" value={ev.http_method ?? "—"} mono />
                <Field
                  label="Classification"
                  value={
                    <Badge variant={ev.classification === 1 ? "destructive" : "outline"}>
                      {ev.classification === 1 ? "Malicious" : "Legitimate"}
                    </Badge>
                  }
                />
                <Field
                  label="Model confidence"
                  value={`${(ev.confidence_score * 100).toFixed(2)}%`}
                />
                <Field label="Attack type" value={ev.attack_type ?? "—"} />
                <Field
                  label="Action"
                  value={
                    <Badge
                      variant={
                        ev.action_taken.startsWith("BLOCKED") ? "destructive" : "secondary"
                      }
                    >
                      {ev.action_taken}
                    </Badge>
                  }
                />
                {ev.latency_ms != null && (
                  <Field label="Latency" value={`${ev.latency_ms} ms`} />
                )}
                {ev.scenario_id && <Field label="Scenario" value={ev.scenario_id} mono />}
              </div>

              <Field label="Request URI" value={ev.request_uri ?? "—"} mono />

              <div className="flex flex-col gap-1.5">
                <span className="text-xs font-medium text-muted-foreground">
                  Payload fragment
                </span>
                <ScrollArea className="h-32 rounded-lg border bg-muted/40">
                  <pre className="p-3 font-mono text-xs leading-relaxed whitespace-pre-wrap break-all">
                    {ev.payload_fragment ?? "—"}
                  </pre>
                </ScrollArea>
              </div>
            </>
          )}
        </div>
      </SheetContent>
    </Sheet>
  );
}
