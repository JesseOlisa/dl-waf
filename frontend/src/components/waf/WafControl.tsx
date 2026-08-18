"use client";

import { useState } from "react";
import { ShieldCheck, ShieldAlert, RotateCcw, History } from "lucide-react";
import { cn } from "@/lib/utils";
import { useWafStatus, useWafAudit, useToggleWaf } from "@/hooks/useWaf";
import { useResetSim } from "@/hooks/useSimulation";
import { Switch } from "@/components/ui/switch";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Skeleton } from "@/components/ui/skeleton";

export function WafControl() {
  const { data: status, isLoading } = useWafStatus();
  const { data: audit } = useWafAudit(50);
  const toggle = useToggleWaf();
  const reset = useResetSim();
  const [confirmOpen, setConfirmOpen] = useState(false);

  const enabled = status?.enabled ?? true;

  return (
    <div className="flex flex-col gap-6">
      {/* Protection status banner */}
      <div
        className={cn(
          "flex flex-col gap-4 rounded-xl border p-6 sm:flex-row sm:items-center sm:justify-between",
          enabled
            ? "border-allow/30 bg-allow/10"
            : "border-block/40 bg-block/10"
        )}
      >
        <div className="flex items-center gap-4">
          <span
            className={cn(
              "flex size-12 items-center justify-center rounded-full",
              enabled ? "bg-allow/20 text-allow" : "bg-block/20 text-block"
            )}
          >
            {enabled ? (
              <ShieldCheck className="size-6" />
            ) : (
              <ShieldAlert className="size-6" />
            )}
          </span>
          <div className="flex flex-col gap-0.5">
            <div className="flex items-center gap-2">
              <h2 className="text-lg font-bold">
                {enabled ? "Protected" : "Unprotected"}
              </h2>
              <Badge
                className={cn(
                  enabled
                    ? "bg-allow text-allow-foreground hover:bg-allow"
                    : "bg-block text-block-foreground hover:bg-block"
                )}
              >
                WAF {enabled ? "ON" : "OFF"}
              </Badge>
            </div>
            <p className="text-sm text-muted-foreground">
              {enabled
                ? "All traffic is inspected by the deep-learning engine. Malicious requests are blocked."
                : "Traffic is NOT inspected. Attacks will reach the banking application and execute."}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <span className="text-sm font-medium text-muted-foreground">
            {enabled ? "Enabled" : "Disabled"}
          </span>
          {isLoading ? (
            <Skeleton className="h-6 w-11 rounded-full" />
          ) : (
            <Switch
              checked={enabled}
              disabled={toggle.isPending}
              onCheckedChange={(v) =>
                toggle.mutate({
                  enabled: v,
                  note: v ? "Re-enabled from SOC" : "Disabled from SOC",
                })
              }
              aria-label="Toggle WAF protection"
            />
          )}
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        {/* Reset simulation */}
        <Card className="lg:col-span-1">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <RotateCcw className="size-4" /> Reset Simulation
            </CardTitle>
            <CardDescription>
              Restore the demo bank to a clean state — undo dropped tables,
              zeroed balances, and defacement between runs.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Dialog open={confirmOpen} onOpenChange={setConfirmOpen}>
              <DialogTrigger
                render={
                  <Button variant="outline" className="w-full" disabled={reset.isPending}>
                    {reset.isPending ? "Resetting…" : "Reset bank data"}
                  </Button>
                }
              />
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Reset the simulation?</DialogTitle>
                  <DialogDescription>
                    This re-seeds the sandboxed bank database, undoing every
                    successful attack from previous runs. Event history and WAF
                    audit trail are not affected.
                  </DialogDescription>
                </DialogHeader>
                <DialogFooter>
                  <DialogClose render={<Button variant="ghost">Cancel</Button>} />
                  <Button
                    onClick={() => {
                      reset.mutate();
                      setConfirmOpen(false);
                    }}
                  >
                    Reset now
                  </Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>
          </CardContent>
        </Card>

        {/* Audit trail */}
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <History className="size-4" /> Control Audit Trail
            </CardTitle>
            <CardDescription>
              Every kill-switch change and reset, with operator and timestamp.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="max-h-72 overflow-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Time</TableHead>
                    <TableHead>Actor</TableHead>
                    <TableHead>Action</TableHead>
                    <TableHead>Note</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {!audit || audit.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={4} className="text-center text-muted-foreground">
                        No control actions recorded yet.
                      </TableCell>
                    </TableRow>
                  ) : (
                    audit.map((a) => (
                      <TableRow key={a.id}>
                        <TableCell className="whitespace-nowrap text-xs text-muted-foreground">
                          {new Date(a.timestamp).toLocaleString()}
                        </TableCell>
                        <TableCell className="font-medium">{a.actor}</TableCell>
                        <TableCell>
                          <Badge
                            variant={
                              a.action === "WAF_DISABLED" ? "destructive" : "secondary"
                            }
                          >
                            {a.action.replace(/_/g, " ")}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-sm text-muted-foreground">
                          {a.note ?? "—"}
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
