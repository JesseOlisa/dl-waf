"use client";

import { ShieldAlert, ShieldCheck, KeyRound } from "lucide-react";
import type { Consequence } from "@/lib/api";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

export function ConsequenceView({ c }: { c: Consequence }) {
  if (c.kind === "none") {
    return (
      <div className="flex flex-col gap-3">
        <p className="text-sm text-muted-foreground">{c.summary ?? "No effect."}</p>
        <DetailBlock c={c} />
      </div>
    );
  }

  const benign = c.severity === "benign";

  return (
    <div className="flex flex-col gap-3">
      <Alert variant={benign ? "default" : "destructive"}>
        {benign ? <ShieldCheck /> : <ShieldAlert />}
        <AlertTitle>{c.title}</AlertTitle>
        {c.summary && <AlertDescription>{c.summary}</AlertDescription>}
      </Alert>

      {c.kind === "rows" && c.columns && c.rows && (
        <div className="overflow-auto rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                {c.columns.map((col) => (
                  <TableHead key={col}>{col}</TableHead>
                ))}
              </TableRow>
            </TableHeader>
            <TableBody>
              {c.rows.map((row, i) => (
                <TableRow key={i}>
                  {row.map((cell, j) => (
                    <TableCell key={j} className="font-mono text-xs">
                      {String(cell)}
                    </TableCell>
                  ))}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      {c.kind === "cookie" && c.cookie && (
        <div className="flex items-center gap-2 rounded-lg border border-block/30 bg-block/5 p-3">
          <KeyRound className="size-4 text-block" />
          <code className="break-all font-mono text-sm text-block">{c.cookie}</code>
        </div>
      )}

      {c.kind === "boolean_leak" && c.detail && (
        <div className="rounded-lg border border-block/30 bg-block/5 p-3">
          <span className="text-xs text-muted-foreground">Recovered secret</span>
          <p className="font-mono text-lg font-bold text-block">{c.detail}</p>
        </div>
      )}

      {c.kind !== "boolean_leak" && <DetailBlock c={c} />}

      {c.kind === "defacement" && c.defaced_html && (
        <div className="flex flex-col gap-1.5">
          <span className="text-xs text-muted-foreground">
            Rendered attacker markup (sandboxed):
          </span>
          {/* Sandboxed iframe — NEVER dangerouslySetInnerHTML. */}
          <iframe
            title="Injected content preview"
            sandbox=""
            srcDoc={c.defaced_html}
            className="h-40 w-full rounded-lg border bg-white"
          />
        </div>
      )}
    </div>
  );
}

/** Renders the exact statement the vulnerable app executed, when there is one. */
function DetailBlock({ c }: { c: Consequence }) {
  if (!c.detail) return null;
  return (
    <div className="flex flex-col gap-1.5">
      <span className="text-xs font-medium text-muted-foreground">
        {c.detail_label ?? "Executed query"}
      </span>
      <pre className="overflow-x-auto rounded-lg border bg-muted/40 p-3 font-mono text-xs leading-relaxed whitespace-pre-wrap break-all">
        {c.detail}
      </pre>
    </div>
  );
}
