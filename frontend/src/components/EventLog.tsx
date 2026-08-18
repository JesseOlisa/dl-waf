"use client";

import { useState, useEffect, useRef } from "react";
import { useEvents } from "@/hooks/useDashboard";
import { ForensicsDrawer } from "@/components/ForensicsDrawer";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";

export function EventLog() {
  const [page, setPage] = useState(1);
  const [classification, setClassification] = useState<number | undefined>(undefined);
  const [attackTypeInput, setAttackTypeInput] = useState("");
  const [attackType, setAttackType] = useState("");
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  function openEvent(id: number) {
    setSelectedId(id);
    setDrawerOpen(true);
  }

  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => {
      setAttackType(attackTypeInput);
      setPage(1);
    }, 300);
    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current);
    };
  }, [attackTypeInput]);

  const filters = {
    page,
    page_size: 20,
    ...(classification !== undefined && { classification }),
    ...(attackType && { attack_type: attackType }),
  };

  const { data, isLoading } = useEvents(filters);

  function handleClassificationChange(val: string | null) {
    setClassification(!val || val === "all" ? undefined : Number(val));
    setPage(1);
  }

  function handleReset() {
    setClassification(undefined);
    setAttackTypeInput("");
    setAttackType("");
    setPage(1);
  }

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium">Event Log</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Filters */}
        <div className="flex flex-wrap items-center gap-2">
          <Select
            value={classification !== undefined ? String(classification) : "all"}
            onValueChange={handleClassificationChange}
          >
            <SelectTrigger className="h-8 w-36 text-xs">
              <SelectValue placeholder="All" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All</SelectItem>
              <SelectItem value="1">Blocked</SelectItem>
              <SelectItem value="0">Allowed</SelectItem>
            </SelectContent>
          </Select>

          <Input
            className="h-8 w-40 text-xs"
            placeholder="Attack type…"
            value={attackTypeInput}
            onChange={(e) => setAttackTypeInput(e.target.value)}
          />

          <Button variant="ghost" size="sm" className="h-8 text-xs" onClick={handleReset}>
            Reset
          </Button>
        </div>

        {/* Table */}
        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="text-xs">Timestamp</TableHead>
                <TableHead className="text-xs">Method</TableHead>
                <TableHead className="text-xs">URI</TableHead>
                <TableHead className="text-xs">Classification</TableHead>
                <TableHead className="text-xs">Confidence</TableHead>
                <TableHead className="text-xs">Attack Type</TableHead>
                <TableHead className="text-xs">Action</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading ? (
                Array.from({ length: 5 }).map((_, i) => (
                  <TableRow key={i}>
                    {Array.from({ length: 7 }).map((__, j) => (
                      <TableCell key={j}>
                        <Skeleton className="h-4 w-full" />
                      </TableCell>
                    ))}
                  </TableRow>
                ))
              ) : !data || data.items.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="py-8 text-center text-sm text-muted-foreground">
                    No events found
                  </TableCell>
                </TableRow>
              ) : (
                data.items.map((ev) => {
                  const breach =
                    ev.classification === 1 && !ev.action_taken.startsWith("BLOCKED");
                  return (
                    <TableRow
                      key={ev.event_id}
                      className="cursor-pointer"
                      onClick={() => openEvent(ev.event_id)}
                    >
                      <TableCell className="text-xs whitespace-nowrap">
                        {new Date(ev.timestamp).toLocaleString()}
                      </TableCell>
                      <TableCell className="text-xs font-mono">{ev.http_method ?? "—"}</TableCell>
                      <TableCell className="max-w-[160px] truncate text-xs font-mono" title={ev.request_uri ?? ""}>
                        {ev.request_uri ?? "—"}
                      </TableCell>
                      <TableCell>
                        <Badge variant={ev.classification === 1 ? "destructive" : "outline"} className="text-xs">
                          {ev.classification === 1 ? "Malicious" : "Legitimate"}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-xs">
                        {(ev.confidence_score * 100).toFixed(1)}%
                      </TableCell>
                      <TableCell className="text-xs">{ev.attack_type ?? "—"}</TableCell>
                      <TableCell>
                        <Badge
                          variant={
                            ev.action_taken.startsWith("BLOCKED")
                              ? "destructive"
                              : breach
                                ? "destructive"
                                : "secondary"
                          }
                          className="text-xs"
                        >
                          {breach ? "BREACH" : ev.action_taken}
                        </Badge>
                      </TableCell>
                    </TableRow>
                  );
                })
              )}
            </TableBody>
          </Table>
        </div>

        {/* Pagination */}
        {data && data.pages > 1 && (
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>
              Page {data.page} of {data.pages} ({data.total} total)
            </span>
            <div className="flex gap-2">
              <Button
                variant="outline"
                size="sm"
                className="h-7 text-xs"
                disabled={page <= 1}
                onClick={() => setPage((p) => p - 1)}
              >
                Previous
              </Button>
              <Button
                variant="outline"
                size="sm"
                className="h-7 text-xs"
                disabled={page >= data.pages}
                onClick={() => setPage((p) => p + 1)}
              >
                Next
              </Button>
            </div>
          </div>
        )}
      </CardContent>

      <ForensicsDrawer
        eventId={selectedId}
        open={drawerOpen}
        onOpenChange={setDrawerOpen}
      />
    </Card>
  );
}
