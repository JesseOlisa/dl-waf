"use client";

import { Shield, ShieldOff, Activity, ShieldAlert } from "lucide-react";
import { useSummary } from "@/hooks/useDashboard";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";

const cards = [
  {
    key: "total_requests" as const,
    label: "Total Requests",
    icon: Activity,
    format: (v: number) => v.toLocaleString(),
    color: "text-foreground",
  },
  {
    key: "blocked" as const,
    label: "Blocked",
    icon: ShieldOff,
    format: (v: number) => v.toLocaleString(),
    color: "text-allow",
  },
  {
    key: "attacks_succeeded" as const,
    label: "Breaches",
    icon: ShieldAlert,
    format: (v: number) => v.toLocaleString(),
    color: "text-block",
  },
  {
    key: "allowed" as const,
    label: "Allowed",
    icon: Shield,
    format: (v: number) => v.toLocaleString(),
    color: "text-foreground",
  },
];

export function SummaryCards() {
  const { data, isLoading } = useSummary();

  return (
    <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
      {cards.map(({ key, label, icon: Icon, format, color }) => (
        <Card key={key}>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              {label}
            </CardTitle>
            <Icon className={`size-4 ${color}`} />
          </CardHeader>
          <CardContent>
            {isLoading || !data ? (
              <Skeleton className="h-8 w-24" />
            ) : (
              <p className={`text-2xl font-bold ${color}`}>
                {format(data[key])}
              </p>
            )}
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
