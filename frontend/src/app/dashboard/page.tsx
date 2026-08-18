"use client";

import Link from "next/link";
import { ShieldCheck, ShieldAlert, ArrowRight } from "lucide-react";
import { cn } from "@/lib/utils";
import { PageHeader } from "@/components/PageHeader";
import { SummaryCards } from "@/components/SummaryCards";
import { TrafficChart } from "@/components/TrafficChart";
import { AttackDistribution } from "@/components/AttackDistribution";
import { buttonVariants } from "@/components/ui/button";
import { useWafStatus } from "@/hooks/useWaf";

function WafBanner() {
  const { data: waf } = useWafStatus();
  const enabled = waf?.enabled ?? true;
  return (
    <div
      className={cn(
        "flex items-center justify-between gap-4 rounded-xl border px-5 py-3",
        enabled ? "border-allow/30 bg-allow/10" : "border-block/40 bg-block/10"
      )}
    >
      <div className="flex items-center gap-3">
        {enabled ? (
          <ShieldCheck className="size-5 text-allow" />
        ) : (
          <ShieldAlert className="size-5 text-block" />
        )}
        <div className="flex flex-col">
          <span className="text-sm font-semibold">
            {enabled ? "Perimeter protected" : "Perimeter unprotected"}
          </span>
          <span className="text-xs text-muted-foreground">
            {enabled
              ? "DL-WAF is inspecting all inbound traffic."
              : "WAF is disabled — malicious traffic is reaching the bank."}
          </span>
        </div>
      </div>
      <Link
        href="/dashboard/waf"
        className={cn(buttonVariants({ variant: "ghost", size: "sm" }))}
      >
        Manage <ArrowRight data-icon="inline-end" />
      </Link>
    </div>
  );
}

export default function DashboardPage() {
  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader
        title="Security Overview"
        description="Real-time threat monitoring for Sterling Trust Bank."
      />

      <WafBanner />

      <SummaryCards />

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <TrafficChart />
        <AttackDistribution />
      </div>
    </div>
  );
}
