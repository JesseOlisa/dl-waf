"use client";

import Link from "next/link";
import { ShieldCheck, ShieldAlert, UserRound } from "lucide-react";
import { cn } from "@/lib/utils";
import { BrandLogo } from "@/components/brand/BrandLogo";
import { StaffTaskCard } from "@/components/staff/StaffTaskCard";
import { useStaffTasks, useStaffProtection } from "@/hooks/useStaff";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";

function ProtectionPill() {
  const { data } = useStaffProtection();
  const enabled = data?.enabled ?? true;
  return (
    <div
      className={cn(
        "flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs font-medium",
        enabled
          ? "border-allow/40 bg-allow/10 text-allow"
          : "border-block/50 bg-block/10 text-block",
      )}
    >
      {enabled ? <ShieldCheck className="size-3.5" /> : <ShieldAlert className="size-3.5" />}
      {enabled ? "WAF protecting this workstation" : "WAF OFF — you are exposed"}
    </div>
  );
}

export default function StaffPage() {
  const { data: tasks, isLoading } = useStaffTasks();

  return (
    <div className="flex min-h-screen flex-col">
      {/* Workstation top bar */}
      <header className="sticky top-0 z-10 border-b bg-card/95 backdrop-blur">
        <div className="mx-auto flex w-full max-w-6xl items-center justify-between px-4 py-3">
          <BrandLogo tagline="Staff Workstation" />
          <div className="flex items-center gap-3">
            <ProtectionPill />
            <div className="hidden items-center gap-2 rounded-full border px-3 py-1.5 sm:flex">
              <span className="flex size-6 items-center justify-center rounded-full bg-brand-navy/10 text-brand-navy dark:bg-brand-gold/15 dark:text-brand-gold">
                <UserRound className="size-3.5" />
              </span>
              <div className="flex flex-col leading-tight">
                <span className="text-xs font-semibold">Amaka Eze</span>
                <span className="text-[10px] text-muted-foreground">Teller · Ikeja Branch</span>
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* Intro */}
      <section className="border-b bg-sidebar text-sidebar-foreground">
        <div className="mx-auto w-full max-w-6xl px-4 py-8">
          <Badge className="mb-3 bg-brand-gold text-brand-navy hover:bg-brand-gold">
            Security awareness demo
          </Badge>
          <h1 className="max-w-2xl text-2xl font-bold md:text-3xl">
            Do your daily tasks — safely, even when you slip.
          </h1>
          <p className="mt-2 max-w-2xl text-sm text-sidebar-foreground/70">
            You handle customers all day. Sometimes a &ldquo;customer&rdquo; or an email tricks you
            into pasting something dangerous. For each task below, try the normal action and the
            risky one, and watch how the deep-learning firewall protects the bank — and you.
          </p>
        </div>
      </section>

      {/* Task grid */}
      <section className="mx-auto w-full max-w-6xl flex-1 px-4 py-8">
        {isLoading ? (
          <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
            {Array.from({ length: 6 }).map((_, i) => (
              <Skeleton key={i} className="h-64 rounded-xl" />
            ))}
          </div>
        ) : (
          <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
            {tasks?.map((task) => (
              <StaffTaskCard key={task.id} task={task} />
            ))}
          </div>
        )}
      </section>

      {/* Footer */}
      <footer className="border-t bg-card">
        <div className="mx-auto flex w-full max-w-6xl items-center justify-between px-4 py-5 text-sm text-muted-foreground">
          <span>Sterling Trust Bank · Internal use only</span>
          <Link href="/dashboard" className="font-medium underline hover:text-foreground">
            Security team →
          </Link>
        </div>
      </footer>
    </div>
  );
}
