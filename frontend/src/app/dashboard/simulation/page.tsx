"use client";

import { PageHeader } from "@/components/PageHeader";
import { AttackConsole } from "@/components/simulation/AttackConsole";

export default function SimulationPage() {
  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader
        title="Attack Simulation"
        description="Fire real SQL injection and XSS attacks against Sterling Trust Bank to demonstrate the WAF live."
      />
      <AttackConsole />
    </div>
  );
}
