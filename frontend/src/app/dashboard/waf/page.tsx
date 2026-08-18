"use client";

import { PageHeader } from "@/components/PageHeader";
import { WafControl } from "@/components/waf/WafControl";

export default function WafPage() {
  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader
        title="WAF Control"
        description="Enable or disable the deep-learning firewall and manage the attack simulation environment."
      />
      <WafControl />
    </div>
  );
}
