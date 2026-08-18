"use client";

import { PageHeader } from "@/components/PageHeader";
import { EventLog } from "@/components/EventLog";

export default function EventsPage() {
  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader
        title="Event Log"
        description="Every request the WAF has inspected. Click a row for full forensic detail."
      />
      <EventLog />
    </div>
  );
}
