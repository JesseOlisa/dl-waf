import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Sterling Trust Bank — Online Banking",
  description: "Sterling Trust Bank — secure online banking for every Nigerian.",
};

export default function PortalLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return <div className="min-h-screen bg-background">{children}</div>;
}
