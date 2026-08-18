import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Sterling Trust Bank — Staff Workstation",
  description: "Sterling Trust Bank internal back-office console.",
};

export default function StaffLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return <div className="min-h-screen bg-background">{children}</div>;
}
