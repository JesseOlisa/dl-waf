"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  LogOut,
  Crosshair,
  ShieldHalf,
  ScrollText,
} from "lucide-react";
import { logout } from "@/lib/auth";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { BrandLogo } from "@/components/brand/BrandLogo";
import { useWafStatus } from "@/hooks/useWaf";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from "@/components/ui/sidebar";

const NAV = [
  { href: "/dashboard", label: "Overview", icon: LayoutDashboard },
  { href: "/dashboard/simulation", label: "Attack Simulation", icon: Crosshair },
  { href: "/dashboard/waf", label: "WAF Control", icon: ShieldHalf },
  { href: "/dashboard/events", label: "Event Log", icon: ScrollText },
];

export function AppSidebar() {
  const pathname = usePathname();
  const { data: waf } = useWafStatus();

  return (
    <Sidebar collapsible="none" className="sticky top-0 h-svh">
      <SidebarHeader className="border-b border-sidebar-border px-4 py-4">
        <BrandLogo
          tagline="Security Operations"
          wordmarkClassName="text-sidebar-foreground"
          taglineClassName="text-sidebar-foreground/60"
        />
      </SidebarHeader>

      <SidebarContent className="px-2 py-3">
        <SidebarGroup>
          <SidebarGroupLabel>Monitoring</SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {NAV.map((item) => {
                const active =
                  item.href === "/dashboard"
                    ? pathname === "/dashboard"
                    : pathname.startsWith(item.href);
                return (
                  <SidebarMenuItem key={item.href}>
                    <SidebarMenuButton
                      render={<Link href={item.href} />}
                      isActive={active}
                      tooltip={item.label}
                    >
                      <item.icon className="size-4" />
                      <span>{item.label}</span>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                );
              })}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>

        <div className="mt-auto flex flex-col gap-2 px-2">
          {/* Live protection status */}
          <div
            className={cn(
              "flex items-center gap-2 rounded-md px-2.5 py-2 text-xs font-medium",
              waf?.enabled === false
                ? "bg-block/15 text-block"
                : "bg-allow/15 text-allow"
            )}
          >
            <span
              className={cn(
                "size-2 rounded-full",
                waf?.enabled === false ? "bg-block" : "bg-allow animate-pulse"
              )}
            />
            {waf?.enabled === false ? "WAF Disabled" : "WAF Active"}
          </div>
          <Badge
            variant="outline"
            className="w-fit border-sidebar-border text-xs font-normal text-sidebar-foreground/70"
          >
            LSTM · F1 99.4%
          </Badge>
        </div>
      </SidebarContent>

      <SidebarFooter className="border-t border-sidebar-border px-4 py-3">
        <div className="flex items-center justify-between">
          <span className="text-sm text-sidebar-foreground/70">admin</span>
          <Button
            variant="ghost"
            size="sm"
            onClick={logout}
            className="gap-1 text-sidebar-foreground/70 hover:bg-sidebar-accent hover:text-sidebar-foreground"
          >
            <LogOut className="size-4" />
            Logout
          </Button>
        </div>
      </SidebarFooter>
    </Sidebar>
  );
}
