import Link from "next/link";
import {
  ArrowUpRight,
  ArrowDownLeft,
  Lock,
  ShieldCheck,
  Smartphone,
  CreditCard,
  Send,
  Search,
} from "lucide-react";
import { BrandLogo } from "@/components/brand/BrandLogo";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";

const ACCOUNTS = [
  { name: "Everyday Savings", no: "0123 4567 01", type: "Savings", balance: "₦842,500.75" },
  { name: "Premier Current", no: "0123 4567 02", type: "Current", balance: "₦1,560,000.00" },
];

const TRANSACTIONS = [
  { desc: "Salary — Dangote Group", date: "12 Aug", amount: "+₦450,000.00", credit: true },
  { desc: "POS — Shoprite Ikeja", date: "11 Aug", amount: "−₦18,500.00", credit: false },
  { desc: "Transfer to 0123456704", date: "10 Aug", amount: "−₦250,000.00", credit: false },
  { desc: "Airtime — MTN", date: "09 Aug", amount: "−₦5,000.00", credit: false },
];

const QUICK_ACTIONS = [
  { icon: Send, label: "Transfer" },
  { icon: CreditCard, label: "Pay Bills" },
  { icon: Smartphone, label: "Airtime" },
  { icon: Search, label: "Find Account" },
];

export default function PortalPage() {
  return (
    <div className="flex min-h-screen flex-col">
      {/* Top navigation */}
      <header className="sticky top-0 z-10 border-b bg-card/95 backdrop-blur">
        <div className="mx-auto flex w-full max-w-6xl items-center justify-between px-4 py-3">
          <BrandLogo tagline="Online Banking" />
          <nav className="hidden items-center gap-6 text-sm font-medium text-muted-foreground md:flex">
            <span className="cursor-pointer hover:text-foreground">Personal</span>
            <span className="cursor-pointer hover:text-foreground">Business</span>
            <span className="cursor-pointer hover:text-foreground">Loans</span>
            <span className="cursor-pointer hover:text-foreground">Support</span>
          </nav>
          <div className="flex items-center gap-2">
            <Badge variant="outline" className="hidden gap-1 border-brand-emerald/40 text-brand-emerald sm:flex">
              <ShieldCheck className="size-3" /> Protected by DL-WAF
            </Badge>
            <Button size="sm">Log in</Button>
          </div>
        </div>
      </header>

      {/* Hero */}
      <section className="bg-sidebar text-sidebar-foreground">
        <div className="mx-auto grid w-full max-w-6xl gap-8 px-4 py-14 md:grid-cols-2 md:items-center">
          <div className="flex flex-col gap-5">
            <Badge className="w-fit bg-brand-gold text-brand-navy hover:bg-brand-gold">
              Trusted by 2.4 million Nigerians
            </Badge>
            <h1 className="text-4xl font-bold leading-tight md:text-5xl">
              Banking you can{" "}
              <span className="text-brand-gold">trust</span>, everywhere you are.
            </h1>
            <p className="max-w-md text-sidebar-foreground/70">
              Send money, pay bills and manage your accounts securely — backed by
              deep-learning threat protection on every request.
            </p>
            <div className="flex items-center gap-3 text-sm text-sidebar-foreground/60">
              <Lock className="size-4" /> 256-bit encryption · NDIC insured
            </div>
          </div>

          {/* Sign-in card */}
          <div className="rounded-2xl border border-sidebar-border bg-card p-6 text-card-foreground shadow-xl">
            <h2 className="text-lg font-semibold">Internet Banking</h2>
            <p className="mb-4 text-sm text-muted-foreground">
              Sign in to your Sterling Trust account.
            </p>
            <div className="flex flex-col gap-3">
              <Input placeholder="User ID" />
              <Input type="password" placeholder="Password" />
              <Button className="w-full">Secure Login</Button>
              <div className="flex items-center justify-between text-xs text-muted-foreground">
                <span className="cursor-pointer hover:text-foreground">Forgot password?</span>
                <span className="cursor-pointer hover:text-foreground">Register</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Dashboard-style overview */}
      <section className="mx-auto w-full max-w-6xl flex-1 px-4 py-12">
        <div className="mb-6 flex items-center justify-between">
          <div>
            <p className="text-sm text-muted-foreground">Welcome back,</p>
            <h2 className="text-2xl font-bold">Chinedu Okafor</h2>
          </div>
          <Badge variant="secondary">Last login: Today, 09:14</Badge>
        </div>

        <div className="grid gap-6 lg:grid-cols-3">
          {/* Accounts + quick actions */}
          <div className="flex flex-col gap-6 lg:col-span-2">
            <div className="grid gap-4 sm:grid-cols-2">
              {ACCOUNTS.map((a) => (
                <div
                  key={a.no}
                  className="flex flex-col gap-3 rounded-xl border bg-card p-5 shadow-sm"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium text-muted-foreground">
                      {a.name}
                    </span>
                    <Badge variant="outline">{a.type}</Badge>
                  </div>
                  <span className="font-mono text-sm text-muted-foreground">{a.no}</span>
                  <span className="text-2xl font-bold text-brand-navy dark:text-foreground">
                    {a.balance}
                  </span>
                </div>
              ))}
            </div>

            <div className="grid grid-cols-4 gap-3">
              {QUICK_ACTIONS.map((q) => (
                <button
                  key={q.label}
                  className="flex flex-col items-center gap-2 rounded-xl border bg-card p-4 text-center text-xs font-medium shadow-sm transition-colors hover:border-brand-gold hover:bg-accent"
                >
                  <span className="flex size-10 items-center justify-center rounded-full bg-brand-navy/10 text-brand-navy dark:bg-brand-gold/15 dark:text-brand-gold">
                    <q.icon className="size-5" />
                  </span>
                  {q.label}
                </button>
              ))}
            </div>
          </div>

          {/* Recent transactions */}
          <div className="rounded-xl border bg-card p-5 shadow-sm">
            <h3 className="mb-4 text-sm font-semibold">Recent Transactions</h3>
            <div className="flex flex-col gap-3">
              {TRANSACTIONS.map((t, i) => (
                <div key={i} className="flex items-center gap-3">
                  <span
                    className={
                      "flex size-8 items-center justify-center rounded-full " +
                      (t.credit
                        ? "bg-brand-emerald/15 text-brand-emerald"
                        : "bg-muted text-muted-foreground")
                    }
                  >
                    {t.credit ? (
                      <ArrowDownLeft className="size-4" />
                    ) : (
                      <ArrowUpRight className="size-4" />
                    )}
                  </span>
                  <div className="flex flex-1 flex-col">
                    <span className="text-sm font-medium">{t.desc}</span>
                    <span className="text-xs text-muted-foreground">{t.date}</span>
                  </div>
                  <span
                    className={
                      "text-sm font-semibold " +
                      (t.credit ? "text-brand-emerald" : "text-foreground")
                    }
                  >
                    {t.amount}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t bg-card">
        <div className="mx-auto flex w-full max-w-6xl flex-col items-center justify-between gap-3 px-4 py-6 text-sm text-muted-foreground sm:flex-row">
          <span>© {new Date().getFullYear()} Sterling Trust Bank. All rights reserved.</span>
          <span className="flex items-center gap-2">
            <ShieldCheck className="size-4 text-brand-emerald" />
            Protected by DL-WAF ·{" "}
            <Link href="/dashboard" className="font-medium underline hover:text-foreground">
              Staff SOC
            </Link>
          </span>
        </div>
      </footer>
    </div>
  );
}
