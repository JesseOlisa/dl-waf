"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { ShieldCheck } from "lucide-react";
import { login, isAuthenticated } from "@/lib/auth";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { BrandLogo, BrandMark } from "@/components/brand/BrandLogo";

export default function LoginPage() {
  const router = useRouter();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (isAuthenticated()) router.replace("/dashboard");
  }, [router]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      await login(username, password);
      router.push("/dashboard");
    } catch {
      setError("Invalid username or password.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="grid min-h-screen lg:grid-cols-2">
      {/* Brand panel */}
      <div className="relative hidden flex-col justify-between bg-sidebar p-10 text-sidebar-foreground lg:flex">
        <BrandLogo
          tagline="Security Operations Center"
          wordmarkClassName="text-sidebar-foreground text-lg"
          taglineClassName="text-sidebar-foreground/70"
        />
        <div className="flex flex-col gap-4">
          <h1 className="text-3xl font-bold leading-tight">
            Deep-learning defense for online banking.
          </h1>
          <p className="max-w-md text-sm text-sidebar-foreground/70">
            Real-time interception and classification of web attacks — SQL
            injection and cross-site scripting — protecting Sterling Trust Bank
            customers around the clock.
          </p>
        </div>
        <p className="text-xs text-sidebar-foreground/50">
          DL-WAF · MSc Thesis · AE-FUNAI
        </p>
      </div>

      {/* Login form */}
      <div className="flex items-center justify-center bg-background px-4 py-12">
        <div className="w-full max-w-sm">
          <div className="mb-8 flex flex-col items-center gap-3 text-center lg:hidden">
            <BrandMark className="size-10" />
            <span className="text-lg font-bold">Sterling Trust Bank</span>
          </div>
          <div className="mb-6 flex flex-col gap-1.5">
            <div className="flex items-center gap-2 text-brand-navy dark:text-brand-gold">
              <ShieldCheck className="size-5" />
              <span className="text-sm font-semibold uppercase tracking-wide">
                SOC Console
              </span>
            </div>
            <h2 className="text-2xl font-bold">Sign in</h2>
            <p className="text-sm text-muted-foreground">
              Authorized security personnel only.
            </p>
          </div>

          <form onSubmit={handleSubmit} className="flex flex-col gap-4">
            <div className="flex flex-col gap-2">
              <Label htmlFor="username">Username</Label>
              <Input
                id="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="username"
                placeholder="admin"
                required
              />
            </div>
            <div className="flex flex-col gap-2">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
                required
              />
            </div>
            {error && <p className="text-sm text-destructive">{error}</p>}
            <Button type="submit" className="w-full" disabled={loading}>
              {loading ? "Signing in…" : "Sign in"}
            </Button>
          </form>
        </div>
      </div>
    </div>
  );
}
