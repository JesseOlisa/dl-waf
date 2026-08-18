"use client";

import Cookies from "js-cookie";

const TOKEN_KEY = "waf_token";

export const getToken = (): string | null => Cookies.get(TOKEN_KEY) ?? null;
export const setToken = (token: string): void =>
  void Cookies.set(TOKEN_KEY, token, { sameSite: "strict" });
export const clearToken = (): void => Cookies.remove(TOKEN_KEY);
export const isAuthenticated = (): boolean => !!getToken();

export async function login(username: string, password: string): Promise<void> {
  const res = await fetch("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  if (!res.ok) throw new Error("Invalid credentials");
  const { access_token } = await res.json();
  setToken(access_token);
}

export function logout(): void {
  clearToken();
  window.location.href = "/login";
}
