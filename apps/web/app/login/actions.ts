"use server";

import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import {
  createWorkspaceSession,
  sessionCookie,
  sessionLifetime,
  verifyWorkspaceKey,
  workspaceConfigured,
} from "@/lib/workspace-session";

const cookieOptions = {
  httpOnly: true,
  sameSite: "strict",
  secure: process.env.TRACEWARD_SECURE_COOKIES === "1",
  path: "/",
} as const;

export async function signIn(_previous: string, form: FormData) {
  if (!workspaceConfigured()) return "Set up a workspace key and restart TraceWard.";
  const candidate = form.get("key");
  if (typeof candidate !== "string" || !verifyWorkspaceKey(candidate)) {
    return "That workspace key didn’t match. Check the terminal where TraceWard is running.";
  }
  (await cookies()).set(sessionCookie, createWorkspaceSession(), {
    ...cookieOptions,
    maxAge: sessionLifetime,
  });
  redirect("/workspace");
}

export async function signOut() {
  (await cookies()).set(sessionCookie, "", { ...cookieOptions, maxAge: 0 });
  redirect("/login");
}
