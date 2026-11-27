import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { cookies } from "next/headers";

export const sessionCookie = "traceward_workspace";
export const sessionLifetime = 8 * 60 * 60;

function workspaceKey() {
  const key = process.env.TRACEWARD_WORKSPACE_KEY;
  return key && Buffer.byteLength(key) >= 32 && Buffer.byteLength(key) <= 256 ? key : undefined;
}

export function workspaceConfigured() {
  return workspaceKey() !== undefined;
}

export function verifyWorkspaceKey(candidate: string) {
  const key = workspaceKey();
  if (!key || Buffer.byteLength(candidate) > 256) return false;
  return timingSafeEqual(
    createHash("sha256").update(key).digest(),
    createHash("sha256").update(candidate).digest(),
  );
}

function signature(key: string, claims: string) {
  return createHmac("sha256", key).update("traceward-workspace-v1:").update(claims).digest();
}

export function createWorkspaceSession() {
  const key = workspaceKey();
  if (!key) throw new Error("The workspace key is missing or invalid.");
  const expires = Math.floor(Date.now() / 1000) + sessionLifetime;
  const nonce = randomBytes(16).toString("hex");
  const claims = [expires, nonce].join(".");
  return [claims, signature(key, claims).toString("hex")].join(".");
}

export function isWorkspaceSession(value?: string) {
  const key = workspaceKey();
  if (!key || !value || value.length > 110) return false;
  const match = /^([0-9]{1,12})\.([a-f0-9]{32})\.([a-f0-9]{64})$/.exec(value);
  if (!match) return false;
  const [, expires, nonce, mac] = match;
  if (Number(expires) <= Math.floor(Date.now() / 1000)) return false;
  return timingSafeEqual(signature(key, [expires, nonce].join(".")), Buffer.from(mac, "hex"));
}

export async function hasWorkspaceSession() {
  return isWorkspaceSession((await cookies()).get(sessionCookie)?.value);
}
