import { NextRequest } from "next/server";
import { isWorkspaceSession, sessionCookie } from "@/lib/workspace-session";

export const runtime = "nodejs";
const MAX_BODY = 256 * 1024;
const error = (status: number, code: string, message: string) =>
  Response.json(
    { error: { code, message, request_id: crypto.randomUUID() } },
    { status, headers: { "cache-control": "no-store" } },
  );

export async function POST(request: NextRequest) {
  if (!isWorkspaceSession(request.cookies.get(sessionCookie)?.value)) {
    return error(401, "AUTH_REQUIRED", "Sign in to the workspace to scan source code.");
  }
  if (
    request.headers.get("content-type")?.split(";")[0].trim().toLowerCase() !== "application/json"
  )
    return error(415, "INVALID_INPUT", "Use application/json.");
  const body = request.body?.getReader();
  if (!body) return error(422, "INVALID_INPUT", "A JSON body is required.");
  const deadline = AbortSignal.timeout(5000);
  const chunks: Uint8Array[] = [];
  let length = 0;
  const abort = () => {
    void body.cancel();
  };
  deadline.addEventListener("abort", abort, { once: true });
  try {
    while (true) {
      const { done, value } = await body.read();
      if (deadline.aborted) return error(408, "INVALID_INPUT", "Request timed out.");
      if (done) break;
      length += value.length;
      if (length > MAX_BODY) {
        await body.cancel();
        return error(413, "INPUT_TOO_LARGE", "Request exceeds 256 KiB.");
      }
      chunks.push(value);
    }
    const payload = Buffer.concat(chunks);
    const origin = process.env.TRACEWARD_API_URL ?? "http://127.0.0.1:8000";
    const response = await fetch(new URL("/api/v1/scans/snippet", origin), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: payload,
      signal: AbortSignal.timeout(10000),
      cache: "no-store",
    });
    // Forward the versioned contract, including API validation error statuses.
    return new Response(await response.text(), {
      status: response.status,
      headers: { "content-type": "application/json", "cache-control": "no-store" },
    });
  } catch {
    return error(
      503,
      "API_UNAVAILABLE",
      "The scanner is unavailable. Check that the API is running.",
    );
  } finally {
    deadline.removeEventListener("abort", abort);
    body.releaseLock();
  }
}
