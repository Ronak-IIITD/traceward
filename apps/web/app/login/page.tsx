import type { Metadata } from "next";
import Image from "next/image";
import Link from "next/link";
import { redirect } from "next/navigation";
import { hasWorkspaceSession, workspaceConfigured } from "@/lib/workspace-session";
import SignInForm from "./SignInForm";

export const metadata: Metadata = { title: "Sign in · TraceWard" };

export default async function Login() {
  if (await hasWorkspaceSession()) redirect("/workspace");

  return (
    <main className="entry">
      <div className="entry-scene" aria-hidden="true">
        <Image src="/images/lighthouse.webp" fill unoptimized alt="" />
      </div>
      <section className="entry-panel" aria-labelledby="entry-title">
        <div className="entry-content">
          <p className="public-kicker">Local workspace</p>
          <h1 id="entry-title">Sign in.</h1>
          <p className="entry-description">
            Unlock your workspace to scan snippets and review the evidence.
          </p>
          {workspaceConfigured() ? (
            <SignInForm />
          ) : (
            <div className="entry-setup">
              Start TraceWard with <code>./start.sh</code> from the project directory to generate a
              workspace key, then reload this page.
            </div>
          )}
          <Link href="/" className="entry-back">
            Back to TraceWard
          </Link>
        </div>
      </section>
    </main>
  );
}
