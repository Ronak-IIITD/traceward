import type { Metadata } from "next";
import Header from "@/components/Header";
import { hasWorkspaceSession } from "@/lib/workspace-session";
import "./globals.css";
import "./navigation.css";
import "./public.css";

export const metadata: Metadata = {
  title: "TraceWard · Code security workspace",
  description: "Inspect SQL injection candidates in Java, Python, JavaScript, and TypeScript.",
};

export default async function Layout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <Header signedIn={await hasWorkspaceSession()} />
        {children}
        <footer className="tw-footer">
          <span>
            <svg
              width="14"
              height="16"
              viewBox="0 0 24 24"
              aria-hidden="true"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.7"
            >
              <path d="m12 2 8 3v6c0 5-3.6 9-8 11-4.4-2-8-6-8-11V5z" />
              <path d="m8.5 12 2.3 2.3 4.7-5" />
            </svg>
            Local processing · Source stays in memory
          </span>
          <span>
            TraceWard <b aria-hidden="true">/</b> SQL injection analysis
          </span>
        </footer>
      </body>
    </html>
  );
}
