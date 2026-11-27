"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { signOut } from "@/app/login/actions";

export default function Header({ signedIn }: { signedIn: boolean }) {
  const pathname = usePathname();
  const home = pathname === "/";
  const workspace = pathname === "/workspace";
  return (
    <header className={home ? "tw-header tw-header-landing" : "tw-header"}>
      <div className="tw-header-inner">
        <Link href="/" className="tw-wordmark" aria-label="TraceWard home">
          <svg className="tw-mark" viewBox="0 0 32 36" aria-hidden="true" fill="none">
            <path d="M16 2 29 7v10c0 7.7-5.5 13-13 17C8.5 30 3 24.7 3 17V7Z" fill="currentColor" />
            <path
              d="M8 13h17m-13 4h9m-5-4v12"
              stroke="#092420"
              strokeWidth="2.6"
              strokeLinecap="square"
            />
          </svg>
          TraceWard
        </Link>
        <nav className="tw-navigation" aria-label="Main">
          {signedIn && (
            <Link href="/workspace" aria-current={workspace ? "page" : undefined}>
              Scan workspace
            </Link>
          )}
          <Link href="/methodology" aria-current={pathname === "/methodology" ? "page" : undefined}>
            Coverage &amp; methods
          </Link>
        </nav>
        {signedIn ? (
          <form action={signOut} className="tw-account">
            <button type="submit">Sign out</button>
          </form>
        ) : (
          <Link
            href="/login"
            className="tw-account"
            aria-current={pathname === "/login" ? "page" : undefined}
          >
            Sign in
          </Link>
        )}
      </div>
    </header>
  );
}
