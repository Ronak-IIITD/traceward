"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const destinations = [
  { href: "/", title: "Scan workspace" },
  { href: "/methodology", title: "Coverage & methods" },
];

export default function Header() {
  const pathname = usePathname();
  return (
    <header className="tw-header">
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
          {destinations.map(({ href, title }) => (
            <Link key={href} href={href} aria-current={pathname === href ? "page" : undefined}>
              {title}
            </Link>
          ))}
        </nav>
        <span className="tw-local">
          <i aria-hidden="true" />
          Local workspace
        </span>
      </div>
    </header>
  );
}
