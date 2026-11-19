import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";

export const metadata: Metadata = {
  title: "TraceWard · Code security workspace",
  description: "Inspect Java SQL injection candidates and the evidence behind them."
};
export default function Layout({children}: {children: React.ReactNode}) {
  return <html lang="en"><body>
    <header className="site-header"><Link href="/" className="brand"><span className="brand-icon" aria-hidden="true">T</span>TraceWard</Link>
      <nav aria-label="Main"><Link href="/">Scan workspace</Link><Link href="/methodology">Coverage & methods</Link></nav>
      <span className="local-label">LOCAL WORKSPACE</span>
    </header>
    {children}
    <footer>Trace the risk. Secure the code.<span>Source is submitted only when you select Scan Java.</span></footer>
  </body></html>;
}
