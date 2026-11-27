import Image from "next/image";
import Link from "next/link";

export default function Home() {
  return (
    <main className="landing">
      <section className="landing-hero" aria-labelledby="landing-title">
        <div className="landing-scene" aria-hidden="true">
          <Image src="/images/lighthouse.webp" alt="" fill preload unoptimized />
        </div>
        <div className="public-frame landing-layout">
          <div className="landing-copy">
            <p className="public-kicker">Local static analysis</p>
            <h1 id="landing-title">TraceWard</h1>
            <p className="landing-tagline">Trace the risk. Secure the code.</p>
            <p className="landing-description">
              Follow untrusted input to SQL queries and see the source lines behind each finding.
            </p>
            <div className="landing-actions">
              <Link href="/workspace" className="entry-primary">
                Open workspace <span aria-hidden="true">↗</span>
              </Link>
              <Link href="/methodology" className="landing-secondary">
                Explore coverage
              </Link>
            </div>
          </div>
          <div className="landing-baseline">
            <p>
              <span /> Experimental coverage · CWE-89
            </p>
            <p>Source is processed in memory and never executed.</p>
          </div>
        </div>
      </section>

      <section className="public-frame landing-evidence" aria-labelledby="evidence-title">
        <div>
          <p className="public-kicker">Source-to-sink evidence</p>
          <h2 id="evidence-title">See where input becomes a query.</h2>
          <p className="landing-description">
            Scan Java, Python, JavaScript, or TypeScript. Select a finding to jump from the database
            call back through the input and the lines that carried it there.
          </p>
          <Link href="/workspace" className="landing-secondary">
            Try an example in the workspace <span aria-hidden="true">↗</span>
          </Link>
        </div>
        <ol className="landing-trace" aria-label="Example Java trace">
          <li>
            <span>Source</span>
            <code>request.getParameter(…)</code>
          </li>
          <li>
            <span>Propagation</span>
            <code>String query = …</code>
          </li>
          <li>
            <span>Sink</span>
            <code>statement.executeQuery(…)</code>
          </li>
        </ol>
      </section>
    </main>
  );
}
