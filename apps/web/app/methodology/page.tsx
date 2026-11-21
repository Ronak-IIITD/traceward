import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = { title: "Coverage & methods · TraceWard" };

export default function Methodology() {
  return (
    <main className="tw-methods">
      <section className="tw-methods-hero">
        <span className="tw-methods-kicker">Coverage &amp; methods</span>
        <h1>Know what was analyzed.</h1>
        <p>Review the Java and Python rules, the evidence they follow, and the limits of each scan.</p>
        <span className="tw-maturity">Experimental coverage</span>
      </section>

      <div className="tw-methods-grid">
        <div className="tw-methods-column">
          <section className="tw-method-card">
            <h2>Supported rules</h2>
            <div className="tw-table-scroll">
              <table>
                <caption className="tw-visually-hidden">Current scanner capabilities</caption>
                <thead>
                  <tr>
                    <th>Language</th>
                    <th>Weakness</th>
                    <th>Technique</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>Java</td>
                    <td>CWE-89</td>
                    <td>Servlet input to JDBC</td>
                  </tr>
                  <tr>
                    <td>Python</td>
                    <td>CWE-89</td>
                    <td>Console input to SQLite</td>
                  </tr>
                </tbody>
              </table>
            </div>
            <h3>Java query concatenation</h3>
            <code className="tw-rule-id">java.sql.concatenated-untrusted-input</code>
            <dl className="tw-method-steps">
              <dt>Source</dt>
              <dd>Request parameters and headers from explicitly typed servlet requests.</dd>
              <dt>Propagation</dt>
              <dd>
                Local assignments, concatenation, simple boolean branches, and the normal path through
                try-with-resources.
              </dd>
              <dt>Sink</dt>
              <dd>
                Supported JDBC execution, batching, and query preparation calls on explicitly typed
                receivers.
              </dd>
            </dl>
            <h3>Python query concatenation</h3>
            <code className="tw-rule-id">python.sqlite.concatenated-input</code>
            <dl className="tw-method-steps">
              <dt>Source</dt>
              <dd>Interactive input from the built-in <code>input()</code>.</dd>
              <dt>Propagation</dt>
              <dd>Straight-line assignments and string concatenation with <code>+</code>.</dd>
              <dt>Sink</dt>
              <dd>
                <code>execute()</code> on a local SQLite connection or a cursor created with{" "}
                <code>db.cursor()</code>. Bind values separately using placeholders.
              </dd>
            </dl>
          </section>
          <section className="tw-method-card">
            <h2>Known limitations</h2>
            <p>
              A finding is a medium-confidence candidate for review. A scan with zero findings covers
              only the paths the selected rule can follow.
            </p>
            <ul>
              <li>
                Complex conditions, loops, and exception handlers can stop analysis of an affected path.
              </li>
              <li>
                Fields, framework wrappers, runtime dispatch, and flow across method boundaries are
                outside the current model.
              </li>
              <li>
                In Java, different tainted values after a branch can leave the continuation unresolved. Check the
                scan diagnostics.
              </li>
              <li>
                The Python rule skips branches, f-strings, web request inputs, and flows across functions.
              </li>
            </ul>
          </section>
        </div>
        <aside className="tw-methods-column">
          <section className="tw-method-card">
            <h2>Source privacy</h2>
            <p>
              Starting a scan sends the snippet to your local scanner. A disposable worker parses the
              source in memory. Submitted code is never executed.
            </p>
            <p>
              Downloadable reports contain evidence and locations. Export saves the report on your
              device.
            </p>
          </section>
          <section className="tw-method-card">
            <h2>Coverage roadmap</h2>
            <ol className="tw-roadmap">
              <li>
                <small>Available</small>
                <strong>Java and Python CWE-89</strong>
                <p>The CLI and dashboard share the same experimental static rules.</p>
              </li>
              <li>
                <small>Research</small>
                <strong>Offline model evaluation</strong>
                <p>
                  Juliet and CVE-linked MegaVul provide research baselines. Live scans use static
                  analysis. Model promotion requires independently reviewed, held-out data.
                </p>
              </li>
              <li>
                <small>Planned</small>
                <strong>Broader language coverage</strong>
                <p>
                  Additional languages and weakness classes require their own rules, fixtures, and
                  independent evaluation.
                </p>
              </li>
            </ol>
          </section>
        </aside>
      </div>
      <Link className="tw-return" href="/">
        Return to scan workspace <span aria-hidden="true">→</span>
      </Link>
    </main>
  );
}
