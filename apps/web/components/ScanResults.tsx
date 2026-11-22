"use client";

import { useState } from "react";
import type { Finding, Location, ScanResult } from "@/lib/contracts";
import { languageNames, type Language } from "@/lib/examples";
import "./results.css";

type Props = {
  language: Language;
  result: ScanResult | null;
  busy: boolean;
  error: string;
  stale: boolean;
  lines: number;
  selected: number;
  onSelect: (index: number) => void;
  onReveal: (location: Location) => void;
  onExample: () => void;
  onRetry: () => void;
};

const nodeFix = {
  description: "A command-line argument contributes to SQL passed to the Node.js SQLite API.",
  before: 'db.prepare("SELECT name FROM sqlite_schema WHERE name = " + name);',
  after: [
    'const statement = db.prepare("SELECT name FROM sqlite_schema WHERE name = ?");',
    "statement.get(name);",
  ],
};

const fixes = {
  java: {
    description: "Request data reaches a JDBC call through a concatenated SQL query.",
    before: 'statement.executeQuery("SELECT name FROM users WHERE id=" + id);',
    after: [
      'String sql = "SELECT name FROM users WHERE id = ?";',
      "try (PreparedStatement ps = connection.prepareStatement(sql)) {",
      "    ps.setString(1, id);",
      "    try (ResultSet rows = ps.executeQuery()) {",
      "        // Read rows here.",
      "    }",
      "}",
    ],
  },
  python: {
    description: "Untrusted input reaches a SQLite call through a concatenated SQL query.",
    before: 'db.execute("SELECT name FROM sqlite_schema WHERE name = " + name)',
    after: [
      'sql = "SELECT name FROM sqlite_schema WHERE name = ?"',
      "db.execute(sql, (name,))",
    ],
  },
  javascript: nodeFix,
  typescript: nodeFix,
};

function Glyph({ type }: { type: "activity" | "arrow" | "check" | "alert" | "copy" | "export" }) {
  const paths = {
    activity: "M2 12h5l3-7 4 14 3-7h5",
    arrow: "M5 12h14m-5-5 5 5-5 5",
    check: "m5 12 4 4L19 6",
    alert: "M12 3l10 17H2L12 3Zm0 5v5m0 3v.5",
    copy: "M8 8h12v13H8V8Zm8-4V2H3v15h2",
    export: "M12 3v12m-5-5 5 5 5-5M3 16v5h18v-5",
  };
  return (
    <svg
      aria-hidden="true"
      width="16"
      height="16"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d={paths[type]} />
    </svg>
  );
}

function TraceSchematic() {
  return (
    <svg className="trace-schematic" aria-hidden="true" viewBox="0 0 240 128" fill="none">
      <defs>
        <pattern id="trace-dots" width="8" height="8" patternUnits="userSpaceOnUse">
          <circle cx="4" cy="4" r=".8" fill="currentColor" opacity=".35" />
        </pattern>
        <radialGradient id="trace-vignette">
          <stop offset=".15" stopColor="white" />
          <stop offset="1" stopColor="black" />
        </radialGradient>
        <mask id="trace-field">
          <rect width="240" height="128" fill="url(#trace-vignette)" />
        </mask>
      </defs>
      <rect width="240" height="128" fill="url(#trace-dots)" mask="url(#trace-field)" />
      <g stroke="currentColor" strokeLinejoin="round">
        <g opacity=".45">
          <path d="M25 48h34l15 16h18M42 82h17l10-10h23M148 64h15l18-18h26M148 72h19l16 16h16" />
          <circle cx="23" cy="48" r="2" />
          <circle cx="40" cy="82" r="2" />
          <circle cx="209" cy="46" r="2" />
          <circle cx="201" cy="88" r="2" />
          <path d="M75 38v-8h10m70 0h10v8M75 91v8h10m70 0h10v-8" />
        </g>
        <path
          d="m120 23 32 13v25c0 19-15 33-32 43-17-10-32-24-32-43V36z"
          fill="var(--surface)"
          opacity=".85"
        />
        <path
          d="m120 31 25 10v21c0 14-11 26-25 35-14-9-25-21-25-35V41z"
          fill="currentColor"
          fillOpacity=".07"
        />
        <path d="M104 65h9l5-13 6 23 5-12h8" strokeWidth="2.2" strokeLinecap="round" />
      </g>
    </svg>
  );
}

function CopyButton({ text, label }: { text: string | (() => string); label: string }) {
  const [message, setMessage] = useState("");
  async function copy() {
    try {
      await navigator.clipboard.writeText(typeof text === "string" ? text : text());
      setMessage("Copied");
    } catch {
      setMessage("Clipboard unavailable");
    }
  }
  return (
    <button type="button" className="rs-tool" onClick={copy} aria-label={label}>
      <Glyph type={message === "Copied" ? "check" : "copy"} />
      <span role="status">{message || label}</span>
    </button>
  );
}

function exportReport(report: ScanResult) {
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }),
  );
  const link = document.createElement("a");
  link.href = url;
  link.download = "traceward-results.json";
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function rangeText(location: Location) {
  return location.start_line === location.end_line
    ? String(location.start_line)
    : `${location.start_line}–${location.end_line}`;
}

function FindingCard({
  finding,
  language,
  active,
  stale,
  select,
  reveal,
  index,
}: {
  finding: Finding;
  language: Language;
  active: boolean;
  stale: boolean;
  select: () => void;
  reveal: Props["onReveal"];
  index: number;
}) {
  const location = finding.location;
  const fix = fixes[language];
  return (
    <article
      className="rs-card"
      data-selected={active}
      style={{ animationDelay: `${Math.min(index, 4) * 24}ms` }}
    >
      <div className="rs-tags">
        <span className="rs-severity" data-severity={finding.severity.toLowerCase()}>
          {finding.severity}
        </span>
        <span>{finding.cwe.join(", ")}</span>
        <span>{finding.confidence} confidence</span>
      </div>
      <h3>
        <button
          type="button"
          className="rs-card-title"
          onClick={select}
          aria-expanded={active}
          aria-controls={`trace-${finding.id}`}
        >
          {finding.title}
          <Glyph type="arrow" />
        </button>
      </h3>
      <code className="rs-location">
        {location.path}:{rangeText(location)}
      </code>
      <div id={`trace-${finding.id}`} hidden={!active} className="rs-evidence">
        <p>{fix.description}</p>
        <h4>Source to sink</h4>
        <ol className="rs-trace">
          {finding.evidence.flow.map((step, i) => (
            <li key={i} data-kind={step.kind}>
              <button
                type="button"
                disabled={stale}
                onClick={() => reveal(step.location)}
                aria-label={`${step.kind} ${step.symbol} Line ${step.location.start_line}`}
              >
                <span>{step.kind}</span>
                <code>{step.symbol}</code>
                <small>L{rangeText(step.location)}</small>
              </button>
            </li>
          ))}
        </ol>
        <details className="rs-details">
          <summary>Suggested fix</summary>
          <p>{finding.guidance}</p>
          <p className="rs-code-label">Example parameterized query</p>
          <pre className="rs-diff" tabIndex={0} aria-label={`Example ${languageNames[language]} parameterization diff`}>
            <code>
              <span className="rs-del">{`- ${fix.before}\n`}</span>
              {fix.after.map((line, i) => (
                <span className="rs-add" key={i}>{`+ ${line}\n`}</span>
              ))}
            </code>
          </pre>
          <CopyButton text={fix.after.join("\n")} label="Copy example" />
        </details>
        <details className="rs-details">
          <summary>Review context</summary>
          <code className="rs-location">{finding.rule_id}</code>
          <p>{finding.evidence_level.replaceAll("_", " ")}</p>
          <ul>
            {finding.evidence.uncertainties.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
          <a href="https://cwe.mitre.org/data/definitions/89.html" target="_blank" rel="noreferrer">
            CWE-89 reference ↗
          </a>
        </details>
      </div>
    </article>
  );
}

export default function ScanResults({
  language,
  result,
  busy,
  error,
  stale,
  lines,
  selected,
  onSelect,
  onReveal,
  onExample,
  onRetry,
}: Props) {
  const languageName = languageNames[language];
  const errors = result?.summary.errors ?? 0;
  const count = result?.summary.findings ?? 0;
  const status = busy
    ? "Scanning"
    : error || errors
      ? "Needs attention"
      : result
        ? "Scan complete"
        : "Awaiting scan";
  return (
    <section className="panel results-panel" aria-labelledby="result-title">
      <div className="rs-heading">
        <h2 id="result-title">
          <span className="rs-header-icon">
            <Glyph type="activity" />
          </span>
          Scan results
        </h2>
        <span
          className="rs-status"
          data-state={busy ? "busy" : error || errors ? "error" : result ? "done" : "idle"}
          aria-live="polite"
        >
          <i aria-hidden="true" />
          {status}
          {result && (
            <span className="sr-only">
              . {count} findings, {errors} analysis errors.
            </span>
          )}
        </span>
      </div>
      <dl className="rs-metrics">
        <div>
          <dt>Findings</dt>
          <dd className={count > 0 ? "rs-count" : ""}>{result ? count : "—"}</dd>
        </div>
        <div>
          <dt>Scan time</dt>
          <dd>
            {result ? (
              <>
                {result.duration_ms}
                <small>ms</small>
              </>
            ) : (
              "—"
            )}
          </dd>
        </div>
        <div title="Source lines in the analyzed snippet. Rule coverage is partial.">
          <dt>Source lines</dt>
          <dd>{result ? lines : "—"}</dd>
        </div>
      </dl>
      <div className="rs-scroll" aria-busy={busy} tabIndex={0} role="region" aria-label="Scan evidence">
        {busy ? (
          <div className="rs-pending">
            <h3>Tracing supported flows</h3>
            <p>Checking {languageName} source for supported SQL injection paths.</p>
            <div className="rs-skeleton" aria-hidden="true">
              {[0, 1, 2].map((n) => (
                <div key={n}>
                  <i />
                  <span />
                  <span />
                </div>
              ))}
            </div>
          </div>
        ) : error ? (
          <div className="rs-state rs-error">
            <Glyph type="alert" />
            <h3>Scan interrupted</h3>
            <p role="alert">{error}</p>
            <button className="rs-action" onClick={onRetry}>
              Retry scan <Glyph type="arrow" />
            </button>
          </div>
        ) : !result ? (
          <div className="rs-empty">
            <TraceSchematic />
            <h3>Ready to trace</h3>
            <ol>
              <li>Add {languageName} source or choose an example.</li>
              <li>
                Run <b>Scan {languageName}</b> to inspect the evidence.
              </li>
            </ol>
            <button type="button" className="rs-action" onClick={onExample}>
              Try the vulnerable example <Glyph type="arrow" />
            </button>
          </div>
        ) : (
          <div className="rs-report" key={result.scan_id}>
            {stale && (
              <p role="status" className="rs-warning">
                Source changed. Run the scan again to refresh locations.
              </p>
            )}
            {errors > 0 && (
              <div className="rs-state rs-error">
                <Glyph type="alert" />
                <h3>Analysis needs attention</h3>
                <p>Review the diagnostics and edit the source before retrying.</p>
                <button className="rs-action" onClick={onRetry}>
                  Retry scan <Glyph type="arrow" />
                </button>
              </div>
            )}
            {!errors && !count && (
              <div className="rs-state rs-clean">
                <Glyph type="check" />
                <h3>No SQL injection paths found</h3>
                <p>
                  This experimental rule checks a limited set of {languageName} flows. Unsupported paths still need
                  review.
                </p>
              </div>
            )}
            {result.findings.map((finding, index) => (
              <FindingCard
                key={finding.id}
                finding={finding}
                language={language}
                index={index}
                active={selected === index}
                stale={stale}
                reveal={onReveal}
                select={() => {
                  onSelect(index);
                  if (!stale) onReveal(finding.location);
                }}
              />
            ))}
            {result.diagnostics.length > 0 && (
              <section className="rs-diagnostics">
                <h3>Diagnostics</h3>
                {result.diagnostics.map((diagnostic, i) => (
                  <div key={i}>
                    <strong>{diagnostic.code}</strong>
                    <p>{diagnostic.message}</p>
                    {diagnostic.location && (
                      <button
                        className="rs-tool"
                        disabled={stale}
                        onClick={() => onReveal(diagnostic.location!)}
                      >
                        Line {rangeText(diagnostic.location)}
                      </button>
                    )}
                  </div>
                ))}
              </section>
            )}
            <details className="rs-details">
              <summary>Coverage and limitations</summary>
              <ul>
                {result.coverage.limitations.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </details>
          </div>
        )}
      </div>
      {result && !busy && (
        <div className="rs-actions">
          <CopyButton
            key={result.scan_id}
            text={() => JSON.stringify(result, null, 2)}
            label="Copy JSON"
          />
          <button type="button" className="rs-tool" onClick={() => exportReport(result)}>
            <Glyph type="export" />
            Export JSON
          </button>
        </div>
      )}
    </section>
  );
}
