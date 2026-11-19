"use client";

import { useRef, useState } from "react";
import type { Location, ScanResult } from "@/lib/contracts";
import { examples } from "@/lib/examples";

const MAX_SOURCE = 65536;
function byteColumn(text: string, column: number) {
  // Tree-sitter reports UTF-8 bytes. Textarea selection uses UTF-16 code units.
  const bytes = new TextEncoder().encode(text);
  return new TextDecoder().decode(bytes.slice(0, column - 1)).length;
}
export default function Workspace() {
  const [code, setCode] = useState(examples.vulnerable);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [scannedCode, setScannedCode] = useState("");
  const [selected, setSelected] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const editor = useRef<HTMLTextAreaElement>(null);
  const size = new TextEncoder().encode(code).length;
  const finding = result?.findings[selected];
  const stale = result !== null && scannedCode !== code;

  function replace(value: string) {
    setCode(value); setResult(null); setError(""); setSelected(0);
  }
  function reveal(location: Location) {
    if (!editor.current || stale) return;
    const lines = code.split("\n");
    const offset = (line: number, column: number) => lines.slice(0, line - 1).reduce(
      (sum, text) => sum + text.length + 1, 0) + byteColumn(lines[line - 1] ?? "", column);
    editor.current.focus();
    editor.current.setSelectionRange(
      offset(location.start_line, location.start_column), offset(location.end_line, location.end_column));
    editor.current.scrollTop = Math.max(0, (location.start_line - 3) * 24);
  }
  async function scan() {
    setBusy(true); setError(""); setResult(null);
    try {
      const response = await fetch("/api/v1/scans/snippet", {
        method: "POST", headers: {"content-type": "application/json"},
        body: JSON.stringify({language: "java", code}), signal: AbortSignal.timeout(15000)
      });
      const body = await response.json();
      if (!response.ok) throw new Error(body.error?.message ?? "The scan failed. Try again.");
      setScannedCode(code); setResult(body as ScanResult); setSelected(0);
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "The scan failed.");
    } finally { setBusy(false); }
  }
  function download() {
    if (!result) return;
    const url = URL.createObjectURL(new Blob([JSON.stringify(result, null, 2)], {type: "application/json"}));
    const link = document.createElement("a");
    link.href = url; link.download = "traceward-results.json"; link.click();
    URL.revokeObjectURL(url);
  }
  return <main>
    <section className="intro"><div><p className="eyebrow">JAVA APPLICATION SECURITY</p>
      <h1>Follow the evidence.</h1><p>Scan your Java code and inspect potential SQL injection paths.</p></div>
      <div className="coverage-note"><span className="status-dot"/>Experimental coverage<br/><small>Java · CWE-89 · Local static analysis</small></div>
    </section>
    <div className="workspace">
      <section className="panel editor-panel" aria-labelledby="editor-title">
        <div className="panel-heading"><h2 id="editor-title">Source code</h2><span className="language">Java</span></div>
        <div className="toolbar"><span>Load an example</span><button disabled={busy} onClick={() => replace(examples.vulnerable)}>Vulnerable</button>
          <button disabled={busy} onClick={() => replace(examples.safe)}>Parameterized</button><button className="clear" disabled={busy} onClick={() => replace("")}>Clear</button></div>
        <div className="editor-wrap"><div className="line-numbers" aria-hidden="true">{code.split("\n").map((_, n) => <div key={n}>{n + 1}</div>)}</div>
          <textarea ref={editor} aria-label="Java source code" value={code} onChange={event => setCode(event.target.value)}
            disabled={busy} spellCheck={false} wrap="off"/></div>
        <div className="editor-bottom"><span className={size > MAX_SOURCE ? "danger" : ""}>{size.toLocaleString()} / 65,536 bytes</span>
          <button className="primary" onClick={scan} disabled={busy || !code.trim() || size > MAX_SOURCE}>{busy ? "Scanning…" : "Scan Java"}</button></div>
        <p className="privacy">Your source is processed in memory by the local scanner. Submitted code is never executed.</p>
      </section>
      <section className="panel result-panel" aria-labelledby="result-title">
        <div className="panel-heading"><h2 id="result-title">Scan results</h2>{result && <button onClick={download}>Export JSON</button>}</div>
        <div className="result-content" aria-live="polite" aria-busy={busy}>
          {error && <p role="alert" className="error-box">{error}</p>}
          {busy && <div className="empty"><span className="loader"/><h3>Tracing supported flows</h3><p>Parsing Java and checking request input at JDBC sinks.</p></div>}
          {!result && !busy && !error && <div className="empty"><span className="empty-mark" aria-hidden="true">⌕</span><h3>Your evidence starts here</h3><p>Paste a Java class or use an example, then run a scan.</p><p className="muted">One experimental rule. Every finding includes its actual source locations.</p></div>}
          {result && <>
            <div className="summary"><div><strong>{result.summary.findings}</strong><span>Potential findings</span></div><div><strong>{result.summary.errors}</strong><span>Analysis errors</span></div><div><strong>{result.duration_ms}<small>ms</small></strong><span>Analysis time</span></div></div>
            <p className="coverage-warning">Partial coverage · Supported checks cover a limited Java CWE-89 subset.</p>
            {stale && <p role="status" className="coverage-warning">Source changed. Run the scan again to refresh locations.</p>}
            {!finding && <div className="no-findings"><h3>{result.summary.errors ? "Analysis needs attention" : "No supported findings"}</h3><p>{result.summary.errors ? "Review the diagnostics below before interpreting this scan." : "This result covers the enabled rule. Continue reviewing unsupported code paths."}</p></div>}
            {result.findings.length > 0 && <div className="finding-list">{result.findings.map((item, index) =>
              <button className={selected === index ? "finding active" : "finding"} key={item.id} onClick={() => setSelected(index)}>
                <span className="severity">{item.severity}</span><strong>{item.cwe.join(", ")} · Line {item.location.start_line}</strong><span>{item.title}</span>
              </button>)}</div>}
            {finding && <article className="detail"><p className="eyebrow">FINDING DETAILS</p><h3>{finding.title}</h3>
              <div className="tags"><span>{finding.confidence} confidence</span><span>{finding.evidence_level.replaceAll("_", " ")}</span></div>
              <h4>Source to sink</h4><ol className="trace">{finding.evidence.flow.map((step, index) => <li key={index}>
                <button onClick={() => reveal(step.location)} disabled={stale}><span>{step.kind}</span><code>{step.symbol}</code><small>Line {step.location.start_line}</small></button></li>)}</ol>
              <h4>Remediation</h4><p>{finding.guidance}</p>
              <h4>Review context</h4><ul>{finding.evidence.uncertainties.map(item => <li key={item}>{item}</li>)}</ul>
              <a href="https://cwe.mitre.org/data/definitions/89.html" target="_blank" rel="noreferrer">Read the CWE-89 reference</a>
            </article>}
            {result.diagnostics.length > 0 && <section className="diagnostics"><h3>Diagnostics</h3>{result.diagnostics.map((item, index) => <p key={index}><strong>{item.code}</strong> {item.message}{item.location && <button disabled={stale} onClick={() => reveal(item.location!)}>Line {item.location.start_line}</button>}</p>)}</section>}
            <details className="limitations"><summary>Coverage and limitations</summary><ul>{result.coverage.limitations.map(item => <li key={item}>{item}</li>)}</ul></details>
          </>}
        </div>
      </section>
    </div>
  </main>;
}
