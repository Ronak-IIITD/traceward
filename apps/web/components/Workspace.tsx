"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import SourceEditor from "@/components/SourceEditor";
import ScanResults from "@/components/ScanResults";
import type { Location, ScanResult } from "@/lib/contracts";
import { examples, languageNames, languages, snippetNames, type Language } from "@/lib/examples";

const MAX_SOURCE = 65536;
const paths = {
  code: "m8 6-6 6 6 6m8-12 6 6-6 6m-3-15-2 18",
  unsafe: "m12 3 9 17H3Zm0 6v5m0 2v1",
  safe: "m12 2 8 3v6c0 5-3 8-8 11-5-3-8-6-8-11V5Zm-4 9 3 3 5-6",
  clear: "M4 6h16M9 6V3h6v3M7 6l1 15h8l1-15",
  file: "M5 2h9l5 5v15H5Zm9 0v6h5",
  wrap: "M3 6h17M3 11h12a4 4 0 0 1 0 8h-4m2-3-3 3 3 3M3 16h4",
  play: "m7 4 13 8-13 8Z",
  lock: "M6 10h12v11H6Zm2 0V7a4 4 0 1 1 8 0v3m-4 4v3",
};
function Icon({ name, size = 16 }: { name: keyof typeof paths; size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.65"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d={paths[name]} />
    </svg>
  );
}

export default function Workspace() {
  const [language, setLanguage] = useState<Language>("java");
  const [drafts, setDrafts] = useState(() =>
    Object.fromEntries(languages.map((item) => [item, examples[item].vulnerable])),
  );
  const code = drafts[language];
  const languageName = languageNames[language];
  const example = examples[language];
  const [result, setResult] = useState<ScanResult | null>(null);
  const [scannedCode, setScannedCode] = useState("");
  const [selected, setSelected] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [wrap, setWrap] = useState(true);
  const [reveal, setReveal] = useState<{ location: Location; nonce: number } | null>(null);
  const [shortcut, setShortcut] = useState("Ctrl ↵");
  const inFlight = useRef(false);
  const workspace = useRef<HTMLDivElement>(null);
  const size = new TextEncoder().encode(code).length;
  const stale = !!result && scannedCode !== code;
  useEffect(() => {
    if (/Mac|iPad|iPhone/.test(navigator.platform)) setShortcut("⌘ ↵");
  }, []);

  function setCode(value: string) {
    setDrafts((previous) => ({ ...previous, [language]: value }));
  }

  function resetResults() {
    setResult(null);
    setError("");
    setSelected(0);
    setReveal(null);
  }

  function replace(value: string) {
    setCode(value);
    resetResults();
  }

  const scan = useCallback(async (source: string, sourceLanguage: Language) => {
    if (inFlight.current || !source.trim() || new TextEncoder().encode(source).length > MAX_SOURCE)
      return;
    inFlight.current = true;
    setBusy(true);
    setError("");
    setResult(null);
    setReveal(null);
    try {
      const response = await fetch("/api/v1/scans/snippet", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ language: sourceLanguage, code: source }),
        signal: AbortSignal.timeout(15000),
      });
      const body = await response.json();
      if (!response.ok) throw new Error(body.error?.message ?? "The scan failed. Try again.");
      setScannedCode(source);
      setResult(body as ScanResult);
      setSelected(0);
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "The scan failed.");
    } finally {
      inFlight.current = false;
      setBusy(false);
      if (window.matchMedia("(max-width: 1023px)").matches) {
        workspace.current?.lastElementChild?.scrollIntoView({ block: "start" });
      }
    }
  }, []);

  useEffect(() => {
    function handleScanShortcut(event: KeyboardEvent) {
      if (event.key === "Enter" && (event.metaKey || event.ctrlKey) && !event.isComposing) {
        event.preventDefault();
        if (!event.repeat) void scan(code, language);
      }
    }
    document.addEventListener("keydown", handleScanShortcut);
    return () => document.removeEventListener("keydown", handleScanShortcut);
  }, [code, language, scan]);

  function showLocation(location: Location) {
    if (!stale) setReveal((previous) => ({ location, nonce: (previous?.nonce ?? 0) + 1 }));
  }

  return (
    <main className="scan-main">
      <section className="workspace-heading" aria-labelledby="workspace-title">
        <div>
          <p className="workspace-kicker">
            <span /> Local workspace
          </p>
          <h1 id="workspace-title">Scan workspace</h1>
          <p className="workspace-description">Test a snippet for supported SQL injection paths.</p>
        </div>
        <div className="scope-pills">
          <span className="experimental">
            <Icon name="unsafe" size={12} />
            Experimental coverage
          </span>
          <span>CWE-89</span>
        </div>
      </section>
      <div ref={workspace} className="workspace">
        <section className="panel source-panel" aria-labelledby="source-title">
          <div className="source-heading">
            <Icon name="code" size={20} />
            <h2 id="source-title">Source code</h2>
            <select
              className="file-type"
              aria-label="Language"
              disabled={busy}
              value={language}
              onChange={(event) => {
                setLanguage(event.target.value as Language);
                resetResults();
              }}
            >
              {languages.map((item) => (
                <option key={item} value={item}>
                  {languageNames[item]}
                </option>
              ))}
            </select>
          </div>
          <div className="editor-tools">
            <span className="label">Load an example</span>
            <fieldset aria-label="Source controls" className="segments">
              <button
                disabled={busy}
                aria-pressed={code === example.vulnerable}
                onClick={() => replace(example.vulnerable)}
              >
                <Icon name="unsafe" />
                Vulnerable
              </button>
              <button
                disabled={busy}
                aria-pressed={code === example.safe}
                onClick={() => replace(example.safe)}
              >
                <Icon name="safe" />
                Parameterized
              </button>
              <button disabled={busy} onClick={() => replace("")}>
                <Icon name="clear" />
                Clear
              </button>
            </fieldset>
          </div>
          <div className="file-row">
            <Icon name="file" size={14} />
            {snippetNames[language]}
            <button
              className="wrap"
              aria-label="Soft wrap"
              aria-pressed={wrap}
              onClick={() => setWrap(!wrap)}
            >
              <Icon name="wrap" size={14} />
              Wrap
            </button>
          </div>
          <div className="editor-host">
            <SourceEditor
              key={language}
              language={language}
              code={code}
              onChange={setCode}
              wrap={wrap}
              findings={stale ? undefined : result?.findings}
              selected={selected}
              reveal={stale ? null : reveal}
            />
          </div>
          <div className="source-actions">
            <label
              className={
                "capacity " + (size > MAX_SOURCE ? "over" : size >= MAX_SOURCE * 0.85 ? "near" : "")
              }
            >
              {size.toLocaleString("en-US")} B / 64 KiB{size > MAX_SOURCE ? " · Over limit" : ""}
              <progress
                value={Math.min(size, MAX_SOURCE)}
                max={MAX_SOURCE}
                aria-label="Source size"
              />
            </label>
            <button
              className={"scan-submit " + (busy ? "scanning" : "")}
              aria-label={busy ? "Scanning" : `Scan ${languageName}`}
              aria-keyshortcuts="Control+Enter Meta+Enter"
              disabled={busy || !code.trim() || size > MAX_SOURCE}
              onClick={() => void scan(code, language)}
            >
              <Icon name="play" size={14} />
              {busy ? "Scanning…" : `Scan ${languageName}`}
              <kbd aria-hidden="true">{shortcut}</kbd>
            </button>
          </div>
        </section>
        <ScanResults
          language={language}
          result={result}
          busy={busy}
          error={error}
          stale={stale}
          selected={selected}
          lines={result?.summary.files_analyzed ? scannedCode.split("\n").length : 0}
          onSelect={setSelected}
          onReveal={showLocation}
          onRetry={() => void scan(code, language)}
          onExample={() => {
            replace(example.vulnerable);
            void scan(example.vulnerable, language);
          }}
        />
      </div>
      <aside className="trust-strip">
        <Icon name="lock" size={19} />
        <div>
          <strong>Private by design</strong>
          <span>Your code is processed in memory by the local scanner. It is never executed.</span>
        </div>
      </aside>
    </main>
  );
}
