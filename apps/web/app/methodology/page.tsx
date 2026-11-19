import Link from "next/link";
export default function Methodology() {
  return <main className="methodology"><p className="eyebrow">COVERAGE & METHODS</p><h1>Know what was analyzed.</h1>
    <p className="lead">TraceWard currently provides an experimental Java SQL injection rule. Review each result alongside the supported scope and diagnostics.</p>
    <section className="panel"><h2>Current capability</h2><table><thead><tr><th>Language</th><th>Check</th><th>Technique</th><th>Maturity</th></tr></thead>
      <tbody><tr><td>Java</td><td>CWE-89</td><td>Tree-sitter + local flow</td><td>Experimental</td></tr></tbody></table>
      <p>The scanner tracks explicitly typed servlet request parameters and headers through straight-line assignments and concatenation to supported JDBC calls. It reports source, transformation and sink locations.</p>
      <p>Branches, loops, nested scopes, fields, framework wrappers and interprocedural flow have limited coverage. Findings use medium confidence and heuristic evidence. Every scan reports partial coverage.</p></section>
    <section className="panel"><h2>Machine learning and evaluation</h2>
      <p>Production ML inference is disabled pending corpus evaluation and model review. The offline research harness accepts documented datasets and creates reproducible split manifests and measured model reports.</p>
      <p>TraceWard is an independent solo project. Its research harness now has an exploratory baseline using CVE-linked MegaVul Java functions with repository-family splits. Upstream labels require further manual review. See the evaluation report in the repository for measured results and limitations. Historical benchmark figures in the proposal are unverified reference material.</p></section>
    <section className="panel"><h2>Source privacy</h2><p>Scanning begins only when you select Scan Java. Code is sent to the local API through the dashboard server, parsed in a disposable worker, and held in memory for the request. Report export saves a JSON file on your device.</p>
      <p>Use this local workspace for development. Public hosting requires deployment isolation and abuse controls.</p></section>
    <Link href="/" className="back-link">Return to scan workspace</Link>
  </main>;
}
