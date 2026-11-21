import Link from "next/link";
export default function Methodology() {
  return <main className="methodology"><p className="eyebrow">COVERAGE & METHODS</p><h1>Know what was analyzed.</h1>
    <p className="lead">TraceWard traces selected SQL injection paths in Java and Python. Both rules are experimental and report partial coverage.</p>
    <section className="panel"><h2>Current capability</h2><table><thead><tr><th>Language</th><th>Check</th><th>Technique</th><th>Maturity</th></tr></thead>
      <tbody>
        <tr><td>Java</td><td>CWE-89</td><td>Servlet input to JDBC</td><td>Experimental</td></tr>
        <tr><td>Python</td><td>CWE-89</td><td>Console input to SQLite</td><td>Experimental</td></tr>
      </tbody></table>
      <h3>Java</h3><p>The scanner tracks explicitly typed servlet request parameters and headers through method-local assignments, concatenation, and simple if/else branches to supported JDBC calls. It reports source, transformation and sink locations.</p>
      <p>Conditions support boolean literals and explicitly typed boolean variables. Complex conditions, loops, fields, framework wrappers, and interprocedural flow are outside the supported scope.</p>
      <h3>Python</h3><p>The rule follows <code>input()</code> through local assignments and string concatenation with <code>+</code> to an SQLite query. Given a local connection from <code>sqlite3.connect()</code>, it checks <code>db.execute()</code> and <code>cursor.execute()</code> when the cursor is assigned directly with <code>cursor = db.cursor()</code>.</p>
      <p>Pass values separately with SQLite placeholders, as shown in the parameterized example. Review other database drivers, input sources, and paths that cross function boundaries separately.</p></section>
    <section className="panel"><h2>Machine learning and evaluation</h2>
      <p>Production ML inference is disabled pending corpus evaluation and model review. The offline research harness accepts documented datasets and creates reproducible split manifests and measured model reports.</p>
      <p>TraceWard is an independent solo project. Its research harness now has an exploratory baseline using CVE-linked MegaVul Java functions with repository-family splits. Upstream labels require further manual review. See the evaluation report in the repository for measured results and limitations. Historical benchmark figures in the proposal are unverified reference material.</p></section>
    <section className="panel"><h2>Source privacy</h2><p>Scanning begins only when you run a scan. Code is sent to the local API through the dashboard server, parsed in a disposable worker, and held in memory for the request. Report export saves a JSON file on your device.</p>
      <p>Use this local workspace for development. Public hosting requires deployment isolation and abuse controls.</p></section>
    <Link href="/" className="back-link">Return to scan workspace</Link>
  </main>;
}
