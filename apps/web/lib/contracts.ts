export type Location = {path: string; start_line: number; start_column: number; end_line: number; end_column: number};
export type Finding = {
  id: string; fingerprint: string; title: string; cwe: string[]; rule_id: string;
  severity: string; confidence: string; evidence_level: string; guidance: string; references: string[];
  location: Location;
  evidence: {flow: {kind: string; location: Location; symbol: string}[]; uncertainties: string[]};
};
export type ScanResult = {
  scan_id: string; schema_version: string; duration_ms: number;
  summary: {files_analyzed: number; files_discovered: number; findings: number; errors: number};
  findings: Finding[];
  coverage: {partial: boolean; supported_checks: string[]; limitations: string[]};
  diagnostics: {code: string; message: string; level: string; location: Location | null}[];
};
