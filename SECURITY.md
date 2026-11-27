# Security and data handling

This is an experimental local scanner with an optional loopback HTTP service.
It parses source without executing it, running project scripts, fetching models,
installing scanned dependencies, or making network requests. The scanner reads
UTF-8 source in memory and writes reports only with an explicit output option.
Reports include local paths, locations, variable names and evidence metadata;
treat reports as potentially sensitive. There is no telemetry or scan database.

Discovery skips symlinks and opens final components with `O_NOFOLLOW`; it rejects
devices/FIFOs before reading. Parent-directory replacement races are not fully
isolated. Use stable local checkouts. Native parsers remain an untrusted-input
attack surface despite byte/time limits. The local HTTP service caps request and source bytes and simultaneous scans.
The web workspace and its scan proxy require a workspace key and use a signed,
expiring HTTP-only session cookie. This provides single-operator access for the
local web app. The underlying Python API is a separate loopback service intended
for direct local use. Keep it on a private interface.
Each snippet runs in a disposable Linux subprocess with a five-second wall deadline,
a CPU limit and a 256 MiB address-space limit. The worker inherits the server user’s
filesystem and network permissions. Public hosting still requires deployment
isolation, per-client abuse controls and independent security review. Archives and repository retrieval
must remain disabled until dedicated security controls exist.

For a suspected vulnerability, contact the repository owner privately through an
established channel before public disclosure. A dedicated reporting address must
be configured before publication. Do not post private source or credentials in
public issues. No deployed-service security claim is made.
