# Contributing

Follow README setup and run all verification commands before proposing changes.
Keep core code independent of API and web layers. Every detector change needs
meaningful vulnerable and safe fixtures, precise location checks and explicit
unsupported cases. Never promote a detector based only on synthetic fixtures.

Do not execute scanned code or introduce background source uploads. Report partial
analysis and missing capabilities explicitly. Preserve research attribution and
record provenance and distribution rights before adding datasets or models.
Do not bundle secrets or model pickle files from untrusted sources.

Future work follows the PRD milestone order. Update `docs/status.md` and regenerate
the JSON Schema when the result contract changes. A project license and private
security contact remain owner decisions before external publication.
