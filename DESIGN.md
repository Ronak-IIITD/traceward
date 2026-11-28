---
name: TraceWard
description: Evidence-first code security, expressed through a restrained technical workspace.
colors:
  primary: "#69e6ba"
  bg: "#0d1013"
  panel: "#15191e"
  surface: "#1b2026"
  raised: "#242a31"
  line: "#333a42"
  line-soft: "#292f36"
  text: "#f1f4f6"
  secondary: "#ccd2d8"
  muted: "#a2adb7"
  amber: "#f4ca80"
  critical: "#ff889d"
  high: "#ff9d8b"
  low: "#a8c6ff"
  info: "#8dcfe9"
  on-primary-workspace: "#092a21"
  on-primary-entry: "#09251c"
  primary-hover-workspace: "#99f2d2"
  primary-hover-entry: "#a1f4d8"
  field-border: "#66717c"
  editor-bg: "#0e1519"
  editor-text: "#dae5ed"
  editor-active-line: "#1b282d"
  editor-selection: "#315d69"
  editor-reveal: "#436a62"
  evidence-source: "#efbb68"
  evidence-sink: "#ff898b"
  syntax-keyword: "#c9abf6"
  syntax-type: "#87d7d5"
  syntax-function: "#a4c9fb"
  syntax-string: "#b2d99d"
  syntax-literal: "#f1bd88"
  syntax-comment: "#93a8b6"
  syntax-punctuation: "#a4b5c3"
typography:
  display:
    fontFamily: "Geist, Inter, system-ui, sans-serif"
    fontSize: "clamp(66px, 8.2vw, 122px)"
    fontWeight: 615
    lineHeight: 0.94
    letterSpacing: "-0.086em"
  display-mobile:
    fontFamily: "Geist, Inter, system-ui, sans-serif"
    fontSize: "clamp(57px, 13vw, 95px)"
    fontWeight: 615
    lineHeight: 0.94
    letterSpacing: "-0.086em"
  headline:
    fontFamily: "Geist, Inter, system-ui, sans-serif"
    fontSize: "clamp(31px, 3vw, 44px)"
    fontWeight: 620
    lineHeight: 1.08
    letterSpacing: "-0.06em"
  headline-read:
    fontFamily: "Geist, Inter, system-ui, sans-serif"
    fontSize: "clamp(32px, 3.3vw, 52px)"
    fontWeight: 620
    lineHeight: 1.08
    letterSpacing: "-0.047em"
  headline-entry:
    fontFamily: "Geist, Inter, system-ui, sans-serif"
    fontSize: "clamp(45px, 5vw, 72px)"
    fontWeight: 610
    lineHeight: 1
    letterSpacing: "-0.075em"
  title:
    fontFamily: "Geist, Inter, system-ui, sans-serif"
    fontSize: "16px"
    fontWeight: 620
    lineHeight: 1.55
    letterSpacing: "-0.025em"
  title-finding:
    fontFamily: "Geist, Inter, system-ui, sans-serif"
    fontSize: "18px"
    fontWeight: 700
    lineHeight: 1.3
    letterSpacing: "-0.035em"
  body:
    fontFamily: "Geist, Inter, system-ui, sans-serif"
    fontSize: "15px"
    fontWeight: 400
    lineHeight: 1.55
  body-detail:
    fontFamily: "Geist, Inter, system-ui, sans-serif"
    fontSize: "13px"
    fontWeight: 400
    lineHeight: 1.6
  label:
    fontFamily: '"Geist Mono", "JetBrains Mono", ui-monospace, monospace'
    fontSize: "11px"
    fontWeight: 400
    lineHeight: 1.4
  label-kicker:
    fontFamily: '"Geist Mono", "JetBrains Mono", ui-monospace, monospace'
    fontSize: "11px"
    fontWeight: 600
    lineHeight: 1.5
    letterSpacing: "0.16em"
  code:
    fontFamily: '"Geist Mono", "JetBrains Mono", ui-monospace, monospace'
    fontSize: "13px"
    fontWeight: 400
    lineHeight: 1.8
  metric:
    fontFamily: '"Geist Mono", "JetBrains Mono", ui-monospace, monospace'
    fontSize: "18px"
    fontWeight: 500
    lineHeight: 1.25
rounded:
  trace: "4px"
  tag: "5px"
  account: "6px"
  control: "7px"
  segment: "8px"
  finding: "9px"
  panel: "10px"
  reading-card: "12px"
spacing:
  space-2: "2px"
  space-4: "4px"
  space-6: "6px"
  space-8: "8px"
  space-12: "12px"
  space-16: "16px"
  space-20: "20px"
  space-24: "24px"
  space-32: "32px"
components:
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.on-primary-workspace}"
    rounded: "{rounded.control}"
    padding: "9px 12px"
  button-primary-hover:
    backgroundColor: "{colors.primary-hover-workspace}"
    textColor: "#052217"
  button-entry:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.on-primary-entry}"
    rounded: "{rounded.control}"
    padding: "0 15px"
  button-entry-hover:
    backgroundColor: "{colors.primary-hover-entry}"
    textColor: "#072017"
  button-secondary:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.secondary}"
    rounded: "{rounded.control}"
    padding: "7px 12px"
  button-secondary-hover:
    backgroundColor: "{colors.raised}"
    textColor: "{colors.text}"
  button-ghost:
    backgroundColor: "transparent"
    textColor: "{colors.text}"
    rounded: "{rounded.control}"
    padding: "7px 12px"
  input-key:
    backgroundColor: "{colors.panel}"
    textColor: "{colors.text}"
    rounded: "{rounded.control}"
    padding: "11px 12px"
  navigation:
    textColor: "{colors.muted}"
    padding: "0 2px"
  chip-high:
    textColor: "{colors.high}"
    rounded: "{rounded.tag}"
    padding: "2px 7px"
  card-finding:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.text}"
    rounded: "{rounded.finding}"
    padding: "{spacing.space-16}"
  trace-row:
    backgroundColor: "transparent"
    textColor: "{colors.secondary}"
    rounded: "{rounded.trace}"
    padding: "{spacing.space-6}"
  segmented-control:
    backgroundColor: "{colors.bg}"
    rounded: "{rounded.segment}"
    padding: "{spacing.space-2}"
---

# Design System: TraceWard

<!-- impeccable:design-map -->

Name: TraceWard
Colors: primary: primary #69e6ba; neutral: bg #0d1013; semantic: amber #f4ca80; syntax: syntax-keyword #c9abf6; primary: primary-hover-workspace #99f2d2; primary: primary-hover-entry #a1f4d8 (+28 more in the sidecar)
Fonts: Geist (display, display-mobile, headline, headline-read, headline-entry, title, title-finding, body, body-detail); Geist Mono (label, label-kicker, code, metric)
Spacing: space-2 2px, space-4 4px, space-6 6px, space-8 8px, space-12 12px, space-16 16px, space-20 20px, space-24 24px, space-32 32px
Radius: trace 4px, tag 5px, account 6px, control 7px, segment 8px, finding 9px, panel 10px, reading-card 12px
North Star: "Evidence notebook"
Rules:

- The Evidence Color Rule. Pair color with a label, marker, underline, or explicit state text. Preserve the distinction between severity, confidence, and completion.
- The Technical Label Rule. Keep symbols, paths, metrics, and editor text distinct from narrative copy. Do not turn ordinary prose or every heading into monospace.
- The Tonal Depth Rule. Reuse tonal steps and existing dividers before introducing another shadow. Keep the workspace shell shadow distinct from evidence markers.
- The Reviewable State Rule. Retain “No SQL injection paths found,” diagnostics, and partial-coverage explanations as separate states. A green icon alone is not an analysis result.

Elevation:

- Workspace shell shadow: 0 3px 12px #0002
- Trace marker isolation: 0 0 0 2px var(--surface)
- Editor endpoint marks: inset gutter bars communicate evidence.

Don't:

- Don't present a clean or completed scan as a security certification.
- Don't claim a light theme, strict spacing grid, or component state that the code does not implement.
- Don't treat preview swatch ramps as shipped application tokens.
- Don't replace the separate scan/entry action colors with one invented shared variant.
- Don't expand the landing page's lighthouse treatment into every application panel.
- Don't hide source-selection controls, focus indicators, or diagnostic explanations for visual simplicity.

Do:

- Do reuse the graphite hierarchy and signal mint while keeping status roles separate.
- Do preserve visible text for severity, confidence, completion, errors, and partial coverage.
- Do reuse the current font stacks, variable weights, control corners, and focus treatment.
- (+3 more)

Map: apps/web/app/globals.css
Map: apps/web/app/navigation.css
Map: apps/web/app/public.css
Map: apps/web/components/editor.css
Map: apps/web/components/editor-theme.ts
Map: apps/web/components/SourceEditor.tsx
Map: apps/web/components/results.css
Map: apps/web/components/Workspace.tsx

Full: .impeccable/design-full.md (read a section when you need its detail)
