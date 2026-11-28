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

## Overview

**Creative North Star: "Evidence notebook"**

TraceWard places source code beside an inspectable record of what the scanner
observed. The visual language is calm and technical: dark graphite surfaces,
clear type, compact controls, and distinct source, propagation, and sink marks.
The workspace gives evidence room without turning each datum into a separate card.

Components feel restrained and technical. Tonal layers with subtle ambient depth
separate the working areas; borders and typography carry most of the hierarchy.
The public landing and sign-in pages use the existing lighthouse image and larger
type. That imagery is a page-specific expression, not a background for the scanner.

**Key Characteristics:**

- One dark theme, a signal-mint action accent, and separate status colors.
- Geist for interface text; Geist Mono for the editor and explicit technical labels.
- Rounded rectangular controls, thin dividers, and closely grouped evidence.
- Text labels alongside status color, with visible focus and reduced-motion handling.

This is an extraction of the implementation at `7db1908`, checked at desktop
(1440 × 1000) and mobile (390 × 844). The frontmatter records observed values;
its spacing and radius names describe repeated dimensions, not new CSS variables.
No light theme, universal modular type scale, or global spacing API is implemented.
The field boundary, bracket highlight, font loading, and narrow control wrapping
include the subsequent accessibility audit corrections.

Source map:
[foundation and workspace](apps/web/app/globals.css),
[navigation and methodology](apps/web/app/navigation.css),
[landing and sign-in](apps/web/app/public.css),
[editor](apps/web/components/editor.css),
[syntax and evidence behavior](apps/web/components/SourceEditor.tsx), and
[results](apps/web/components/results.css).
Component composition lives in
[Workspace](apps/web/components/Workspace.tsx),
[ScanResults](apps/web/components/ScanResults.tsx),
[Header](apps/web/components/Header.tsx), and
[SignInForm](apps/web/app/login/SignInForm.tsx).

## Colors

The palette combines near-black graphite layers with cool off-white text.
Descriptive labels below lead; token keys and CSS names retain the implementation mapping.

### Primary

| Descriptive label  | Token                                            | Source and use                                                                                                       |
| ------------------ | ------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------- |
| Signal mint        | `primary`                                        | `--accent`: primary actions, links, focus, active navigation, available/finished states, and decorative trace marks. |
| Deep mint ink      | `on-primary-workspace`, `on-primary-entry`       | Distinct dark text colors for scan and entry actions. Keep their existing differences.                               |
| Pale mint feedback | `primary-hover-workspace`, `primary-hover-entry` | Separate hover fills for scan and entry actions.                                                                     |

### Neutral

| Descriptive label | Token / CSS property              | Use                                                                                            |
| ----------------- | --------------------------------- | ---------------------------------------------------------------------------------------------- |
| Graphite canvas   | `bg` / `--bg`                     | Page background and recessed groups.                                                           |
| Graphite panel    | `panel` / `--panel`               | Editor/results shells, methodology cards, and the key field.                                   |
| Graphite surface  | `surface` / `--surface`           | Findings, metric strip, result states, and secondary actions.                                  |
| Raised graphite   | `raised` / `--raised`             | Hover fills, pressed example selection, and meter track.                                       |
| Slate rule        | `line` / `--line`                 | Container boundaries and dividers.                                                             |
| Quiet slate rule  | `line-soft` / `--line-soft`       | Lower-emphasis internal divisions.                                                             |
| Frost text        | `text` / `--text`                 | Main headings and readable foreground.                                                         |
| Silver text       | `secondary` / `--secondary`       | Supporting content and standard button labels. This is a text role, not a second brand accent. |
| Muted slate text  | `muted` / `--muted`               | Captions, locations, inactive navigation, and helper text.                                     |
| Field outline     | `field-border` / `--field-border` | The sign-in field's resting border, with at least 3:1 contrast against its adjacent surfaces.  |

### Status and evidence

- **Caution amber** (`amber` / `--amber`): experimental coverage, incomplete/error
  explanations, source dots in the results trace, and the near-limit size meter.
- **High-risk coral** (`high` / `--high`): high severity, finding counts, sink dots,
  removed example lines, and over-limit size state.
- **Critical rose**, **low-severity periwinkle**, and **information blue**
  (`critical`, `low`, `info`): the existing critical/error and severity styles.
  Styled severity variants do not imply additional implemented detectors.
- The CSS aliases `--medium` to `--amber` and `--success` to `--accent`.
  A mint “Scan complete” status describes completion; it does not certify security.
- `--accent-dim` is declared in the foundation but currently has no consumers.
  It is not promoted into the extracted token set.

### Editor palette

The editor is a distinct code-reading surface. `editor-bg` documents the active
fallback of `var(--editor-bg, …)`; no root `--editor-bg` value is currently defined.
`editor-text`, `editor-active-line`, `editor-selection`, and `editor-reveal` describe
the editor foreground, active line, selection, and temporary reveal highlight.

`evidence-source` and `evidence-sink` record the editor's amber and rose underlines;
these are local variants of the results trace's status colors. Propagation uses a
dotted underline; endpoints use solid underlines and inset gutter marks.

| Syntax token         | Meaning                                       |
| -------------------- | --------------------------------------------- |
| `syntax-keyword`     | Keywords and modifiers, in soft violet.       |
| `syntax-type`        | Types, classes, and namespaces, in pale teal. |
| `syntax-function`    | Function names, in pale blue.                 |
| `syntax-string`      | String and character literals, in leaf green. |
| `syntax-literal`     | Numbers, booleans, and null, in warm peach.   |
| `syntax-comment`     | Comments, in muted blue-grey and italics.     |
| `syntax-punctuation` | Operators and punctuation, in cool slate.     |

**The Evidence Color Rule.** Pair color with a label, marker, underline, or explicit
state text. Preserve the distinction between severity, confidence, and completion.

The companion [.impeccable/design.json](.impeccable/design.json) adds swatch ramps
for preview only. Those ramps are generated in OKLCH; they are not shipped colors
and must not be treated as an existing application scale.

## Typography

**Display and body font:** Geist, with the fallback stack in the frontmatter.
**Technical font:** Geist Mono, then JetBrains Mono and platform monospace fallbacks.
Both Geist faces are locally bundled variable fonts with the declared weight range
(100–900) and `font-display: swap`; the CSS loads them from Next.js's installed font assets.
JetBrains Mono and Inter are fallbacks, not separately loaded webfonts.

The pairing uses tight, variable-weight sans-serif headings and quieter monospaced
metadata. It is an observed hierarchy, not a fixed-ratio type scale.

| Role                        | Where it appears                                                                                              |
| --------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `display`, `display-mobile` | Landing wordmark headline; the mobile override applies at the public stacking breakpoint.                     |
| `headline`                  | Scan workspace heading.                                                                                       |
| `headline-read`             | Coverage and methodology heading.                                                                             |
| `headline-entry`            | Sign-in heading.                                                                                              |
| `title`                     | Results panel heading; the source heading shares its size and tracking but retains its inherited bold weight. |
| `title-finding`             | Finding title and result-state headings.                                                                      |
| `body`                      | Global interface copy and the sign-in field's inherited size.                                                 |
| `body-detail`               | Result descriptions, diagnostics, and review context.                                                         |
| `label`                     | Result status and metric labels; file/trace labels use nearby line-height variants.                           |
| `label-kicker`              | Public uppercase kicker; workspace and methodology kickers use narrower tracking.                             |
| `code`                      | CodeMirror source text with generous line spacing.                                                            |
| `metric`                    | Finding count, scan duration, and source-line count.                                                          |

Methodology prose uses a local reading size (14px / 1.65). Landing descriptions cap
at (39ch); the evidence headline caps at (13ch). These are surface-specific limits,
not a universal reading width. Plain inline `code` without an explicit technical
font rule retains the browser's monospace styling.

**The Technical Label Rule.** Keep symbols, paths, metrics, and editor text distinct
from narrative copy. Do not turn ordinary prose or every heading into monospace.

## Layout

There is no framework grid or Tailwind theme. Layout uses CSS Grid and Flexbox,
fluid containers, local padding, and surface-specific breakpoints.

| Surface                            | Existing spatial pattern                                                                                                                      |
| ---------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| Shared header, footer, methodology | Centered width `min(calc(100% - clamp(32px, 7vw, 112px)), 1400px)`.                                                                           |
| Workspace                          | Width `min(calc(100% - 64px), 1400px)`; top/bottom margins (28px / 32px). Editor/results columns are `1.18fr / 1fr`, separated by `space-16`. |
| Workspace panels                   | Equal-height shells: `clamp(472px, 61vh, 750px)`. The editor and results scroll inside their shells.                                          |
| Public pages                       | Centered width `min(calc(100% - clamp(40px, 10vw, 160px)), 1320px)`. Landing and sign-in use `1.08fr / 1fr` columns.                          |
| Methodology                        | Reading and supporting columns at `1.5fr / 1fr`, with `space-20` between cards. Card padding is `clamp(20px, 2.2vw, 32px)`.                   |
| Results                            | Three equal metric columns, a scrollable report, and an export toolbar pinned by the panel's flex layout.                                     |

The frontmatter spacing steps capture recurrent values. Local control padding also
uses intermediate dimensions, including (7px), (14px), and (18px). Preserve those
observed values when matching an existing component; do not claim a strict 8px grid.
Typical report/card insets use `space-16`; panel headings combine `space-16` and
`space-20`; dense traces use `space-6` and `space-8`.

| Maximum viewport width | Observed change                                                                                                                                                           |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1023px                 | Workspace panels stack and become (520px) tall. The trust strip moves above them; page gutters reduce. Trace selection and scan completion scroll their target into view. |
| 920px                  | Landing image/copy column ratio changes to `0.65fr / 1fr`.                                                                                                                |
| 820px                  | Methodology columns stack.                                                                                                                                                |
| 760px                  | Landing and sign-in stack. The sign-in image becomes a short banner; landing copy moves below the visible lighthouse with a stronger dark overlay.                        |
| 640px                  | Header becomes two rows; account control stays above the navigation links. Navigation links have a minimum height (40px).                                                 |
| 620px                  | Workspace gutters become (12px) per side and example controls tighten.                                                                                                    |
| 480px                  | Report insets reduce to `space-12`; trace kinds move above symbol/location columns.                                                                                       |
| 390px                  | Public action gaps tighten and the illustrative landing trace becomes one column.                                                                                         |

These are maximum-width rules, not a shared named breakpoint API. The sidecar
records their values and source scopes without changing the code.

## Elevation & Depth

Tonal layers with subtle ambient depth describe the current implementation.
Graphite canvas, panel, surface, and raised fills establish hierarchy. Thin slate
borders do most of the separation; finding cards do not have drop shadows.

- **Workspace shell shadow** (`0 3px 12px #0002`): a low-opacity ambient shadow on
  the two main panels.
- **Trace marker isolation** (`0 0 0 2px var(--surface)`): separates a trace dot
  from its vertical connector; this is a ring, not an elevation level.
- **Editor endpoint marks**: inset gutter bars communicate evidence. They do not
  imply a raised editor surface.
- The sticky header uses an (88%) canvas mix and backdrop blur (18px). The
  methodology hero uses a faint mint radial wash. Public image overlays preserve
  readable text over the lighthouse scene.

**The Tonal Depth Rule.** Reuse tonal steps and existing dividers before introducing
another shadow. Keep the workspace shell shadow distinct from evidence markers.

## Shapes

The dominant form is the softly rounded rectangle. The frontmatter separates
control, segment, tag, finding, panel, and reading-card corners because the code
does; they are not interchangeable size aliases. `rounded.panel` maps to the
existing root `--radius`; the other dimensions are local CSS values.

Borders are generally (1px), with stronger focus outlines (2px). Circular status
dots and timeline markers use (50%) rounding. Shields and stroke icons identify
brand, action, and state; the source toolbar's icons are usually (14–16px), with
rounded caps and joins. The wordmark uses its existing custom shield geometry.

## Components

### Buttons

Restrained and technical: compact labels, clear boundaries, and direct state feedback.

- **Scan primary:** mint fill, deep ink label, `rounded.control`, and the
  `button-primary` padding. Its label uses weight (680); a small bordered keyboard
  shortcut hint sits beside it.
  The scan label stays on one line; its action row wraps when needed rather than
  squeezing the label or clipping the action.
- **Entry primary:** a related mint variant for public links and sign-in, with
  a minimum height (45px), larger horizontal gap (16px), and its own hover colors.
  The arrow shifts diagonally on hover (2px in each axis).
- **Secondary:** outlined graphite fill; the base label uses (13px / 550).
- **Ghost:** transparent export/copy controls with a (12px / 550) label and a
  (1.5) line-height. Hover uses raised graphite and a stronger border.
- **Pressed/disabled:** base buttons move down (1px) while enabled and pressed.
  Disabled buttons use opacity (0.5) and a not-allowed cursor.
- **Focus:** a mint outline (2px), offset (3px), applies to links, buttons,
  selects, summaries, and focusable regions. Inner scroll areas use an inward offset.

The sign-in account control is a separate outlined navigation action, not another
filled primary. Its minimum height is (36px), with `rounded.account` corners.

### Chips

Compact metadata, not invented filters. Coverage and file-type labels use neutral
fills, thin borders, and technical text. Experimental coverage is amber. Severity
tags use uppercase technical text (10px / 700), tracking (0.06em), a current-color
border mixed at (35%), and a fill mixed at (9%). Pair severity with CWE and
confidence text; only the severity tag carries the severity tint.

### Cards / Containers

Panels frame a working area; cards group a finding or a reading topic.

- **Workspace panels:** graphite panel fill, `rounded.panel`, a single border,
  clipped corners, and the ambient shell shadow.
- **Finding cards:** graphite surface fill, `rounded.finding`, and the
  `card-finding` inset. Selection blends high-risk coral into the border (38%).
  The heading is an expandable button with its state exposed through `aria-expanded`.
- **Methodology cards:** graphite panel fill, `rounded.reading-card`, and fluid
  reading padding. Tables scroll horizontally when needed; they are not compressed
  into illegible columns.
- **Trust strip:** a low-chroma green-tinted band with an icon, bold title, and
  explanatory text. It appears below desktop panels and above stacked mobile panels.

### Inputs / Fields

The workspace-key field is a bordered group containing a password input and a
Show/Hide button. It uses graphite panel fill, the field outline, `rounded.control`,
and `input-key` padding on the input itself. Input text is technical monospace.
Focus within the group changes the border to mint and adds a mint outline (2px),
offset (2px). The error is a critical-rose message with `role="alert"`, linked
through `aria-describedby` and `aria-invalid`; there is no separate red-border rule.

The language picker remains a native select styled as a compact file-type label.
Code entry is CodeMirror, not a textarea. Its focused outline sits inside the
editor (offset −2px). Focused matching brackets use frost text on the existing
green-grey highlight, overriding CodeMirror's default bracket treatment.
Soft wrap is a toggle; Tab indents, and Escape then Tab
allows keyboard exit. There is no existing checkbox, radio, or dialog component
family to document.

### Navigation

The shared header stays sticky with a wordmark, text navigation, and an account
action. Inactive links use muted slate; hover and the current page use frost text.
The current page also gets a mint underline (2px). On narrow screens the links
move below the wordmark/account row. The footer repeats the technical text
treatment and a quiet privacy statement.

### Example selector

The example selector is one recessed, bordered fieldset with `rounded.segment`.
Its compact buttons are transparent until selected; `aria-pressed="true"` uses
raised graphite with frost text and a signal mint border that makes the selected
state visible against adjacent graphite surfaces. Vulnerable, Parameterized, and Clear remain
explicit text actions. The group wraps when enlarged text spacing needs another
row, keeping every action reachable at narrow widths. The separate Wrap toggle
uses mint text while pressed.

### Evidence trace and result states

The signature pattern is an ordered source-to-sink trace. Each row contains a
kind label, technical symbol, and line location. Thin connectors join circular
markers; source and sink markers use their semantic colors. Rows are real buttons
that reveal and select source text, with raised graphite on hover. Stale results
disable location actions and display a text warning until the next scan.

The metrics strip precedes a scrollable report. Idle, pending, clean, error,
finding, and diagnostic states have different text and affordances: an example
action, skeletons, a limited-coverage explanation, a retry, expandable evidence,
or diagnostic locations. Native `details` groups hold Suggested fix, Review
context, and Coverage and limitations. Copy reports status through text; export
remains in the bottom toolbar.

**The Reviewable State Rule.** Retain “No SQL injection paths found,” diagnostics,
and partial-coverage explanations as separate states. A green icon alone is not
an analysis result.

### Motion

Local interactions use short transitions (160ms); entry actions and result cards
use (180ms). Workspace panels enter over (190ms) with a small vertical movement
(3px); findings use the same movement with a capped stagger (24ms per index,
maximum 96ms). The scan icon pulses over (220ms), and revealed source briefly
highlights for (220ms).

Public copy enters over (470ms). The lighthouse image may scale to (1.035) over
the first (680px) of scrolling where scroll timelines are supported. Those public
animations require `prefers-reduced-motion: no-preference`. The global reduced-motion
rule reduces durations to (0.01ms) and iterations to one; result cards disable
their animation and result tools remove the pressed transform. Do not describe
the implementation as disabling every transform or every animation outright.

## Do's and Don'ts

### Do

- **Do** reuse the graphite hierarchy and signal mint while keeping status roles separate.
- **Do** preserve visible text for severity, confidence, completion, errors, and partial coverage.
- **Do** reuse the current font stacks, variable weights, control corners, and focus treatment.
- **Do** keep source, trace, location, and remediation connected in the workspace.
- **Do** match the relevant surface's responsive rules and respect reduced-motion preferences.
- **Do** update this extraction and its sidecar when the underlying visual implementation changes.

### Don't

- **Don't** present a clean or completed scan as a security certification.
- **Don't** claim a light theme, strict spacing grid, or component state that the code does not implement.
- **Don't** treat preview swatch ramps as shipped application tokens.
- **Don't** replace the separate scan/entry action colors with one invented shared variant.
- **Don't** expand the landing page's lighthouse treatment into every application panel.
- **Don't** hide source-selection controls, focus indicators, or diagnostic explanations for visual simplicity.
