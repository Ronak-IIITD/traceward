# TraceWard frontend audit

Target: `apps/web/app` and its shared components, against [DESIGN.md](../DESIGN.md).
Baseline: `e18ec3c`. Scope: landing, sign-in, workspace, and methodology.

## Implementation integrity verdict

**Pass after fixes.** The interface retains the Evidence notebook identity:
graphite surfaces, mint actions, Geist typography, and inspectable source-to-sink
evidence. Four verified implementation issues were corrected without replacing
the design, copy, navigation, or scanner behavior.

## Audit health score

Scores describe this scoped Chromium review, not a WCAG certification or a
performance benchmark.

| Dimension                |    Before |     After | Evidence                                                                                                                                            |
| ------------------------ | --------: | --------: | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| Accessibility            |       2/4 |       3/4 | Field boundary and focused bracket contrast corrected; keyboard navigation and native selection remain functional.                                  |
| Performance              |       3/4 |       3/4 | No performance defect established by source inspection; existing compact WebP and locally bundled fonts retained. No load-time benchmark performed. |
| Theming                  |       3/4 |       3/4 | Documented palette preserved; the field outline now has a shared token. Local values remain intentional parts of the extracted system.              |
| Responsive design        |       2/4 |       3/4 | Narrow controls remain reachable with increased text spacing; 63 rendered samples show no page overflow or clipped toolbar controls.                |
| Implementation integrity |       3/4 |       4/4 | Geist Mono now loads on public routes, and focused brackets use the intended editor treatment.                                                      |
| **Total**                | **13/20** | **16/20** | **Good after fixes**                                                                                                                                |

## Executive summary

Four actionable findings: **0 P0, 3 P1, 1 P2, 0 P3**. All four are fixed and
covered by browser regressions. No confirmed issue remains open within the
checked scope. Generic detector notices are assessed separately below.

## Findings and fixes

### [P1] Example controls clipped after text-spacing overrides

- **Location:** [workspace styles](../apps/web/app/globals.css), example selector
  and source action row.
- **Category:** Responsive design / Accessibility.
- **Impact:** At 320 CSS pixels, increasing letter/word/line/paragraph spacing
  pushed Clear past the clipped panel boundary. The scan action also compressed
  its label into multiple lines.
- **Standard:** Users must retain content and functionality when overriding
  spacing. [WCAG 1.4.12](https://www.w3.org/WAI/WCAG22/Understanding/text-spacing.html).
- **Fix:** Allow the example group and action row to wrap; keep the scan label
  together. All four language selectors retain reachable source actions.
- **Suggested command:** `$impeccable adapt` — completed in this change.

### [P1] Sign-in field boundary below the non-text contrast minimum

- **Location:** [sign-in styles](../apps/web/app/public.css), workspace-key group;
  [foundation](../apps/web/app/globals.css), field-border token.
- **Category:** Accessibility / Theming.
- **Impact:** The empty key field relied on a boundary measuring approximately
  2.75:1 against its inner surface and 2.98:1 against the page. Both fell below
  the 3:1 threshold for a necessary control boundary.
  [WCAG 1.4.11](https://www.w3.org/WAI/WCAG22/Understanding/non-text-contrast.html).
- **Fix:** Use `--field-border` with the corrected slate value. The inner-surface
  contrast is now approximately 3.55:1; both adjacent surfaces pass the threshold.
  DESIGN.md and the affected field preview record the correction.
- **Suggested command:** `$impeccable colorize` — completed in this change.

### [P1] CodeMirror's default focused bracket style overrode the theme

- **Location:** [editor styles](../apps/web/components/editor.css), focused
  matching-bracket selector.
- **Category:** Accessibility / Implementation integrity.
- **Impact:** The library's focused selector won over the local rule. The rendered
  bracket contrast measured approximately 3.15:1, below the normal-text minimum.
  Native selected text already passed and was not the defect.
  [WCAG contrast guidance](https://www.w3.org/WAI/WCAG22/Understanding/contrast-minimum.html).
- **Fix:** Scope the existing bracket treatment to the focused editor with
  sufficient specificity and use frost text. The regression checks rendered
  foreground/background contrast against 4.5:1 after actual source navigation.
- **Suggested command:** `$impeccable harden` — completed in this change.

### [P2] Public technical typography used a fallback face

- **Location:** [global font declarations](../apps/web/app/globals.css) and
  [editor stylesheet](../apps/web/components/editor.css).
- **Category:** Theming / Implementation integrity.
- **Impact:** The sign-in page requested Geist Mono, but its font-face declaration
  existed only in the editor stylesheet. A fresh public route loaded Geist alone,
  contrary to the intended technical font treatment.
- **Fix:** Move the existing Mono declaration into global styles. Public technical
  text now loads the same bundled face as the workspace. No new font dependency
  or external font request was added.
- **Suggested command:** `$impeccable typeset` — completed in this change.

## Patterns and detector triage

- The fixes address containment under user text settings, CSS specificity at the
  editor-library boundary, and route-level font availability.
- The bundled detector ran against source and rendered public routes before and
  after the fixes. It still emits generic notices about Geist/Geist Mono, tracked
  kickers, small technical captions, and occasional single-word line endings.
  Those notices do not establish the contrast or reflow failures above.
- The two font warnings conflict with the explicitly approved faces in DESIGN.md.
  Kicker/caption notices refer to documented incumbent patterns; they are retained
  rather than treated as authorization to redesign the interface. No detector
  suppression or quality gate was changed.
- A control below 44px is not automatically a WCAG AA target-size failure. Small
  native/isolated controls were assessed with the applicable spacing and inline
  exceptions. [WCAG target-size guidance](https://www.w3.org/WAI/WCAG22/Understanding/target-size-minimum.html).
- The single dark theme, local editor colors, and reduced-motion handling are
  documented behavior. Reduced motion preserves the Scanning text and result
  status, so the global timing reduction does not erase that state feedback.

## Validation and limits

- `bun run test --fully-parallel --workers 2 --shuffle 281128 --retries 0`:
  **26 passed**, including nine audit regressions. The relevant tests failed on
  the baseline for route font loading, clipped controls, and focused brackets.
- Configured web format, lint, type checks and the production build passed.
- Four page routes were sampled at widths 320, 360, 390, 620, 640, 641, 760, 768,
  820, 920, 1023, 1024, 1280 and 1440px. Additional finding/text-spacing states
  brought the total to 63 rendered samples; none showed page overflow or clipped
  toolbar controls after the fixes.
- Public screenshots were captured with Impeccable shot at mobile, tablet and
  desktop sizes. Workspace and sign-in states were inspected with Playwright.
  The affected ten-component design sidecar also passed source/token/reference
  checks and desktop/mobile preview validation.
- Touch evidence uses synthesized Chromium taps with `hasTouch: true` for each
  language's Clear control. This was not a physical-device test. Safari, Firefox,
  screen readers, touch drag-selection and real-device gestures remain untested.
- RTL failures were not inferred from physical CSS properties: these pages use
  English and do not declare an RTL direction.

## Positive findings

Source locations remain keyboard-accessible and selectable. Focus indicators,
editor Escape/Tab exit, safe/error result distinctions, diagnostics, and explicit
partial-coverage explanations remain present. Existing auth, export, remediation,
and CLI/API-backed browser flows continue to pass.

## Recommended actions

1. `$impeccable audit`: repeat the narrow-width and spacing checks after future UI changes.
2. `$impeccable polish`: an optional final visual pass on additional engines and physical devices.
