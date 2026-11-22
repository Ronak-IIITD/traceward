"use client";

import { useEffect, useRef } from "react";
import {
  defaultKeymap,
  history,
  historyKeymap,
  indentWithTab,
  temporarilySetTabFocusMode,
} from "@codemirror/commands";
import { java } from "@codemirror/lang-java";
import { javascript } from "@codemirror/lang-javascript";
import { python } from "@codemirror/lang-python";
import { bracketMatching, HighlightStyle, indentUnit, syntaxHighlighting } from "@codemirror/language";
import {
  Compartment,
  EditorState,
  RangeSet,
  StateEffect,
  StateField,
  type Text,
} from "@codemirror/state";
import {
  Decoration,
  EditorView,
  GutterMarker,
  gutterLineClass,
  highlightActiveLine,
  highlightActiveLineGutter,
  keymap,
  lineNumbers,
  type DecorationSet,
} from "@codemirror/view";
import { tags } from "@lezer/highlight";
import type { Finding, Location } from "@/lib/contracts";
import { languageNames, type Language } from "@/lib/examples";
import "./editor.css";

const languageExtensions = {
  java,
  python,
  javascript,
  typescript: () => javascript({ typescript: true }),
};

type Props = {
  code: string;
  language: Language;
  onChange: (code: string) => void;
  wrap: boolean;
  findings?: Finding[];
  selected: number;
  reveal: { location: Location; nonce: number } | null;
};

const syntax = HighlightStyle.define([
  { tag: [tags.keyword, tags.modifier], color: "#c9abf6" },
  { tag: [tags.typeName, tags.className, tags.namespace], color: "#87d7d5" },
  { tag: [tags.function(tags.variableName), tags.function(tags.propertyName)], color: "#a4c9fb" },
  { tag: [tags.string, tags.character], color: "#b2d99d" },
  { tag: [tags.number, tags.bool, tags.null], color: "#f1bd88" },
  { tag: tags.comment, color: "#93a8b6", fontStyle: "italic" },
  { tag: [tags.operator, tags.punctuation], color: "#a4b5c3" },
]);

const wrapping = new Compartment();
const encoder = new TextEncoder();
// ignoreBOM preserves a literal U+FEFF when counting UTF-16 selection offsets.
const decoder = new TextDecoder("utf-8", { ignoreBOM: true });

function offset(doc: Text, lineNo: number, byteColumn: number) {
  const line = doc.line(lineNo);
  // The scanner counts UTF-8 bytes from 1; CodeMirror counts UTF-16 units from 0.
  return line.from + decoder.decode(encoder.encode(line.text).subarray(0, byteColumn - 1)).length;
}

function span(doc: Text, loc: Location) {
  if (loc.start_line < 1 || loc.end_line > doc.lines || loc.end_line < loc.start_line) return null;
  return {
    from: offset(doc, loc.start_line, loc.start_column),
    to: offset(doc, loc.end_line, loc.end_column),
  };
}

class EvidenceMarker extends GutterMarker {
  constructor(readonly elementClass: string) {
    super();
  }
  eq(other: GutterMarker) {
    return this.elementClass === other.elementClass;
  }
}
const sourceMarker = new EvidenceMarker("cm-source-marker");
const sinkMarker = new EvidenceMarker("cm-sink-marker");
type Evidence = { marks: DecorationSet; gutter: RangeSet<GutterMarker> };
const empty: Evidence = { marks: Decoration.none, gutter: RangeSet.empty };
const annotate = StateEffect.define<Evidence>();
const evidence = StateField.define<Evidence>({
  create: () => empty,
  update(value, transaction) {
    for (const effect of transaction.effects) if (effect.is(annotate)) return effect.value;
    return transaction.docChanged ? empty : value;
  },
  provide: (field) => [
    EditorView.decorations.from(field, (value) => value.marks),
    gutterLineClass.from(field, (value) => value.gutter),
  ],
});

function annotations(doc: Text, findings: Finding[] | undefined, selected: number): Evidence {
  if (!findings?.length) return empty;
  const marks = [];
  const gutter = new Map<number, GutterMarker>();
  for (const [index, finding] of findings.entries()) {
    for (const step of finding.evidence.flow) {
      if (index !== selected && step.kind !== "source" && step.kind !== "sink") continue;
      const range = span(doc, step.location);
      if (!range || range.to <= range.from) continue;
      const endpoint = step.kind === "source" || step.kind === "sink";
      marks.push(
        Decoration.mark({ class: endpoint ? "cm-evidence-" + step.kind : "cm-evidence-flow" }).range(
          range.from,
          range.to,
        ),
      );
      if (endpoint) {
        const start = doc.lineAt(range.from).from;
        // Prefer the sink marker if both endpoints occur on the same line.
        if (!gutter.has(start) || step.kind === "sink")
          gutter.set(start, step.kind === "sink" ? sinkMarker : sourceMarker);
      }
    }
  }
  return {
    marks: Decoration.set(marks, true),
    gutter: RangeSet.of(
      Array.from(gutter, ([pos, marker]) => marker.range(pos)),
      true,
    ),
  };
}

const flash = StateEffect.define<DecorationSet>();
const flashField = StateField.define<DecorationSet>({
  create: () => Decoration.none,
  update(value, transaction) {
    for (const effect of transaction.effects) if (effect.is(flash)) return effect.value;
    return transaction.docChanged ? Decoration.none : value;
  },
  provide: (field) => EditorView.decorations.from(field),
});

export default function SourceEditor({ code, language, onChange, wrap, findings, selected, reveal }: Props) {
  const host = useRef<HTMLDivElement>(null);
  const editor = useRef<EditorView | null>(null);
  const initialDocument = useRef({ code, language });
  const onEdit = useRef(onChange);

  useEffect(() => {
    onEdit.current = onChange;
  }, [onChange]);
  useEffect(() => {
    if (!host.current) return;
    const initial = initialDocument.current;
    const view = new EditorView({
      parent: host.current,
      state: EditorState.create({
        doc: initial.code,
        extensions: [
          lineNumbers(),
          highlightActiveLineGutter(),
          highlightActiveLine(),
          languageExtensions[initial.language](),
          bracketMatching(),
          syntaxHighlighting(syntax),
          history(),
          indentUnit.of("    "),
          EditorState.tabSize.of(4),
          keymap.of([
            { key: "Escape", run: temporarilySetTabFocusMode },
            indentWithTab,
            ...historyKeymap,
            ...defaultKeymap.filter((binding) => binding.key !== "Mod-Enter"),
          ]),
          EditorView.contentAttributes.of({
            "aria-label": `${languageNames[initial.language]} source code`,
            "aria-description": "Tab indents. Press Escape then Tab to leave the editor.",
            "aria-multiline": "true",
            spellcheck: "false",
          }),
          wrapping.of([]),
          evidence,
          flashField,
          EditorView.updateListener.of((update) => {
            if (update.docChanged) onEdit.current(update.state.doc.toString());
          }),
        ],
      }),
    });
    editor.current = view;
    return () => {
      view.destroy();
      editor.current = null;
    };
  }, []);
  useEffect(() => {
    const view = editor.current;
    if (view && view.state.doc.toString() !== code) {
      view.dispatch({
        changes: { from: 0, to: view.state.doc.length, insert: code },
        selection: { anchor: 0 },
      });
    }
  }, [code]);
  useEffect(() => {
    editor.current?.dispatch({ effects: wrapping.reconfigure(wrap ? EditorView.lineWrapping : []) });
  }, [wrap]);
  useEffect(() => {
    const view = editor.current;
    if (view) view.dispatch({ effects: annotate.of(annotations(view.state.doc, findings, selected)) });
  }, [findings, selected]);
  useEffect(() => {
    const view = editor.current;
    if (!view || !reveal) return;
    const range = span(view.state.doc, reveal.location);
    if (!range) return;
    const marks =
      range.to > range.from
        ? Decoration.set([Decoration.mark({ class: "cm-revealed" }).range(range.from, range.to)])
        : Decoration.none;
    view.dispatch({
      selection: { anchor: range.from, head: range.to },
      effects: [flash.of(marks), EditorView.scrollIntoView(range.from, { y: "center" })],
    });
    view.focus();
    if (window.matchMedia("(max-width: 1023px)").matches)
      host.current?.scrollIntoView({ block: "center" });
    const timer = window.setTimeout(() => view.dispatch({ effects: flash.of(Decoration.none) }), 220);
    return () => {
      window.clearTimeout(timer);
      if (editor.current === view) view.dispatch({ effects: flash.of(Decoration.none) });
    };
  }, [reveal]);

  return <div className="source-editor" ref={host} />;
}
