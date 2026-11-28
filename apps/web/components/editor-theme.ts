import { HighlightStyle } from "@codemirror/language";
import { tags } from "@lezer/highlight";

export const syntaxTheme = HighlightStyle.define([
  { tag: [tags.keyword, tags.modifier], color: "#c9abf6" },
  { tag: [tags.typeName, tags.className, tags.namespace], color: "#87d7d5" },
  { tag: [tags.function(tags.variableName), tags.function(tags.propertyName)], color: "#a4c9fb" },
  { tag: [tags.string, tags.character], color: "#b2d99d" },
  { tag: [tags.number, tags.bool, tags.null], color: "#f1bd88" },
  { tag: tags.comment, color: "#93a8b6", fontStyle: "italic" },
  { tag: [tags.operator, tags.punctuation], color: "#a4b5c3" },
]);
