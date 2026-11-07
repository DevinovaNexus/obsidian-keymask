/**
 * VaultGuard CodeMirror 6 ViewPlugin
 *
 * Scans editor viewport for inline comment secrets (%%vg:v1:...%%)
 * and replaces them with interactive VaultGuardPillWidget decorations in Live Preview.
 *
 * Note: Fenced code blocks (```vaultguard ... ```) are processed exclusively by Obsidian's
 * native registerMarkdownCodeBlockProcessor to avoid multi-line CM6 inline replacement RangeErrors.
 *
 * High performance viewport-bounded scanning guarantees 60 FPS scrolling.
 */

import {
  EditorView,
  ViewPlugin,
  ViewUpdate,
  Decoration,
  DecorationSet,
  PluginValue,
} from "@codemirror/view";
import { RangeSetBuilder } from "@codemirror/state";
import type VaultGuardPlugin from "../main";
import {
  parseInline,
  INLINE_SECRET_REGEX,
} from "../crypto/serializer";
import { VaultGuardPillWidget } from "./pillWidget";

export function createVaultGuardViewPlugin(plugin: VaultGuardPlugin) {
  return ViewPlugin.fromClass(
    class implements PluginValue {
      decorations: DecorationSet;
      private plugin: VaultGuardPlugin;

      constructor(view: EditorView) {
        this.plugin = plugin;
        this.decorations = this.buildDecorations(view);
      }

      update(update: ViewUpdate) {
        if (update.docChanged || update.viewportChanged) {
          this.decorations = this.buildDecorations(update.view);
        }
      }

      private buildDecorations(view: EditorView): DecorationSet {
        const builder = new RangeSetBuilder<Decoration>();
        const doc = view.state.doc;

        // Iterate over visible viewport ranges to stay well within 60 FPS budget
        for (const { from, to } of view.visibleRanges) {
          // Add a line of buffer before and after visible range
          const startLine = doc.lineAt(from);
          const endLine = doc.lineAt(to);
          const scanFrom = startLine.from;
          const scanTo = endLine.to;
          const text = doc.sliceString(scanFrom, scanTo);

          // Scan Inline Secrets: %%vg:v1:...%%
          INLINE_SECRET_REGEX.lastIndex = 0;
          let match: RegExpExecArray | null;
          while ((match = INLINE_SECRET_REGEX.exec(text)) !== null) {
            const matchFrom = scanFrom + match.index;
            const matchTo = matchFrom + match[0].length;
            const rawText = match[0];
            const payload = parseInline(rawText);

            builder.add(
              matchFrom,
              matchTo,
              Decoration.replace({
                widget: new VaultGuardPillWidget({
                  plugin: this.plugin,
                  payload,
                  rawText,
                  isCodeBlock: false,
                }),
              })
            );
          }
        }

        return builder.finish();
      }

      destroy() {}
    },
    {
      decorations: (v) => v.decorations,
    }
  );
}
