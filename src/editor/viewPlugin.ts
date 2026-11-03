/**
 * VaultGuard CodeMirror 6 ViewPlugin
 *
 * Scans editor viewport for:
 * 1. Inline comment secrets (%%vg:v1:...%%)
 * 2. Fenced code block secrets (```vaultguard ... ```)
 *
 * Generates CodeMirror 6 replacement decorations using VaultGuardPillWidget.
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
  parseCodeBlock,
  INLINE_SECRET_REGEX,
  CODE_BLOCK_SECRET_REGEX,
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

          interface MatchItem {
            from: number;
            to: number;
            widget: VaultGuardPillWidget;
          }
          const matches: MatchItem[] = [];

          // 1. Scan Inline Secrets: %%vg:v1:...%%
          INLINE_SECRET_REGEX.lastIndex = 0;
          let match: RegExpExecArray | null;
          while ((match = INLINE_SECRET_REGEX.exec(text)) !== null) {
            const matchFrom = scanFrom + match.index;
            const matchTo = matchFrom + match[0].length;
            const rawText = match[0];
            const payload = parseInline(rawText);

            matches.push({
              from: matchFrom,
              to: matchTo,
              widget: new VaultGuardPillWidget({
                plugin: this.plugin,
                payload,
                rawText,
                isCodeBlock: false,
              }),
            });
          }

          // 2. Scan Fenced Code Blocks: ```vaultguard ... ```
          CODE_BLOCK_SECRET_REGEX.lastIndex = 0;
          while ((match = CODE_BLOCK_SECRET_REGEX.exec(text)) !== null) {
            const matchFrom = scanFrom + match.index;
            const matchTo = matchFrom + match[0].length;
            const rawText = match[0];
            const payload = parseCodeBlock(rawText);

            matches.push({
              from: matchFrom,
              to: matchTo,
              widget: new VaultGuardPillWidget({
                plugin: this.plugin,
                payload,
                rawText,
                isCodeBlock: true,
              }),
            });
          }

          // Sort matches by 'from' position for RangeSetBuilder requirement
          matches.sort((a, b) => a.from - b.from);

          for (const item of matches) {
            builder.add(
              item.from,
              item.to,
              Decoration.replace({
                widget: item.widget,
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
