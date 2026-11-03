/**
 * VaultGuard Editor Paste Interceptor Handler
 *
 * Hooks into Obsidian's workspace 'editor-paste' event to scan incoming clipboard
 * payloads for API keys, tokens, and credentials.
 * Halts the paste event if sensitive patterns are detected and prompts the user.
 */

import { Editor, MarkdownView } from "obsidian";
import type VaultGuardPlugin from "../main";
import { detectSensitiveToken } from "../utils/heuristics";
import { InterceptPasteModal } from "../modals/interceptPasteModal";

export function registerPasteHandler(plugin: VaultGuardPlugin): void {
  plugin.registerEvent(
    plugin.app.workspace.on(
      "editor-paste",
      (evt: ClipboardEvent, editor: Editor, view: MarkdownView) => {
        // If paste interception is disabled in settings, allow standard paste
        if (!plugin.settings.interceptPaste) {
          return;
        }

        const clipboardData = evt.clipboardData;
        if (!clipboardData) return;

        const pastedText = clipboardData.getData("text/plain");
        if (!pastedText) return;

        // Perform fast heuristic scan (< 15ms budget)
        const detected = detectSensitiveToken(pastedText);
        if (!detected) {
          return;
        }

        // Sensitive token detected! Halt default paste event
        evt.preventDefault();
        evt.stopPropagation();

        // Open Intercept Modal
        new InterceptPasteModal(plugin.app, plugin, {
          editor,
          pastedText,
          detectedToken: detected,
        }).open();
      }
    )
  );
}
