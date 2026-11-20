/**
 * KeyMask Editor Paste Interceptor Handler
 *
 * Hooks into:
 * 1. Document capture-phase 'paste' DOM event (intercepts before CodeMirror 6 / Obsidian)
 * 2. Obsidian workspace 'editor-paste' event as a secondary fallback
 *
 * Scans incoming clipboard payloads for API keys, tokens, and passwords.
 * Halts the paste event if sensitive patterns are detected and prompts the user.
 */

import { Editor, MarkdownView } from "obsidian";
import type KeyMaskPlugin from "../main";
import { detectSensitiveToken, DetectedToken } from "../utils/heuristics";
import { InterceptPasteModal } from "../modals/interceptPasteModal";

export function registerPasteHandler(plugin: KeyMaskPlugin): void {
  let isHandlingPaste = false;

  const processPaste = (
    rawText: string,
    evt: ClipboardEvent,
    editor: Editor
  ): boolean => {
    if (!plugin.settings.interceptPaste) {
      return false;
    }

    if (!rawText) return false;

    const detected = detectSensitiveToken(rawText);
    if (!detected) {
      return false;
    }

    // Sensitive token detected! Stop event dead in its tracks
    evt.preventDefault();
    evt.stopPropagation();
    if (evt.stopImmediatePropagation) {
      evt.stopImmediatePropagation();
    }

    // Debounce modal opening if both handlers fire
    if (isHandlingPaste) return true;
    isHandlingPaste = true;

    setTimeout(() => {
      new InterceptPasteModal(plugin.app, plugin, {
        editor,
        pastedText: rawText,
        detectedToken: detected,
      }).open();

      setTimeout(() => {
        isHandlingPaste = false;
      }, 500);
    }, 10);

    return true;
  };

  /**
   * Helper to retrieve text from ClipboardEvent or Electron clipboard
   */
  const getPastedText = (evt: ClipboardEvent): string => {
    let text = evt.clipboardData?.getData("text/plain") || "";
    if (!text) {
      try {
        const electron = (window as any).require?.("electron");
        text = electron?.clipboard?.readText() || "";
      } catch {}
    }
    return text;
  };

  // 1. Primary: Capture-phase DOM paste listener on window/document
  // Intercepts in the capture phase BEFORE CodeMirror 6 or Obsidian process the event!
  plugin.registerDomEvent(
    document,
    "paste",
    (evt: ClipboardEvent) => {
      const activeView = plugin.app.workspace.getActiveViewOfType(MarkdownView);
      if (!activeView || !activeView.editor) return;

      const pastedText = getPastedText(evt);
      if (!pastedText) return;

      processPaste(pastedText, evt, activeView.editor);
    },
    { capture: true }
  );

  // 2. Secondary: Obsidian workspace 'editor-paste' event fallback
  plugin.registerEvent(
    plugin.app.workspace.on(
      "editor-paste",
      (evt: ClipboardEvent, editor: Editor, view: MarkdownView) => {
        const pastedText = getPastedText(evt);
        if (!pastedText) return;

        processPaste(pastedText, evt, editor);
      }
    )
  );
}
