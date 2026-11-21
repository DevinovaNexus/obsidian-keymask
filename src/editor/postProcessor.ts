/**
 * KeyMask Markdown Post Processor (Reading View)
 *
 * Implements Obsidian's MarkdownPostProcessor API:
 * 1. registerMarkdownCodeBlockProcessor("keymask", ...) for fenced code blocks (and legacy "vaultguard").
 * 2. registerMarkdownPostProcessor(...) for inline %%km:v1:...%% / %%vg:v1:...%% comment tokens.
 *
 * Replaces tokens with interactive DOM pills identical to Live Preview.
 */

import { MarkdownPostProcessorContext } from "obsidian";
import type KeyMaskPlugin from "../main";
import {
  parseCodeBlock,
  parseInline,
  INLINE_SECRET_REGEX,
} from "../crypto/serializer";
import { createPillElement } from "./pillWidget";

/**
 * Register code block and inline post processors for Reading View
 */
export function registerPostProcessors(plugin: KeyMaskPlugin): void {
  // 1. Fenced Code Block Processor (```keymask and legacy ```vaultguard)
  const handleCodeBlock = (tag: string) => {
    return (source: string, el: HTMLElement, ctx: MarkdownPostProcessorContext) => {
      const rawText = `\`\`\`${tag}\n${source.trim()}\n\`\`\``;
      const payload = parseCodeBlock(rawText);

      const pillEl = createPillElement({
        plugin,
        payload,
        rawText,
        isCodeBlock: true,
        sourcePath: ctx.sourcePath,
      });

      el.empty();
      el.appendChild(pillEl);
    };
  };

  plugin.registerMarkdownCodeBlockProcessor("keymask", handleCodeBlock("keymask"));
  plugin.registerMarkdownCodeBlockProcessor("vaultguard", handleCodeBlock("vaultguard"));

  // 2. Inline Comment Secret Post Processor (%%km:v1:...%% and legacy %%vg:v1:...%%)
  plugin.registerMarkdownPostProcessor(
    (el: HTMLElement, ctx: MarkdownPostProcessorContext) => {
      const doc = el.ownerDocument;
      // Find all text nodes that might contain %%km:v1: or %%vg:v1:
      const walker = doc.createTreeWalker(el, NodeFilter.SHOW_TEXT);
      const nodesToReplace: { node: Text; text: string }[] = [];

      let currentNode = walker.nextNode();
      while (currentNode) {
        const textNode = currentNode as Text;
        if (
          textNode.nodeValue &&
          (textNode.nodeValue.includes("%%km:v1:") || textNode.nodeValue.includes("%%vg:v1:"))
        ) {
          nodesToReplace.push({ node: textNode, text: textNode.nodeValue });
        }
        currentNode = walker.nextNode();
      }

      for (const { node, text } of nodesToReplace) {
        INLINE_SECRET_REGEX.lastIndex = 0;
        let lastIndex = 0;
        let match: RegExpExecArray | null;
        const fragments: (Node | HTMLElement)[] = [];

        while ((match = INLINE_SECRET_REGEX.exec(text)) !== null) {
          // Text before match
          if (match.index > lastIndex) {
            fragments.push(doc.createTextNode(text.slice(lastIndex, match.index)));
          }

          const rawToken = match[0];
          const payload = parseInline(rawToken);
          const pill = createPillElement({
            plugin,
            payload,
            rawText: rawToken,
            isCodeBlock: false,
          });
          fragments.push(pill);

          lastIndex = INLINE_SECRET_REGEX.lastIndex;
        }

        // Remaining text after last match
        if (lastIndex < text.length) {
          fragments.push(doc.createTextNode(text.slice(lastIndex)));
        }

        if (fragments.length > 0 && node.parentNode) {
          for (const frag of fragments) {
            node.parentNode.insertBefore(frag, node);
          }
          node.parentNode.removeChild(node);
        }
      }
    }
  );
}
