// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Copyright (c) 2026 2351485 ALBERTA INC.

/** A tiny renderer for the markdown subset HELP.md / FAQ.md use:
 * `#`/`##`/`###` headings, paragraphs, `-` bullets, and **bold**.
 * Everything is built with createElement + textContent — never
 * innerHTML — so help text can never inject markup. That is a
 * security property, not a style choice: this text renders inside
 * a password manager. */

function appendInline(parent: HTMLElement, text: string): void {
  const parts = text.split(/\*\*(.+?)\*\*/g);
  parts.forEach((part, i) => {
    if (i % 2 === 1) {
      const strong = document.createElement("strong");
      strong.textContent = part;
      parent.append(strong);
    } else if (part) {
      parent.append(document.createTextNode(part));
    }
  });
}

export function renderMarkdown(source: string): HTMLElement {
  const root = document.createElement("div");
  root.className = "help-doc";
  const noComments = source.replace(/<!--[\s\S]*?-->/g, "");
  const lines = noComments.split("\n");

  let paragraph: string[] = [];
  let list: HTMLUListElement | null = null;

  const flushParagraph = (): void => {
    if (paragraph.length === 0) return;
    const p = document.createElement("p");
    appendInline(p, paragraph.join(" "));
    root.append(p);
    paragraph = [];
  };
  const flushList = (): void => {
    list = null;
  };

  for (const raw of lines) {
    const line = raw.trim();
    if (line.startsWith("### ")) {
      flushParagraph(); flushList();
      const h = document.createElement("h5");
      appendInline(h, line.slice(4));
      root.append(h);
    } else if (line.startsWith("## ")) {
      flushParagraph(); flushList();
      const h = document.createElement("h4");
      appendInline(h, line.slice(3));
      root.append(h);
    } else if (line.startsWith("# ")) {
      flushParagraph(); flushList();
      const h = document.createElement("h3");
      appendInline(h, line.slice(2));
      root.append(h);
    } else if (line.startsWith("- ")) {
      flushParagraph();
      if (!list) {
        list = document.createElement("ul");
        root.append(list);
      }
      const li = document.createElement("li");
      appendInline(li, line.slice(2));
      list.append(li);
    } else if (line === "") {
      flushParagraph(); flushList();
    } else {
      flushList();
      paragraph.push(line);
    }
  }
  flushParagraph();
  return root;
}
