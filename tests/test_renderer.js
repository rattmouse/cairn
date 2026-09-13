/*
 * Tests for the markdown renderer and the block splitter in editor.html.
 *
 *     node tests/test_renderer.js
 *
 * The renderer is hand-written and was, until this file existed, the largest
 * unguarded thing in the repo. It is a pure function of (markdown, context) ->
 * html, so it needs no browser: this reads editor.html, cuts out the two
 * regions that make up the parser, and runs them with the handful of globals
 * they touch stubbed.
 *
 * Cutting rather than importing is deliberate. editor.html being one file you
 * can read top to bottom is a feature of cairn, and a renderer.js beside it
 * would be a second file to ship and a route to serve it with. The markers
 * below are the price: move them and this fails loudly, which is the right
 * failure.
 *
 * node is NOT a dependency of cairn — invariant 1 is still python, git and a
 * browser. The python suite runs this when node happens to be installed and
 * says so when it isn't, the same way it does for git.
 */

"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");

const EDITOR = path.join(__dirname, "..", "editor.html");

function cut(text, from, to, what){
  const a = text.indexOf(from);
  const b = text.indexOf(to);
  if (a < 0 || b < 0 || b <= a)
    throw new Error("cannot find the " + what + " in editor.html — the markers "
                  + JSON.stringify(from) + " / " + JSON.stringify(to) + " moved. "
                  + "Point them at the new ones rather than deleting the test.");
  return text.slice(a, b);
}

const html = fs.readFileSync(EDITOR, "utf8");
const source = [
  cut(html, "function esc(s){", "/* ============================== state ===", "renderer"),
  cut(html, "const LIST_RE =", "function grow(ta){", "block splitter")
].join("\n");

/* What the two regions reach for and this harness is not: a token for image
   URLs, the note-address helper, and the flag that decides whether a shell
   fence gets a terminal button. */
const sandbox = {
  TOKEN: "test-token",
  TERMINAL_OK: false,
  noteHref: p => "/n/" + p.split("/").map(encodeURIComponent).join("/"),
  console: console
};
vm.createContext(sandbox);
vm.runInContext(source, sandbox, {filename: "editor.html (extracted)"});

const {render, blocksOf, inline, splitFm} = sandbox;

/* The context a page builds for a render: the images it knows about, the
   notes a [[wikilink]] can land on, and the running task count. */
const ctx = (over) => Object.assign({
  images: {"photo.png": "attachments/photo.png"},
  targets: {"Alpha": "Notes/Alpha.md"},
  tasks: 0
}, over || {});

let passed = 0;
const failed = [];

function check(label, cond, detail){
  if (cond) passed++;
  else failed.push(label + (detail ? "  (" + detail + ")" : ""));
  console.log("  %s %s %s", label.padEnd(52), cond ? "ok" : "FAIL",
              cond ? "" : (detail || ""));
}

function html_of(md, over){
  return render(md, ctx(over), 0);
}

function eq(label, md, want, over){
  const got = html_of(md, over);
  check(label, got === want, got);
}

function has(label, md, want, over){
  const got = html_of(md, over);
  check(label, got.includes(want), got);
}

function blocks(md){
  const lines = md.split("\n");
  return blocksOf(md).map(b => ({
    kind: b.kind, num: b.num,
    text: lines.slice(b.a, b.b).join("\n")
  }));
}

// --------------------------------------------------------------------------
console.log("\ninline");

eq("a paragraph is a paragraph", "Just text.\n", "<p>Just text.</p>");
eq("bold", "**bold**\n", "<p><strong>bold</strong></p>");
eq("italic", "an *emphasis* here\n", "<p>an <em>emphasis</em> here</p>");
eq("strikethrough", "~~gone~~\n", "<p><del>gone</del></p>");
eq("a code span", "use `git log` here\n", "<p>use <code>git log</code> here</p>");
has("html in the source is escaped", "<script>alert(1)</script>\n",
    "&lt;script&gt;alert(1)&lt;/script&gt;");
has("a code span keeps its angle brackets as text", "`<b>`\n",
    "<code>&lt;b&gt;</code>");
has("a wikilink that resolves is a link", "See [[Alpha]].\n",
    'data-open="Notes/Alpha.md"');
has("a wikilink that does not is dead text", "See [[Nowhere]].\n",
    'class="wl dead"');
has("a piped wikilink shows its label", "See [[Alpha|the first one]].\n",
    ">the first one</a>");
has("an embed that resolves is an img", "![[photo.png]]\n",
    'src="/media/attachments/photo.png');
has("an embed that does not says so", "![[gone.png]]\n", "missing image");
has("a markdown link", "[docs](https://example.com/a)\n",
    '<a href="https://example.com/a" target="_blank"');
has("a bare url", "see https://example.com/a now\n",
    '<a href="https://example.com/a"');

// --------------------------------------------------------------------------
console.log("\nblocks");

eq("a heading carries its source line", "# Title\n",
   '<h1 id="L0">Title</h1>');
eq("a rule", "---\n", "<hr>");
has("a blockquote", "> quoted\n", "<blockquote><p>quoted</p></blockquote>");
has("a callout keeps its kind", "> [!NOTE] Heads up\n> body\n",
    '<div class="callout callout-note">');
has("a table", "| a | b |\n|---|---|\n| 1 | 2 |\n",
    "<thead><tr><th>a</th><th>b</th></tr></thead>");
has("frontmatter renders as frontmatter",
    "---\ntitle: X\n---\n\nbody\n", '<div class="fm">title: X</div>');

// --------------------------------------------------------------------------
console.log("\nfenced code");

has("a fence", "```\nplain\n```\n", "<pre><code>plain</code></pre>");
has("a fence with a language", "```python\nx = 1\n```\n",
    'class="language-python"');
has("a fence keeps a blank line inside it",
    "```sh\none\n\ntwo\n```\n", "one\n\ntwo");
/* Indented up to three spaces is still a fence, and the indent comes back
   off the code. A fence written under a list item is indented by definition. */
has("an indented fence is still code",
    "  ```sh\n  echo hi\n  ```\n", "<code class=\"language-sh\">echo hi</code>");
check("a fence's own backticks are not lost to the paragraph",
      !html_of("  ```sh\n  echo hi\n  ```\n").includes("```"),
      html_of("  ```sh\n  echo hi\n  ```\n"));

// --------------------------------------------------------------------------
console.log("\nlists");

eq("a bullet list", "- one\n- two\n",
   "<ul><li>one</li><li>two</li></ul>");
eq("an ordered list", "1. one\n2. two\n",
   "<ol><li>one</li><li>two</li></ol>");
has("a task box is a canvas the click can find",
    "- [ ] todo\n", 'data-task="0" data-on="0"');
has("a done task says so", "- [x] done\n", 'data-task="0" data-on="1"');
has("an indented continuation joins its item",
    "- item\n  more of it\n", "item<br>more of it");
has("a tab-indented continuation joins it too",
    "- item\n\tmore of it\n", "item<br>more of it");

/* Nesting. A list is the one construct here that nests, and until 0.6 the
   renderer flattened it: four items where the note had two and a sub-list. */
eq("a nested bullet list is nested", "- a\n  - b\n  - c\n- d\n",
   "<ul><li>a<ul><li>b</li><li>c</li></ul></li><li>d</li></ul>");
eq("a nested ordered list is nested", "1. a\n   1. x\n   2. y\n2. b\n",
   "<ol><li>a<ol><li>x</li><li>y</li></ol></li><li>b</li></ol>");
eq("a tab nests as well as two spaces", "- a\n\t- b\n",
   "<ul><li>a<ul><li>b</li></ul></li></ul>");
eq("an ordered list under a bullet", "- a\n  1. x\n  2. y\n",
   "<ul><li>a<ol><li>x</li><li>y</li></ol></li></ul>");
eq("three deep", "- a\n  - b\n    - c\n",
   "<ul><li>a<ul><li>b<ul><li>c</li></ul></li></ul></li></ul>");
eq("a continuation and a child, in the order they were written",
   "- a\n  more\n  - b\n", "<ul><li>a<br>more<ul><li>b</li></ul></li></ul>");

/* Numbering. Where a list starts is the author's to say. */
eq("a list resumed after a paragraph keeps its number", "4. four\n5. five\n",
   '<ol start="4"><li>four</li><li>five</li></ol>');
eq("a list that starts at one says nothing about it", "1. one\n",
   "<ol><li>one</li></ol>");
eq("a blank line between items does not end the list", "- a\n\n- b\n",
   "<ul><li>a</li><li>b</li></ul>");
eq("a paragraph after a list is not swallowed by it", "- a\n\nAfter.\n",
   "<ul><li>a</li></ul><p>After.</p>");
has("a nested task keeps its place in the count",
    "- [ ] one\n  - [x] two\n- [ ] three\n", 'data-task="2" data-on="0"');

// --------------------------------------------------------------------------
console.log("\nthe block splitter");

const three = blocks("1. one\n2. two\n3. three\n");
check("every top-level list item is its own block",
      three.length === 3 && three.every(b => b.kind === "li"),
      JSON.stringify(three));
check("an ordered item remembers the number it was written with",
      JSON.stringify(three.map(b => b.num)) === "[1,2,3]",
      JSON.stringify(three.map(b => b.num)));

/* One item to a block, nested or not — live mode is for editing a paragraph
   at a time — so what carries the nesting is the depth each block records. */
const deep = blocksOf("- parent\n  - child\n    - deeper\n- second\n");
check("a nested item is its own block at its own depth",
      deep.length === 4
        && JSON.stringify(deep.map(b => b.depth)) === "[0,1,2,0]",
      JSON.stringify(deep.map(b => b.depth)));
check("and the depth starts over after something that is not a list",
      JSON.stringify(blocksOf("- a\n  - b\n\npara\n\n- c\n")
        .filter(b => b.kind === "li").map(b => b.depth)) === "[0,1,0]",
      JSON.stringify(blocksOf("- a\n  - b\n\npara\n\n- c\n").map(b => b.kind)));

const loose = blocks("- a\n\n  still a\n\n- b\n");
check("a blank line inside an item does not end it",
      loose.length === 2 && loose[0].text.includes("still a"),
      JSON.stringify(loose));

const after = blocks("- a\n\nAfter.\n");
check("but a paragraph after the list is its own block",
      after.length === 2 && after[1].kind === "p",
      JSON.stringify(after));

const fenced = blocks("- item\n  ```sh\n  one\n\n  two\n  ```\n");
check("a fence under a list item stays in the item, blank line and all",
      fenced.length === 1 && fenced[0].text.endsWith("  ```"),
      JSON.stringify(fenced));

const tabbed = blocks("- item\n\tcontinued here\n");
check("a tab-indented continuation stays in its item",
      tabbed.length === 1 && tabbed[0].text.includes("continued"),
      JSON.stringify(tabbed));

const code = blocks("  ```sh\n  echo hi\n  ```\n");
check("an indented fence is one code block",
      code.length === 1 && code[0].kind === "code", JSON.stringify(code));

const fm = blocks("---\ntitle: X\n---\n\n# H\n");
check("frontmatter is one block whatever is in it",
      fm.length === 2 && fm[0].kind === "fm" && fm[1].kind === "h1",
      JSON.stringify(fm));

const kinds = blocks("# H\n\npara\n\n> quote\n\n| a |\n|---|\n| 1 |\n\n---\n")
  .map(b => b.kind);
check("each kind is recognised",
      JSON.stringify(kinds) === JSON.stringify(["h1", "p", "quote", "table", "hr"]),
      JSON.stringify(kinds));

const every = md => {
  const lines = md.split("\n");
  const seen = new Set();
  for (const b of blocksOf(md)) for (let i = b.a; i < b.b; i++) seen.add(i);
  return lines.every((l, i) => !l.trim() || seen.has(i));
};
check("no line with text in it falls outside every block",
      every("# H\n\n- a\n  - b\n\n```\nx\n```\n\n> q\n\n| a |\n|---|\n| 1 |\n\ntail\n"));

// --------------------------------------------------------------------------
console.log("\n%d passed, %d failed", passed, failed.length);
if (failed.length){
  console.log("\nfailed:");
  for (const f of failed) console.log("  " + f);
  process.exit(1);
}
