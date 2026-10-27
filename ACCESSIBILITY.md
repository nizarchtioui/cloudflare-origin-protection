# Accessibility

This project should be usable by everyone, including people who use screen
readers, magnification, high-contrast settings or only a keyboard. That
covers the skill, its scripts and this documentation.

## What the project does today

- **Words, not colours.** The scripts state every result in words: LOCKED,
  REACHABLE, EXPOSED, UNTESTED, and warnings that start with `WARNING` or
  `[warn]`. They use no colour codes, so nothing depends on seeing colour.
- **Plain ASCII output.** Both scripts print plain ASCII text, which works in
  any terminal and screen reader.
- **Machine-readable results.** `check_origin_lockdown.py --json` and the
  generator's `cidr` and `json` formats let you feed results into your own
  tools. Exit codes carry the verdict, so automation never has to parse text.
- **Text, not images of text.** Example output in the README is real text in
  code blocks.
- **Described diagrams.** The two diagrams in [docs/why-now.md](docs/why-now.md)
  have a text title and description that screen readers announce, and the
  text around each diagram explains the same idea.
- **Structured docs.** Headings, lists and tables in Markdown work with
  GitHub's and your reader's navigation.

## Supported environments

- **Scripts:** any terminal with Python 3.6 or newer. They are tested on Linux
  in CI and were also run on Windows during development.
- **Documentation:** GitHub's web interface, or any Markdown viewer or text
  editor.

## Known limitations

- **Wide tables.** Some README and reference tables are wide. With
  magnification or on a small screen, scroll them sideways, or read the raw
  Markdown, which is plain text.
- **Space-aligned output.** The checker's human-readable output aligns its
  columns with spaces, so a screen reader reads it line by line. If that is
  awkward, use `--json`.
- **Diagram rendering.** Diagrams render with JavaScript on GitHub. Without
  it, you see the diagram source, and the surrounding text still carries the
  meaning.
- **No formal audit.** There has been no formal accessibility audit, so this
  project makes no conformance claim (for example to WCAG).

## Report a barrier

Open an issue with the **Bug report** form and choose **Accessibility** under
"Which part is affected?". Describe what you tried, what got in the way, and
the assistive technology you use if you are comfortable sharing it. Barriers
are treated as bugs.
