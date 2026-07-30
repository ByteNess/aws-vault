# AWS Vault documentation site

The source for <https://byteness.github.io/aws-vault/>, built with
[Hugo](https://gohugo.io/) and the [Hextra](https://github.com/imfing/hextra) theme.

## Prerequisites

- **Hugo extended**, v0.146.0 or newer — `brew install hugo`
- **Go** — Hextra is installed as a Hugo Module, which uses the Go toolchain to fetch it

## Preview locally

```shell
cd docs
hugo server
```

Then open <http://localhost:1313/>. Or from the repository root: `make docs-serve`.

## Build

```shell
cd docs
hugo --gc --minify
```

Output lands in `docs/public/` (git-ignored). Or from the repository root: `make docs-build`.

`baseURL` is intentionally left as `/` in `hugo.yaml`. CI supplies the real value from
`actions/configure-pages`, so the site builds correctly for whichever repository or fork
publishes it. To reproduce a subpath build locally:

```shell
hugo --baseURL "https://<user>.github.io/aws-vault/"
```

## Layout

```
content/
├── _index.md            # home page (hero + feature grid)
├── getting-started.md   # single page: installing, quick start, how it works, roles and MFA, auto-logout
└── docs/                # one page per usage topic
```

Sidebar order is set by `weight` in each page's front matter. Pages with an image are
[page bundles](https://gohugo.io/content-management/page-bundles/) (`<name>/index.md` with
the image alongside), so the image resolves correctly under any `baseURL`.

Cross-page links use `{{% relref %}}` rather than hand-written paths, because a broken
reference then fails the build instead of shipping a dead link.

GitHub-style alerts (`> [!NOTE]`, `> [!TIP]`, …) render as styled callouts natively — no
shortcode conversion needed, so the same Markdown renders on GitHub too.

## Footer, copyright and attribution

Footer strings live in [`i18n/en.yaml`](./i18n/en.yaml). The copyright line mirrors the
repository `LICENSE` (MIT, `Copyright (c) 2015 ByteNess`) — it is not an independent claim.
Overriding it there is necessary: Hextra's built-in default is the placeholder
`© 2026 Hextra Project.`, which would misstate ownership of these docs.

Neither Hextra (MIT) nor Hugo (Apache-2.0) requires a visible attribution in a generated
site. Both licences attach their notice requirements to redistributing *their own source*,
and Hextra is consumed here as a Hugo Module that never enters this repository, so there is
nothing to reproduce. The "Powered by Hextra" credit is a courtesy to the theme author, not
an obligation.

To change what the footer shows, in `hugo.yaml`:

| Goal | Setting |
| --- | --- |
| Drop the theme credit | `params.footer.displayPoweredBy: false` |
| Drop the copyright line | `params.footer.displayCopyright: false` |
| Drop the whole bottom block | set **both** to `false` — the block renders if either is true |

## Updating the theme

```shell
cd docs
hugo mod get -u github.com/imfing/hextra
hugo mod tidy
```

## Deployment

`.github/workflows/pages.yaml` builds and deploys to GitHub Pages on every push to `main`
that touches `docs/**`, and can be run manually via *workflow_dispatch*. Publishing requires
**Settings → Pages → Source = "GitHub Actions"**.
