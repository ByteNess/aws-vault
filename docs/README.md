# AWS Vault documentation site

The source for <https://byteness.github.io/aws-vault/>, built with
[Hugo](https://gohugo.io/) and the [Hextra](https://github.com/imfing/hextra) theme.

## Prerequisites

- **Hugo extended**, v0.165.0 or newer — `brew install hugo`
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

Cross-page links are written as site-relative paths without the `.md` suffix
(`/docs/config#include_profile`). Hextra's `render-link` hook resolves those through the
target page's `RelPermalink`, so they pick up whatever `baseURL` the build was given — no
`{{% relref %}}` needed. This keeps the `markdown` output format (see `outputs` in
`hugo.yaml`) free of raw shortcodes, which relref did leak. The trade-off: a mistyped path
no longer fails the build, it just renders a dead link.

Plain relative links (`config.md`) do *not* work: the hook only rewrites destinations
starting with `/`, so they would be emitted verbatim and 404 against the pretty URLs.

GitHub-style alerts (`> [!NOTE]`, `> [!TIP]`, …) render as styled callouts natively — no
shortcode conversion needed, so the same Markdown renders on GitHub too.

## Layout width

Three independent knobs in `hugo.yaml`, each accepting `normal` (80rem), `wide` (90rem) or
`full` (100%). All three are set to `wide` so the header, content and footer edges line up:

```yaml
params:
  navbar:
    width: wide
  page:
    width: wide
  footer:
    width: wide
```

There is a fourth width the theme does **not** expose as a parameter: the content column is
capped by `--hextra-max-content-width`, hardcoded to `72rem` in Hextra's
`assets/css/variables.css`. The page width bounds the whole three-column shell (sidebar +
content + table of contents), so with the sidebar and ToC taking roughly `32rem`:

| `page.width` | Shell | Content column gets | Content cap reached? |
| --- | --- | --- | --- |
| `normal` | 80rem | ~48rem | no |
| `wide` | 90rem | ~58rem | no |
| `full` | 100% | viewport − 32rem | yes, past ~104rem viewport |

So `full` keeps widening the content only until it hits `72rem`; beyond that the surplus
becomes empty gutter, because `<article>` centres its `<main>`. To go wider than that, raise
the cap yourself in `assets/css/custom.css` (Hextra loads it automatically):

```css
:root {
  --hextra-max-content-width: 90rem;
}
```

Bear in mind long measure hurts readability — much past `72rem` and body text becomes hard to
track from line to line. Prefer widening only if pages are dominated by wide tables or code
blocks.

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
