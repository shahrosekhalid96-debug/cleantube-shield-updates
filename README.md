# CleanTube Shield – update feed

Signed update feed for the CleanTube Shield Chrome extension. It holds **only** block lists and YouTube filter settings. There is no user data here.

- `src/` – inputs: list sources, allowlist, extra blocks, YouTube selectors, notice
- `tools/build.py` – downloads the lists, runs safety checks, builds and signs `dist/bundle.json.gz`
- `dist/latest.json` – version, hash and ECDSA P-256 signature of the bundle
- `.github/workflows/build.yml` – runs every Sunday and on every change to `src/`

The extension accepts a bundle only if:
1. the signature matches the public key built into the extension, and
2. the version is newer than the one it already has.

It never runs code from this feed. CSS selectors are checked for `url()`, `@import` and similar before they're used.

The signing key is stored only as the Actions secret `SHIELD_PRIVATE_KEY`.
