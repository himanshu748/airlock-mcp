# Airlock operator interface

Next.js App Router, static export. The build output is committed to
`airlock/ui/`, so the backend serves the interface at `/ui/` from the same
process and running Airlock never requires Node.

## Build

This project must not be built inside an iCloud-synced directory, where npm
stalls. Build from a local path:

```bash
cp -R frontend /tmp/airlock-frontend && cd /tmp/airlock-frontend
npm install
npm run build
```

Then copy `out/` over `airlock/ui/` in the repository and commit the result.

## Notes

- `basePath` is `/ui` and `trailingSlash` is on, so the export produces
  `index.html` and `record/index.html`, which `StaticFiles(html=True)` serves
  directly.
- Fonts are self-hosted by `next/font`. The built pages make no external
  requests, so the interface works with no network.
- Every value on these pages comes from the server under audit. React escapes
  it. There is no `dangerouslySetInnerHTML` in this project and a test enforces
  that.
