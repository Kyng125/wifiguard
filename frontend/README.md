# Built dashboard

`dist/` is the production build of the Figma-generated React app (Prompts 1 and 1b only: the Dashboard), built with
`VITE_USE_MOCK=false` so it talks to this backend. Flask serves it at `/`, so a laptop needs Python only, not Node.

It is a build output, not source. When more screens are added, rebuild in the frontend project and replace this folder:

```bash
VITE_USE_MOCK=false pnpm build        # or npm run build; output in dist/
rm -rf frontend/dist && cp -r <frontend project>/dist frontend/dist
```

To serve a build from elsewhere, set `WIFIGUARD_FRONTEND_DIST` to its folder.
