# TODO

## Wayland/WebKitGTK Workarounds

**Status:** No workarounds currently in code. If issues arise, consider:
- `WEBKIT_DISABLE_DMABUF_RENDERER=1` — Safer fallback for NVIDIA users

### References

- https://github.com/tauri-apps/tauri/issues/9394
- https://github.com/tauri-apps/tauri/issues/12361
- https://yaak.app/docs/getting-started/troubleshooting

## Dependency Updates

### Completed

- [x] Tauri ecosystem updated to 2.9.x
- [x] Rust dependencies updated (patch + minor via `ccu -um`)
- [x] `vue` 3.5.27
- [x] `vite` 7.3.1
- [x] `vitest` 4.0.18
- [x] `pinia` 3.0.4
- [x] `vue-tsc` 3.2.4
- [x] `typescript` 5.9.3
- [x] `eslint` 9.39.2 + related plugins
- [x] `unplugin-auto-import` 21.0.0
- [x] `cross-env` 10.1.0
- [x] `postcss` 8.5.6 + related plugins
- [x] `pnpm` 10.28.2

### Remaining

- [ ] `tailwindcss` 3.4.19 → 4.x — Major rewrite, requires CSS-first config migration
  - Current config in `tailwind.config.cjs` needs to be migrated to CSS `@config` directive
  - See: https://tailwindcss.com/docs/upgrade-guide
