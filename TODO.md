# TODO

## Clippy Lints

**Status:** These lints require extensive refactoring to enable as deny.

- [ ] `unwrap_used` — Replace all `.unwrap()` calls with proper error handling
- [ ] `cast_possible_truncation` — Audit all numeric casts for potential truncation
- [x] `cast_sign_loss` — Audit all signed-to-unsigned casts
- [x] `cognitive_complexity` — Refactor complex functions into smaller units

## Dependency Optimizations

| Current | Recommendation | Impact |
|---------|----------------|--------|
| `rand` | Consider `fastrand` if crypto RNG not needed | Faster compile |
| `libaes` | Consider `aes-gcm` for authenticated encryption | Security improvement |

## Wayland/WebKitGTK Workarounds

**Status:** No workarounds currently in code. If issues arise, consider:
- `WEBKIT_DISABLE_DMABUF_RENDERER=1` — Safer fallback for NVIDIA users

### References

- https://github.com/tauri-apps/tauri/issues/9394
- https://github.com/tauri-apps/tauri/issues/12361
- https://yaak.app/docs/getting-started/troubleshooting
