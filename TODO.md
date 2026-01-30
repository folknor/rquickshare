# TODO

## Clippy Lints

**Status:** These lints require extensive refactoring to enable as deny.

- [x] `unwrap_used` — Replace all `.unwrap()` calls with proper error handling
- [x] `cast_possible_truncation` — Audit all numeric casts for potential truncation
- [x] `cast_sign_loss` — Audit all signed-to-unsigned casts
- [x] `cast_possible_wrap` — Audit all usize/u64 to i64 casts
- [x] `cognitive_complexity` — Refactor complex functions into smaller units
- [x] `too_many_lines` — Keep functions under 100 lines

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
