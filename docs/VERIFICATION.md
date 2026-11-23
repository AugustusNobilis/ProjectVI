# Verification

The initial publication snapshot was built and tested locally on Windows x64 on November 24, 2026 (Europe/Moscow). The managed build used .NET SDK 10.0.401. No game files were needed or launched for these checks.

| Check | Observed result |
| --- | --- |
| Managed Release build | Passed, zero warnings and zero errors |
| Synthetic PE imports, exports, delayed imports and forwarders | Passed |
| Range hashing, bounds checking and path traversal rejection | Passed |
| Malformed PE rejection and manifest entry-point discovery | Passed |
| Desktop D3D12 root-signature serialization/deserialization | Passed |
| Invalid root-signature version rejection | Passed |
| CPU page range/scatter mapping and shared writes | Passed |
| Remap, unmap, failed-update rollback and invalid-input rejection | Passed |
| Memory view release | Passed |

The linker emits LNK4001 for the forwarder-only DLL because it intentionally contains no object code. The subsequent serialization test passes.

Commands and expected markers are in the [README](../README.md). GitHub Actions repeats the source check and synthetic tests on a Windows runner; consult the actual workflow result for CI status. The optional `graphics` device probe is not a CI gate because adapter support varies.

These results cover the source in this repository. They are not evidence that GTA VI loads, renders or runs. No third-party reproduction is claimed.
