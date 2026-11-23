# ProjectVI

Independent Windows compatibility research for GTA VI, starting with package inspection, PE import analysis and focused host-side experiments.

**Stage: research groundwork.** This public repository contains development tools and synthetic tests. It does not load or run GTA VI, render its frames, reach its menu or provide a playable PC build.

## What is implemented

| Component | Implemented behavior | Evidence |
| --- | --- | --- |
| Package inventory | Enumerates local files, reads container signatures and resolves executable paths declared in manifests | `src/Analysis.cs`, `src/PackageFiles.cs` |
| PE inspection | Reads normal and delayed imports, name and ordinal imports, exports and forwarders without executing inspected images | `src/PeFile.cs`, synthetic fixtures in `src/SelfTest.cs` |
| Windows import research | Resolves exact API-set v6 contracts, lists nearby-contract candidates and optionally searches installed SDK headers | `src/ApiSchema.cs`, `src/ImportTriage.cs`, `src/SdkLookup.cs` |
| D3D12 inspection | Probes device creation at feature levels 11_0 through 12_2 | `src/HostGraphics.cs` |
| Root-signature experiment | Round-trips a hand-authored description through desktop D3D12 and rejects an invalid version | `native/RootSignatureTest.cpp` |
| CPU page windows | Maps and aliases 64 KiB pages, supports scatter/remap/unmap, rolls back a failed replacement and releases views | `memory/CpuPageWindow.cpp`, `memory/CpuPageWindowTest.cpp` |

An export-name match is an investigation lead, not proof of ABI compatibility. Desktop tests do not establish console compatibility or a game milestone. The memory component is CPU-only; it does not implement console GPU memory semantics.

## Build and verify

Use Windows x64 and the .NET 10 SDK. Native tests additionally require Visual Studio with MSVC x64 and the Windows SDK. No game files are needed for these checks.

From the repository root in PowerShell:

```powershell
dotnet restore .\CompatPrep.csproj --configfile .\NuGet.Config
dotnet build .\CompatPrep.csproj -c Release --no-restore
dotnet .\bin\Release\net10.0\CompatPrep.dll selftest
powershell -NoProfile -ExecutionPolicy Bypass -File .\native\Build-Native.ps1
```

Expected success messages:

```text
SELFTEST_PASS
DESKTOP_ROOT_SIGNATURE_ROUNDTRIP_PASS
64 KiB CPU aliases: range, scatter, shared writes, remap, unmap, rollback and release passed.
```

The native script finds the installed compiler and SDK, builds into `native/build/`, and runs only this repository's synthetic tests. The managed project has no external NuGet dependencies; `NuGet.Config` disables package sources.

## Inspect a local package

```powershell
dotnet .\bin\Release\net10.0\CompatPrep.dll analyze 'D:\Research\MyPackage'
dotnet .\bin\Release\net10.0\CompatPrep.dll range 'D:\Research\MyPackage' 'sample.bin' 0 64
dotnet .\bin\Release\net10.0\CompatPrep.dll graphics
```

`analyze` writes `compatibility.json`, `import-triage.json`, `SUMMARY.md` and `IMPORT_TRIAGE.md` under the input package's `_pc_compat/reports/` directory. It inspects files as data and never launches them. `range` prints the SHA-256 of the requested range. `graphics` calls the system D3D12 API using the default Windows adapter.

Keep package inputs and generated reports local. This repository distributes source code and hand-authored fixtures only; no game archives, executables, extracted assets, keys or downloads are included.

## Progress and contributions

See [current status](docs/STATUS.md), [verification](docs/VERIFICATION.md), [roadmap](docs/ROADMAP.md) and [contribution guidelines](CONTRIBUTING.md). Changes are AI-assisted and must be supported by reviewable source and reproducible tests.

ProjectVI is an unofficial research project and is not affiliated with Rockstar Games, Take-Two or Microsoft. The project name does not imply endorsement. Source code is available under the [MIT License](LICENSE).
