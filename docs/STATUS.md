# Status

Publication scope: standalone inspection tools and host-side experiments. This is an initial public source snapshot, not a complete compatibility runtime.

| Milestone | Status in this repository |
| --- | --- |
| Package and manifest inspection | Implemented |
| PE imports, exports and delayed imports | Implemented |
| Windows API-set lookup and import candidate reports | Implemented |
| Synthetic desktop D3D12 root-signature round-trip | Implemented and locally tested |
| Synthetic CPU page aliases and rollback | Implemented and locally tested |
| Game executable loading | Not implemented |
| First game frame | Not demonstrated |
| Main menu | Not demonstrated |
| In-game rendering | Not demonstrated |
| Game FPS and stability | Not measured |

## Limitations

- Package inventory does not extract or decrypt containers.
- Import candidates do not prove matching signatures, structures or behavior.
- Dynamic imports and forwarder chains need separate investigation.
- SDK text matches are documentation leads, not callable implementations.
- CPU aliases do not demonstrate GPU-visible mappings or console page semantics.
- Desktop D3D12 serialization does not implement console graphics APIs.

## Tracker review

The published evidence supports review as early research or tooling. Placement in a race, watchlist or toolkit is an editorial decision by the tracker. No completion percentage or game milestone is claimed.
