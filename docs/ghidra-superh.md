# SuperH ELF analysis through Ghidra

This lane extends native ELF analysis to 32-bit little-endian SuperH-4(a) (`EM_SH`); it does not execute SuperH code. Big-endian SuperH, SH-1/SH-2/SH-2A/SH-3, DSP, no-FPU, PE/COFF, and raw-binary variants are separate follow-ups.

## Admission boundary

ELF `EM_SH` (42) is retained as the provider-neutral `superh` family. The target also retains class, byte order, `e_type`, and raw `e_flags`. Recognition does not mean every provider or SuperH variant is supported.

The Ghidra lane admits ELF32 `ET_EXEC`, little endian, whose `e_flags` machine field (`EF_SH_MACH_MASK = 0x1f`) declares `EF_SH_UNKNOWN` (`0x0`), `EF_SH4` (`0x9`), `EF_SH4A` (`0xc`), or `EF_SH2A_SH4` (`0x17`), with no reserved bits outside `EF_SH_MACH_MASK`:

| Declaration                                                              | Outcome                                                                          |
| ------------------------------------------------------------------------ | -------------------------------------------------------------------------------- |
| Little-endian ELF32 `ET_EXEC`, `EF_SH_UNKNOWN`/`EF_SH4`/`EF_SH4A`/`0x17` | admitted, `SuperH4:LE:32:default` + `default`                                    |
| ELF64                                                                    | refused; 64-bit SuperH (SH-5) is unsupported                                     |
| Big-endian                                                               | refused; big-endian SuperH needs separate verification                           |
| `ET_REL`, `ET_DYN`, other `e_type`                                       | refused; relocatable objects and shared images need separate load verification   |
| `EF_SH1`, `EF_SH2`, `EF_SH2A`, `EF_SH3`, DSP, or no-FPU `e_flags`        | refused; non-SH-4, DSP, and no-FPU variants need separate processor verification |
| Bits outside `EF_SH_MACH_MASK` (`~0x1f`)                                 | refused with the offending bits named                                            |

## Bound language

Ghidra's `SuperH4.opinion` maps every `EM_SH` (42) ELF to `SuperH4` without inspecting `e_flags`. That auto-selection would import SH-1, SH-2, SH-2A, DSP, or no-FPU binaries into the FPU-enabled SH-4(a) processor model.

The lane therefore checks `e_flags` before admission, imports with `SuperH4:LE:32:default` and compiler spec `default`, commits that choice in the analysis profile as `language_selection: "provider-pinned-v1"`, and checks the language Ghidra reports after import. A different language set through `REA_GHIDRA_LANGUAGE_ID` (and optionally `REA_GHIDRA_COMPILER_SPEC_ID`) replaces the lane default and is admitted against the installed language catalog as usual.

SuperH header facts are committed in the analysis profile under `superh_elf` with `superh_support_lane: "elf32-le-exec-sh4-generic-v1"` so interpretation changes invalidate profile-bound snapshots. Evidence, lifecycle outputs, and saved snapshots preserve the `superh` family. Hopper, IDA, and Kuna adapters do not implicitly gain SuperH support. Windows Ghidra P0 remains PE x86/x86-64/ARM/ARM64 only.

## Use

With a caller-installed Ghidra and compatible JDK on a supported Linux/macOS host:

```bash
rea analyze /absolute/path/to/sh4.elf --provider ghidra --json
rea function /absolute/path/to/sh4.elf function_name --provider ghidra --json
```

MCP uses the existing tools, including `open_binary` with an absolute path and `provider_id: "ghidra"`.
