import type { GhidraLanguageOverride } from "../config/ghidraLanguageOverride.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import type { JsonValue } from "../domain/jsonValue.js";

const EF_SH_MACH_MASK = 0x1f;
const EF_SH_UNKNOWN = 0x0;
const EF_SH4 = 0x9;
const EF_SH4A = 0xc;
const EF_SH2A_SH4 = 0x17;

/**
 * Generic 32-bit little-endian SuperH-4(a). Ghidra's ELF opinion maps every
 * EM_SH (42) image to SuperH4 without inspecting `e_flags`, so the lane bounds
 * admission to SH-4-compatible headers and commits the language explicitly.
 */
export const GHIDRA_SUPERH_LANGUAGE: GhidraLanguageOverride = {
  languageId: "SuperH4:LE:32:default",
  compilerSpecId: "default",
};

const isAdmittedSh4MachineFlag = (mach: number): boolean =>
  mach === EF_SH_UNKNOWN ||
  mach === EF_SH4 ||
  mach === EF_SH4A ||
  mach === EF_SH2A_SH4;

/** Keep family recognition separate from the deliberately bounded Ghidra lane. */
export const ghidraSuperHUnsupportedReason = (
  target: BinaryTarget,
): string | null => {
  if (target.kind !== "executable" || target.architecture !== "superh")
    return null;
  const metadata = target.superh;
  if (target.format !== "elf" || metadata === undefined)
    return "SuperH analysis requires ELF header metadata; a family name alone does not select a processor variant.";
  if (metadata.elfClass !== 32)
    return "This Ghidra SuperH lane supports ELF32 only; 64-bit SuperH (SH-5) remains unsupported.";
  if (metadata.byteOrder !== "little")
    return "This Ghidra SuperH lane supports little-endian ELF32 only; big-endian SuperH needs separate verification.";
  if (metadata.type !== 2)
    return "This Ghidra SuperH lane supports ET_EXEC only; relocatable objects and shared images need separate load verification.";
  const unsupportedFlags = (metadata.flags & ~EF_SH_MACH_MASK) >>> 0;
  if (unsupportedFlags !== 0)
    return `SuperH e_flags declares bits outside EF_SH_MACH_MASK (0x${unsupportedFlags.toString(16)}); reserved or unverified flags are not treated as compatible with this profile.`;
  const mach = metadata.flags & EF_SH_MACH_MASK;
  if (!isAdmittedSh4MachineFlag(mach))
    return `This Ghidra SuperH lane requires an SH-4/SH-4A ELF machine declaration (EF_SH_UNKNOWN, EF_SH4, EF_SH4A, or EF_SH2A_SH4; observed 0x${mach.toString(16)}); SH-1/SH-2/SH-3, DSP, and no-FPU variants need separate processor verification.`;
  return null;
};

/**
 * The language the lane imports with, unless REA_GHIDRA_LANGUAGE_ID already
 * selected one through the committed profile.
 */
export const ghidraSuperHLanguage = (
  target: BinaryTarget,
): GhidraLanguageOverride | undefined =>
  target.kind === "executable" &&
  target.architecture === "superh" &&
  ghidraSuperHUnsupportedReason(target) === null
    ? GHIDRA_SUPERH_LANGUAGE
    : undefined;

/** Commit source ELF interpretation without confusing target ISA with host CPU. */
export const ghidraSuperHProfileParameters = (
  target: BinaryTarget,
): Readonly<Record<string, JsonValue>> => {
  if (
    target.kind !== "executable" ||
    target.architecture !== "superh" ||
    target.superh === undefined
  )
    return {};
  return {
    superh_elf: {
      elf_class: target.superh.elfClass,
      byte_order: target.superh.byteOrder,
      type: target.superh.type,
      flags: target.superh.flags,
    },
    superh_support_lane: "elf32-le-exec-sh4-generic-v1",
  };
};

/** The pinned language is an analysis convention, not proof of the producer. */
export const ghidraSuperHLimitations = (
  target: BinaryTarget,
): readonly string[] =>
  target.kind === "executable" && target.architecture === "superh"
    ? [
        "SuperH ELF: REA pins Ghidra's `SuperH4:LE:32:default` language with the `default` compiler specification because Ghidra's ELF opinion maps every EM_SH (42) image to SuperH4 without inspecting `e_flags`.",
        "Admission reads `e_type` and `e_flags` declarations only: a fixed-address ET_EXEC declaration does not establish static linkage, and header flags do not prove runtime FPSCR precision/transfer mode or instruction conformance.",
      ]
    : [];
