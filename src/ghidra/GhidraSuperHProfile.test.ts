import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createTestTempDirectory } from "../../tests/fixtures/temporaryDirectory.js";
import { parseConfig } from "../config/parseConfig.js";
import type {
  BinaryTarget,
  SuperHElfMetadata,
} from "../domain/binaryTargetTypes.js";
import { silentLogger } from "../logger.js";
import { HopperProvider } from "../hopper/HopperProvider.js";
import { hopperLoaderArgsForTarget } from "../hopper/HopperAnalysisProfile.js";
import { IdaProvider } from "../ida/IdaProvider.js";
import { KunaProvider } from "../kuna/KunaProvider.js";
import {
  ghidraPinnedLanguage,
  ghidraProfileLanguageOverride,
} from "./GhidraAnalysisProfile.js";
import { GhidraProvider } from "./GhidraProvider.js";
import { ghidraProfileInstallationHost as host } from "./GhidraInstallation.fixture.js";

// Abbreviated from Ghidra Processors/SuperH4/data/languages/SuperH4.ldefs.
const SUPERH4_LDEFS = `<?xml version="1.0" encoding="UTF-8"?>
<language_definitions>
  <language processor="SuperH4" endian="big" size="32" variant="default"
            id="SuperH4:BE:32:default">
    <compiler name="default" spec="SuperH4_be.cspec" id="default"/>
  </language>
  <language processor="SuperH4" endian="little" size="32" variant="default"
            id="SuperH4:LE:32:default">
    <compiler name="default" spec="SuperH4_le.cspec" id="default"/>
    <compiler name="Visual Studio" spec="SuperH4_le.cspec" id="windows"/>
  </language>
</language_definitions>
`;

const configFor = (environment: NodeJS.ProcessEnv) => {
  const parsed = parseConfig({ GHIDRA_INSTALL_DIR: "/ghidra", ...environment });
  if (!parsed.ok) throw parsed.error;
  return parsed.value;
};
const config = configFor({});
const target = (change: Partial<SuperHElfMetadata> = {}): BinaryTarget => ({
  path: "/fixture.elf",
  sha256: "a".repeat(64),
  kind: "executable",
  format: "elf",
  architecture: "superh",
  availableArchitectures: ["superh"],
  superh: {
    elfClass: 32,
    byteOrder: "little",
    type: 2,
    flags: 0x9,
    ...change,
  },
});

describe("bounded Ghidra SuperH admission", () => {
  it.each([0x0, 0x9, 0xc, 0x17])(
    "binds SuperH4:LE:32:default for admitted SH-4 machine flag 0x%s",
    async (flags) => {
      const ghidra = new GhidraProvider(config, silentLogger, {}, host);
      const value = target({ flags });
      expect(ghidra.inspectAvailability()).toMatchObject({
        status: "available",
      });
      expect(ghidra.inspectTargetSupport(value).status).toBe("supported");
      const resolved = await ghidra.resolveAnalysisProfile(value);
      if (!resolved.ok) throw resolved.error;
      const parameters = resolved.value.profile?.parameters ?? {};
      expect(parameters).toMatchObject({
        architecture: "superh",
        language_id: "SuperH4:LE:32:default",
        compiler_spec_id: "default",
        language_selection: "provider-pinned-v1",
        superh_elf: {
          elf_class: 32,
          byte_order: "little",
          type: 2,
          flags,
        },
        superh_support_lane: "elf32-le-exec-sh4-generic-v1",
      });
      expect(ghidraPinnedLanguage(value)).toEqual({
        languageId: "SuperH4:LE:32:default",
        compilerSpecId: "default",
      });
      expect(ghidraProfileLanguageOverride(parameters)).toEqual(
        ghidraPinnedLanguage(value),
      );
    },
  );

  it("lets a configured language replace the lane default", async () => {
    const installDir = await createTestTempDirectory("rea-ghidra-superh-");
    const languages = join(
      installDir,
      "Ghidra/Processors/SuperH4/data/languages",
    );
    await mkdir(languages, { recursive: true });
    await writeFile(join(languages, "SuperH4.ldefs"), SUPERH4_LDEFS);
    const ghidra = new GhidraProvider(
      configFor({
        GHIDRA_INSTALL_DIR: installDir,
        REA_GHIDRA_LANGUAGE_ID: "SuperH4:LE:32:default",
        REA_GHIDRA_COMPILER_SPEC_ID: "windows",
      }),
      silentLogger,
      {},
      host,
    );
    const resolved = await ghidra.resolveAnalysisProfile(target());
    if (!resolved.ok) throw resolved.error;
    const parameters = resolved.value.profile?.parameters ?? {};
    expect(parameters).toMatchObject({
      language_id: "SuperH4:LE:32:default",
      compiler_spec_id: "windows",
      language_selection: "configured-v1",
    });
    expect(ghidraProfileLanguageOverride(parameters)).toEqual({
      languageId: "SuperH4:LE:32:default",
      compilerSpecId: "windows",
    });
  });

  it("commits header flags so a changed interpretation changes the profile", async () => {
    const ghidra = new GhidraProvider(config, silentLogger, {}, host);
    const left = await ghidra.resolveAnalysisProfile(target({ flags: 0x9 }));
    const right = await ghidra.resolveAnalysisProfile(target({ flags: 0xc }));
    if (!left.ok) throw left.error;
    if (!right.ok) throw right.error;
    expect(left.value.profile?.digest).not.toBe(right.value.profile?.digest);
  });

  it("does not widen Windows P0", () => {
    const windows = new GhidraProvider(
      config,
      silentLogger,
      {},
      { ...host, platform: "win32" },
    );
    expect(windows.inspectTargetSupport(target()).status).toBe("unsupported");
  });

  it.each([
    [{ elfClass: 64 }, "ELF32"],
    [{ byteOrder: "big" }, "little-endian"],
    [{ type: 1 }, "ET_EXEC"],
    [{ type: 3 }, "ET_EXEC"],
    [{ flags: 0x1 }, "SH-4/SH-4A"],
    [{ flags: 0x2 }, "SH-4/SH-4A"],
    [{ flags: 0x4 }, "SH-4/SH-4A"],
    [{ flags: 0xd }, "SH-4/SH-4A"],
    [{ flags: 0x10 }, "SH-4/SH-4A"],
    [{ flags: 0x109 }, "EF_SH_MACH_MASK"],
  ] satisfies [Partial<SuperHElfMetadata>, string][])(
    "refuses an unverified SuperH interpretation %j",
    async (change, reason) => {
      const ghidra = new GhidraProvider(config, silentLogger, {}, host);
      const value = target(change);
      expect(ghidra.inspectTargetSupport(value)).toMatchObject({
        status: "unsupported",
        reason: expect.stringContaining(reason),
      });
      const resolved = await ghidra.resolveAnalysisProfile(value);
      expect(resolved).toMatchObject({
        ok: false,
        error: {
          _tag: "AnalysisUnsupportedTargetError",
          reason: expect.stringContaining(reason),
        },
      });
    },
  );

  it("keeps SuperH out of unverified Hopper, IDA, and Kuna adapter lanes", () => {
    const hopper = new HopperProvider(config, silentLogger, {}, "linux");
    expect(hopper.inspectTargetSupport(target())).toMatchObject({
      status: "unsupported",
      reason: expect.stringContaining("SuperH"),
    });
    expect(hopperLoaderArgsForTarget(target()).ok).toBe(false);
    const ida = new IdaProvider(config, {});
    expect(ida.inspectTargetSupport(target())).toMatchObject({
      status: "unsupported",
      reason: expect.stringContaining("SuperH"),
    });
    const kuna = new KunaProvider({});
    expect(kuna.inspectTargetSupport(target())).toMatchObject({
      status: "unsupported",
      code: "architecture_unsupported",
    });
  });
});
