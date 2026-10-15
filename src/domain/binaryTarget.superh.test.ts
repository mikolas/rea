import { describe, expect, it } from "vitest";
import { parseExecutableHeader } from "./binaryTarget.js";

const header = (
  little: boolean,
  bits: 32 | 64 = 32,
  flags = 0x9,
  type = 2,
  machine = 42,
): Buffer => {
  const bytes = Buffer.alloc(bits === 32 ? 52 : 64);
  bytes.set([0x7f, 0x45, 0x4c, 0x46, bits === 32 ? 1 : 2, little ? 1 : 2, 1]);
  const flagsOffset = bits === 32 ? 36 : 48;
  const ehsizeOffset = bits === 32 ? 40 : 52;
  if (little) {
    bytes.writeUInt16LE(type, 16);
    bytes.writeUInt16LE(machine, 18);
    bytes.writeUInt32LE(1, 20);
    bytes.writeUInt32LE(flags, flagsOffset);
    bytes.writeUInt16LE(bytes.length, ehsizeOffset);
  } else {
    bytes.writeUInt16BE(type, 16);
    bytes.writeUInt16BE(machine, 18);
    bytes.writeUInt32BE(1, 20);
    bytes.writeUInt32BE(flags, flagsOffset);
    bytes.writeUInt16BE(bytes.length, ehsizeOffset);
  }
  return bytes;
};

describe("SuperH ELF header boundaries", () => {
  it.each([true, false])(
    "retains source endian, type, and flags (little=%s)",
    (little) => {
      const parsed = parseExecutableHeader(header(little, 32, 0x9), "x64");
      if (!parsed.ok) throw new Error(parsed.error);
      expect(parsed.value).toEqual({
        format: "elf",
        architecture: "superh",
        availableArchitectures: ["superh"],
        superh: {
          elfClass: 32,
          byteOrder: little ? "little" : "big",
          type: 2,
          flags: 0x9,
        },
      });
    },
  );

  it("reads ELF64 flags at their own offset without claiming support", () => {
    const bytes = header(true, 64, 0x9);
    const parsed = parseExecutableHeader(bytes, "x64");
    if (!parsed.ok) throw new Error(parsed.error);
    expect(parsed.value).toMatchObject({
      architecture: "superh",
      superh: { elfClass: 64, byteOrder: "little", type: 2, flags: 0x9 },
    });
  });

  it("rejects truncated EM_SH headers", () => {
    expect(
      parseExecutableHeader(header(true).subarray(0, 39), "x64"),
    ).toMatchObject({
      ok: false,
    });
  });

  it("does not recognize adjacent unmapped ELF machine numbers", () => {
    expect(parseExecutableHeader(header(true, 32, 0x9, 2, 43), "x64")).toEqual({
      ok: false,
      error: "unsupported ELF architecture",
    });
  });
});
