# Zig Aarch64 Disassembler

Inspired by [zig-dis-x86_64](https://github.com/kubkon/zig-dis-x86_64/blob/main/src/test.zig).

Using [LLVM's disassembly tests](https://github.com/llvm/llvm-project/tree/release/13.x/llvm/test/MC/Disassembler/AArch64).

## Usage

Programmatic Disassembly:

```zig
const std = @import("std");
const Disassembler = @import("zig-dis-aarch64").Disassembler;

var disassembler = Disassembler.init(&.{
    0x41, 0x00, 0x03, 0x1a,  // adc w1, w2, w3
    0x41, 0x00, 0x03, 0x9a,  // adc x1, x2, x3
});

var text = std.ArrayList(u8).init(gpa);
defer text.deinit();

while (try disassembler.next()) |inst| {
    try inst.fmtPrint(text.writer());
    try text.append('\n');
}

try std.testing.expectEqualStrings(
    \\adc w1, w2, w3
    \\adc x1, x2, x3
    \\
, text.items);
```

Command line interface:

```sh
❯ ./zig-out/bin/zig-dis-aarch64 4100031a4100039a8500033a850003ba4100035a410003da4100037a410003fa
disassembled:
0x0000000000000000: 41 00 03 1A	adc w1, w2, w3
0x0000000000000004: 41 00 03 9A	adc x1, x2, x3
0x0000000000000008: 85 00 03 3A	adcs w5, w4, w3
0x000000000000000c: 85 00 03 BA	adcs x5, x4, x3
0x0000000000000010: 41 00 03 5A	sbc w1, w2, w3
0x0000000000000014: 41 00 03 DA	sbc x1, x2, x3
0x0000000000000018: 41 00 03 7A	sbcs w1, w2, w3
0x000000000000001c: 41 00 03 FA	sbcs x1, x2, x3
```
