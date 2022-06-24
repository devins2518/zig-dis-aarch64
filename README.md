# Zig Aarch64 Disassembler

Inspired by [zig-dis-x86_64](https://github.com/kubkon/zig-dis-x86_64/blob/main/src/test.zig).

Using [LLVM's disassembly tests](https://github.com/llvm/llvm-project/tree/release/13.x/llvm/test/MC/Disassembler/AArch64).

## Usage

Disassembly:

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
