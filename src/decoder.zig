const Disassembler = struct {
    fn decode(op: u32) Self {
        const op0 = op >> 31;
        const op1 = (op >> 25) & 0xF;

        // TODO: handle reserved and sme
        _ = op0;

        switch (op1) {
            0b0001 => @panic("Unallocated"),
            0b0010 => @panic("SVE encoding"),
            0b0011 => @panic("Unallocated"),
            0b1000, 0b1001 => @panic("Data processing - Imm"),
            0b1010, 0b1011 => @panic("Branches, exceptions, system instructions"),
            0b0100, 0b0110, 0b1100, 0b1110 => @panic("Load/Store"),
            0b0101, 0b1101 => @panic("Data processing - Reg"),
            0b0111, 0b0111 => @panic("Data processing - Scalar FP and SIMD"),
        }

        @panic("unimplemented");
    }
};

test "functionality" {
    var disassembler = Disassembler.init(&.{
        0x40, 0xb7, 0x10, // mov dil, 0x10
        0x48, 0x8b, 0xd8, // mov rbx, rax
    });

    var text = std.ArrayList(u8).init(gpa);
    defer text.deinit();

    while (try disassembler.next()) |inst| {
        try inst.fmtPrint(text.writer());
        try text.append('\n');
    }

    try std.testing.expectEqualStrings(
        \\mov dil, 0x10
        \\mov rbx, rax
    , text.items);
}
