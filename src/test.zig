const std = @import("std");
const Disassembler = @import("decoder.zig").Disassembler;

test "a64 ignored fields" {
    return error.SkipZigTest;
}

test "arm64 advsimd" {
    return error.SkipZigTest;
}

test "arm64 arithmetic" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var disassembler = Disassembler.init(&.{
        // Add/Subtract with carry/borrow
        0x41, 0x00, 0x03, 0x1a,
        0x41, 0x00, 0x03, 0x9a,
        0x85, 0x00, 0x03, 0x3a,
        0x85, 0x00, 0x03, 0xba,
        0x41, 0x00, 0x03, 0x5a,
        0x41, 0x00, 0x03, 0xda,
        0x41, 0x00, 0x03, 0x7a,
        0x41, 0x00, 0x03, 0xfa,
        // Add/Subtract with (optionally shifted) immediate
        0x83, 0x00, 0x10, 0x11,
        0x83, 0x00, 0x10, 0x91,
        0x83, 0x00, 0x50, 0x11,
        0x83, 0x00, 0x40, 0x11,
        0x83, 0x00, 0x50, 0x91,
        0x83, 0x00, 0x40, 0x91,
        0xff, 0x83, 0x00, 0x91,
        0x83, 0x00, 0x10, 0x31,
        0x83, 0x00, 0x50, 0x31,
        0x83, 0x00, 0x10, 0xb1,
        0x83, 0x00, 0x50, 0xb1,
        0xff, 0x83, 0x00, 0xb1,
        0x83, 0x00, 0x10, 0x51,
        0x83, 0x00, 0x50, 0x51,
        0x83, 0x00, 0x10, 0xd1,
        0x83, 0x00, 0x50, 0xd1,
        0xff, 0x83, 0x00, 0xd1,
        0x83, 0x00, 0x10, 0x71,
        0x83, 0x00, 0x50, 0x71,
        0x83, 0x00, 0x10, 0xf1,
        0x83, 0x00, 0x50, 0xf1,
        0xff, 0x83, 0x00, 0xf1,
        // Add/Subtract register with (optional) shift
        0xac, 0x01, 0x0e, 0x0b,
        0xac, 0x01, 0x0e, 0x8b,
        0xac, 0x31, 0x0e, 0x0b,
        0xac, 0x31, 0x0e, 0x8b,
        0xac, 0x29, 0x4e, 0x0b,
        0xac, 0x29, 0x4e, 0x8b,
        0xac, 0x1d, 0x8e, 0x0b,
        0xac, 0x9d, 0x8e, 0x8b,
        0xac, 0x01, 0x0e, 0x4b,
        0xac, 0x01, 0x0e, 0xcb,
        0xac, 0x31, 0x0e, 0x4b,
        0xac, 0x31, 0x0e, 0xcb,
        0xac, 0x29, 0x4e, 0x4b,
        0xac, 0x29, 0x4e, 0xcb,
        0xac, 0x1d, 0x8e, 0x4b,
        0xac, 0x9d, 0x8e, 0xcb,
        0xac, 0x01, 0x0e, 0x2b,
        0xac, 0x01, 0x0e, 0xab,
        0xac, 0x31, 0x0e, 0x2b,
        0xac, 0x31, 0x0e, 0xab,
        0xac, 0x29, 0x4e, 0x2b,
        0xac, 0x29, 0x4e, 0xab,
        0xac, 0x1d, 0x8e, 0x2b,
        0xac, 0x9d, 0x8e, 0xab,
        0xac, 0x01, 0x0e, 0x6b,
        0xac, 0x01, 0x0e, 0xeb,
        0xac, 0x31, 0x0e, 0x6b,
        0xac, 0x31, 0x0e, 0xeb,
        0xac, 0x29, 0x4e, 0x6b,
        0xac, 0x29, 0x4e, 0xeb,
        0xac, 0x1d, 0x8e, 0x6b,
        0xac, 0x9d, 0x8e, 0xeb,
        // Add/Subtract with (optional) extend
        0x41, 0x00, 0x23, 0x0b,
        0x41, 0x20, 0x23, 0x0b,
        0x41, 0x40, 0x23, 0x0b,
        0x41, 0x60, 0x23, 0x0b,
        0x41, 0x80, 0x23, 0x0b,
        0x41, 0xa0, 0x23, 0x0b,
        0x41, 0xc0, 0x23, 0x0b,
        0x41, 0xe0, 0x23, 0x0b,
        0x41, 0x00, 0x23, 0x8b,
        0x41, 0x20, 0x23, 0x8b,
        0x41, 0x40, 0x23, 0x8b,
        0x41, 0x80, 0x23, 0x8b,
        0x41, 0xa0, 0x23, 0x8b,
        0x41, 0xc0, 0x23, 0x8b,
        0xe1, 0x43, 0x23, 0x0b,
        0xe1, 0x43, 0x23, 0x0b,
        0x5f, 0x60, 0x23, 0x8b,
        0x5f, 0x60, 0x23, 0x8b,
        0x41, 0x00, 0x23, 0x4b,
        0x41, 0x20, 0x23, 0x4b,
        0x41, 0x40, 0x23, 0x4b,
        0x41, 0x60, 0x23, 0x4b,
        0x41, 0x80, 0x23, 0x4b,
        0x41, 0xa0, 0x23, 0x4b,
        0x41, 0xc0, 0x23, 0x4b,
        0x41, 0xe0, 0x23, 0x4b,
        0x41, 0x00, 0x23, 0xcb,
        0x41, 0x20, 0x23, 0xcb,
        0x41, 0x40, 0x23, 0xcb,
        0x41, 0x80, 0x23, 0xcb,
        0x41, 0xa0, 0x23, 0xcb,
        0x41, 0xc0, 0x23, 0xcb,
        0xe1, 0x43, 0x23, 0x4b,
        0xe1, 0x43, 0x23, 0x4b,
        0x5f, 0x60, 0x23, 0xcb,
        0x5f, 0x60, 0x23, 0xcb,
        0x41, 0x00, 0x23, 0x2b,
        0x41, 0x20, 0x23, 0x2b,
        0x41, 0x40, 0x23, 0x2b,
        0x41, 0x60, 0x23, 0x2b,
        0x41, 0x80, 0x23, 0x2b,
        0x41, 0xa0, 0x23, 0x2b,
        0x41, 0xc0, 0x23, 0x2b,
        0x41, 0xe0, 0x23, 0x2b,
        0x41, 0x00, 0x23, 0xab,
        0x41, 0x20, 0x23, 0xab,
        0x41, 0x40, 0x23, 0xab,
        0x41, 0x80, 0x23, 0xab,
        0x41, 0xa0, 0x23, 0xab,
        0x41, 0xc0, 0x23, 0xab,
        0xe1, 0x43, 0x23, 0x2b,
        0xe1, 0x43, 0x23, 0x2b,
        0x41, 0x00, 0x23, 0x6b,
        0x41, 0x20, 0x23, 0x6b,
        0x41, 0x40, 0x23, 0x6b,
        0x41, 0x60, 0x23, 0x6b,
        0x41, 0x80, 0x23, 0x6b,
        0x41, 0xa0, 0x23, 0x6b,
        0x41, 0xc0, 0x23, 0x6b,
        0x41, 0xe0, 0x23, 0x6b,
        0x41, 0x00, 0x23, 0xeb,
        0x41, 0x20, 0x23, 0xeb,
        0x41, 0x40, 0x23, 0xeb,
        0x41, 0x80, 0x23, 0xeb,
        0x41, 0xa0, 0x23, 0xeb,
        0x41, 0xc0, 0x23, 0xeb,
        0xe1, 0x43, 0x23, 0x6b,
        0xe1, 0x43, 0x23, 0x6b,
        0x1f, 0x41, 0x28, 0xeb,
        0x3f, 0x41, 0x28, 0x6b,
        0xff, 0x43, 0x28, 0x6b,
        0xff, 0x43, 0x28, 0xeb,
        0x3f, 0x41, 0x28, 0x4b,
        0xe1, 0x43, 0x28, 0x4b,
        0xff, 0x43, 0x28, 0x4b,
        0x3f, 0x41, 0x28, 0xcb,
        0xe1, 0x43, 0x28, 0xcb,
        0xff, 0x43, 0x28, 0xcb,
        0xe1, 0x43, 0x28, 0x6b,
        0xe1, 0x43, 0x28, 0xeb,
        // Signed/Unsigned divide
        0x41, 0x0c, 0xc3, 0x1a,
        0x41, 0x0c, 0xc3, 0x9a,
        0x41, 0x08, 0xc3, 0x1a,
        0x41, 0x08, 0xc3, 0x9a,
        // Variable shifts
        0x41, 0x28, 0xc3, 0x1a,
        0x41, 0x28, 0xc3, 0x9a,
        0x41, 0x20, 0xc3, 0x1a,
        0x41, 0x20, 0xc3, 0x9a,
        0x41, 0x24, 0xc3, 0x1a,
        0x41, 0x24, 0xc3, 0x9a,
        0x41, 0x2c, 0xc3, 0x1a,
        0x41, 0x2c, 0xc3, 0x9a,
        // One operand instructions
        0x41, 0x14, 0xc0, 0x5a,
        0x41, 0x14, 0xc0, 0xda,
        0x41, 0x10, 0xc0, 0x5a,
        0x41, 0x10, 0xc0, 0xda,
        0x41, 0x00, 0xc0, 0x5a,
        0x41, 0x00, 0xc0, 0xda,
        0x41, 0x08, 0xc0, 0x5a,
        0x41, 0x0c, 0xc0, 0xda,
        0x41, 0x04, 0xc0, 0x5a,
        0x41, 0x04, 0xc0, 0xda,
        0x41, 0x08, 0xc0, 0xda,
        // 6.6.1 Multiply-add instructions
        0x41, 0x10, 0x03, 0x1b,
        0x41, 0x10, 0x03, 0x9b,
        0x41, 0x90, 0x03, 0x1b,
        0x41, 0x90, 0x03, 0x9b,
        0x41, 0x10, 0x23, 0x9b,
        0x41, 0x90, 0x23, 0x9b,
        0x41, 0x10, 0xa3, 0x9b,
        0x41, 0x90, 0xa3, 0x9b,
        // Multiply-high instructions
        0x41, 0x7c, 0x43, 0x9b,
        0x41, 0x7c, 0xc3, 0x9b,
        // Move immediate instructions
        0x20, 0x00, 0x80, 0x52,
        0x20, 0x00, 0x80, 0xd2,
        0x20, 0x00, 0xa0, 0x52,
        0x20, 0x00, 0xa0, 0xd2,
        0x40, 0x00, 0x80, 0x12,
        0x40, 0x00, 0x80, 0x92,
        0x40, 0x00, 0xa0, 0x12,
        0x40, 0x00, 0xa0, 0x92,
        0x20, 0x00, 0x80, 0x72,
        0x20, 0x00, 0x80, 0xf2,
        0x20, 0x00, 0xa0, 0x72,
        0x20, 0x00, 0xa0, 0xf2,
        // Conditionally set flags instructions
        0x1f, 0x00, 0x00, 0x31,
        0x1f, 0xfc, 0x03, 0xb1,
        0x23, 0x08, 0x42, 0x3a,
        0x23, 0x08, 0x42, 0xba,
        0x23, 0x08, 0x42, 0x7a,
        0x23, 0x08, 0x42, 0xfa,
        0x23, 0x00, 0x42, 0x3a,
        0x23, 0x00, 0x42, 0xba,
        0x23, 0x00, 0x42, 0x7a,
        0x23, 0x00, 0x42, 0xfa,
        // Conditional select instructions
        0x41, 0x00, 0x83, 0x1a,
        0x41, 0x00, 0x83, 0x9a,
        0x41, 0x04, 0x83, 0x1a,
        0x41, 0x04, 0x83, 0x9a,
        0x41, 0x00, 0x83, 0x5a,
        0x41, 0x00, 0x83, 0xda,
        0x41, 0x04, 0x83, 0x5a,
        0x41, 0x04, 0x83, 0xda,
    });

    var text = std.ArrayList(u8).init(gpa.allocator());
    defer text.deinit();

    while (try disassembler.next()) |inst| {
        try inst.fmtPrint(text.writer());
        try text.append('\n');
    }

    try std.testing.expectEqualStrings(
        \\adc w1, w2, w3
        \\adc x1, x2, x3
        \\adcs w5, w4, w3
        \\adcs x5, x4, x3
        \\sbc w1, w2, w3
        \\sbc x1, x2, x3
        \\sbcs w1, w2, w3
        \\sbcs x1, x2, x3
        \\add w3, w4, #1024
        \\add x3, x4, #1024
        \\add w3, w4, #1024, lsl #12
        \\add w3, w4, #0, lsl #12
        \\add x3, x4, #1024, lsl #12
        \\add x3, x4, #0, lsl #12
        \\add sp, sp, #32
        \\adds w3, w4, #1024
        \\adds w3, w4, #1024, lsl #12
        \\adds x3, x4, #1024
        \\adds x3, x4, #1024, lsl #12
        \\cmn sp, #32
        \\sub w3, w4, #1024
        \\sub w3, w4, #1024, lsl #12
        \\sub x3, x4, #1024
        \\sub x3, x4, #1024, lsl #12
        \\sub sp, sp, #32
        \\subs w3, w4, #1024
        \\subs w3, w4, #1024, lsl #12
        \\subs x3, x4, #1024
        \\subs x3, x4, #1024, lsl #12
        \\cmp sp, #32
        \\add w12, w13, w14
        \\add x12, x13, x14
        \\add w12, w13, w14, lsl #12
        \\add x12, x13, x14, lsl #12
        \\add w12, w13, w14, lsr #10
        \\add x12, x13, x14, lsr #10
        \\add w12, w13, w14, asr #7
        \\add x12, x13, x14, asr #39
        \\sub w12, w13, w14
        \\sub x12, x13, x14
        \\sub w12, w13, w14, lsl #12
        \\sub x12, x13, x14, lsl #12
        \\sub w12, w13, w14, lsr #10
        \\sub x12, x13, x14, lsr #10
        \\sub w12, w13, w14, asr #7
        \\sub x12, x13, x14, asr #39
        \\adds w12, w13, w14
        \\adds x12, x13, x14
        \\adds w12, w13, w14, lsl #12
        \\adds x12, x13, x14, lsl #12
        \\adds w12, w13, w14, lsr #10
        \\adds x12, x13, x14, lsr #10
        \\adds w12, w13, w14, asr #7
        \\adds x12, x13, x14, asr #39
        \\subs w12, w13, w14
        \\subs x12, x13, x14
        \\subs w12, w13, w14, lsl #12
        \\subs x12, x13, x14, lsl #12
        \\subs w12, w13, w14, lsr #10
        \\subs x12, x13, x14, lsr #10
        \\subs w12, w13, w14, asr #7
        \\subs x12, x13, x14, asr #39
        \\add w1, w2, w3, uxtb
        \\add w1, w2, w3, uxth
        \\add w1, w2, w3, uxtw
        \\add w1, w2, w3, uxtx
        \\add w1, w2, w3, sxtb
        \\add w1, w2, w3, sxth
        \\add w1, w2, w3, sxtw
        \\add w1, w2, w3, sxtx
        \\add x1, x2, w3, uxtb
        \\add x1, x2, w3, uxth
        \\add x1, x2, w3, uxtw
        \\add x1, x2, w3, sxtb
        \\add x1, x2, w3, sxth
        \\add x1, x2, w3, sxtw
        \\add w1, wsp, w3
        \\add w1, wsp, w3
        \\add sp, x2, x3
        \\add sp, x2, x3
        \\sub w1, w2, w3, uxtb
        \\sub w1, w2, w3, uxth
        \\sub w1, w2, w3, uxtw
        \\sub w1, w2, w3, uxtx
        \\sub w1, w2, w3, sxtb
        \\sub w1, w2, w3, sxth
        \\sub w1, w2, w3, sxtw
        \\sub w1, w2, w3, sxtx
        \\sub x1, x2, w3, uxtb
        \\sub x1, x2, w3, uxth
        \\sub x1, x2, w3, uxtw
        \\sub x1, x2, w3, sxtb
        \\sub x1, x2, w3, sxth
        \\sub x1, x2, w3, sxtw
        \\sub w1, wsp, w3
        \\sub w1, wsp, w3
        \\sub sp, x2, x3
        \\sub sp, x2, x3
        \\adds w1, w2, w3, uxtb
        \\adds w1, w2, w3, uxth
        \\adds w1, w2, w3, uxtw
        \\adds w1, w2, w3, uxtx
        \\adds w1, w2, w3, sxtb
        \\adds w1, w2, w3, sxth
        \\adds w1, w2, w3, sxtw
        \\adds w1, w2, w3, sxtx
        \\adds x1, x2, w3, uxtb
        \\adds x1, x2, w3, uxth
        \\adds x1, x2, w3, uxtw
        \\adds x1, x2, w3, sxtb
        \\adds x1, x2, w3, sxth
        \\adds x1, x2, w3, sxtw
        \\adds w1, wsp, w3
        \\adds w1, wsp, w3
        \\subs w1, w2, w3, uxtb
        \\subs w1, w2, w3, uxth
        \\subs w1, w2, w3, uxtw
        \\subs w1, w2, w3, uxtx
        \\subs w1, w2, w3, sxtb
        \\subs w1, w2, w3, sxth
        \\subs w1, w2, w3, sxtw
        \\subs w1, w2, w3, sxtx
        \\subs x1, x2, w3, uxtb
        \\subs x1, x2, w3, uxth
        \\subs x1, x2, w3, uxtw
        \\subs x1, x2, w3, sxtb
        \\subs x1, x2, w3, sxth
        \\subs x1, x2, w3, sxtw
        \\subs w1, wsp, w3
        \\subs w1, wsp, w3
        \\cmp x8, w8, uxtw
        \\cmp w9, w8, uxtw
        \\cmp wsp, w8
        \\cmp sp, w8, uxtw
        \\sub wsp, w9, w8
        \\sub w1, wsp, w8
        \\sub wsp, wsp, w8
        \\sub sp, x9, w8, uxtw
        \\sub x1, sp, w8, uxtw
        \\sub sp, sp, w8, uxtw
        \\subs w1, wsp, w8
        \\subs x1, sp, w8, uxtw
        \\sdiv w1, w2, w3
        \\sdiv x1, x2, x3
        \\udiv w1, w2, w3
        \\udiv x1, x2, x3
        \\asr w1, w2, w3
        \\asr x1, x2, x3
        \\lsl w1, w2, w3
        \\lsl x1, x2, x3
        \\lsr w1, w2, w3
        \\lsr x1, x2, x3
        \\ror w1, w2, w3
        \\ror x1, x2, x3
        \\cls w1, w2
        \\cls x1, x2
        \\clz w1, w2
        \\clz x1, x2
        \\rbit w1, w2
        \\rbit x1, x2
        \\rev w1, w2
        \\rev x1, x2
        \\rev16 w1, w2
        \\rev16 x1, x2
        \\rev32 x1, x2
        \\madd w1, w2, w3, w4
        \\madd x1, x2, x3, x4
        \\msub w1, w2, w3, w4
        \\msub x1, x2, x3, x4
        \\smaddl x1, w2, w3, x4
        \\smsubl x1, w2, w3, x4
        \\umaddl x1, w2, w3, x4
        \\umsubl x1, w2, w3, x4
        \\smulh x1, x2, x3
        \\umulh x1, x2, x3
        \\movz w0, #1
        \\movz x0, #1
        \\movz w0, #1, lsl #16
        \\movz x0, #1, lsl #16
        \\movn w0, #2
        \\movn x0, #2
        \\movn w0, #2, lsl #16
        \\movn x0, #2, lsl #16
        \\movk w0, #1
        \\movk x0, #1
        \\movk w0, #1, lsl #16
        \\movk x0, #1, lsl #16
        \\cmn w0, #0
        \\cmn x0, #255
        \\ccmn w1, #2, #3, eq
        \\ccmn x1, #2, #3, eq
        \\ccmp w1, #2, #3, eq
        \\ccmp x1, #2, #3, eq
        \\ccmn w1, w2, #3, eq
        \\ccmn x1, x2, #3, eq
        \\ccmp w1, w2, #3, eq
        \\ccmp x1, x2, #3, eq
        \\csel w1, w2, w3, eq
        \\csel x1, x2, x3, eq
        \\csinc w1, w2, w3, eq
        \\csinc x1, x2, x3, eq
        \\csinv w1, w2, w3, eq
        \\csinv x1, x2, x3, eq
        \\csneg w1, w2, w3, eq
        \\csneg x1, x2, x3, eq
        \\
    , text.items);
}

test "arm64 basic a64 undefined" {
    return error.SkipZigTest;
}

test "arm64 bitfield" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var disassembler = Disassembler.init(&.{
        // 5.4.4 Bitfield Operations
        0x41, 0x3c, 0x01, 0x33,
        0x41, 0x3c, 0x41, 0xb3,
        0x41, 0x3c, 0x01, 0x13,
        0x41, 0x3c, 0x41, 0x93,
        0x41, 0x3c, 0x01, 0x53,
        0x41, 0x3c, 0x41, 0xd3,
        // 5.4.5 Extract (immediate)
        0x41, 0x3c, 0x83, 0x13,
        0x62, 0x04, 0xc4, 0x93,
    });

    var text = std.ArrayList(u8).init(gpa.allocator());
    defer text.deinit();

    while (try disassembler.next()) |inst| {
        try inst.fmtPrint(text.writer());
        try text.append('\n');
    }

    try std.testing.expectEqualStrings(
        \\bfxil w1, w2, #1, #15
        \\bfxil x1, x2, #1, #15
        \\sbfx w1, w2, #1, #15
        \\sbfx x1, x2, #1, #15
        \\ubfx w1, w2, #1, #15
        \\ubfx x1, x2, #1, #15
        \\extr w1, w2, w3, #15
        \\extr x2, x3, x4, #1
        \\
    , text.items);
}

test "arm64 branch" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var disassembler = Disassembler.init(&.{
        // Unconditional branch (register) instructions.
        0xc0, 0x03, 0x5f, 0xd6,
        0x20, 0x00, 0x5f, 0xd6,
        0xe0, 0x03, 0xbf, 0xd6,
        0xe0, 0x03, 0x9f, 0xd6,
        0xa0, 0x00, 0x1f, 0xd6,
        0x20, 0x01, 0x3f, 0xd6,
        0x0B, 0x00, 0x18, 0x37,
        // Exception generation instructions.
        0x20, 0x00, 0x20, 0xd4,
        0x41, 0x00, 0xa0, 0xd4,
        0x62, 0x00, 0xa0, 0xd4,
        0x83, 0x00, 0xa0, 0xd4,
        0xa0, 0x00, 0x40, 0xd4,
        0xc2, 0x00, 0x00, 0xd4,
        0xe3, 0x00, 0x00, 0xd4,
        0x01, 0x01, 0x00, 0xd4,
        // // PC-relative branches (both positive and negative displacement)
        0x07, 0x00, 0x00, 0x14,
        0x06, 0x00, 0x00, 0x94,
        0xa1, 0x00, 0x00, 0x54,
        0x80, 0x00, 0x08, 0x36,
        0xe1, 0xff, 0xf7, 0x36,
        0x60, 0x00, 0x08, 0x37,
        0x40, 0x00, 0x00, 0xb4,
        0x20, 0x00, 0x00, 0xb5,
        0x1f, 0x20, 0x03, 0xd5,
        0xff, 0xff, 0xff, 0x17,
        0xc1, 0xff, 0xff, 0x54,
        0xa0, 0xff, 0x0f, 0x36,
        0x80, 0xff, 0xff, 0xb4,
        0x1f, 0x20, 0x03, 0xd5,
    });

    var text = std.ArrayList(u8).init(gpa.allocator());
    defer text.deinit();

    while (try disassembler.next()) |inst| {
        try inst.fmtPrint(text.writer());
        try text.append('\n');
    }

    try std.testing.expectEqualStrings(
        \\ret
        \\ret x1
        \\drps
        \\eret
        \\br x5
        \\blr x9
        \\tbnz w11, #3, #0
        \\brk #1
        \\dcps1 #2
        \\dcps2 #3
        \\dcps3 #4
        \\hlt #5
        \\hvc #6
        \\smc #7
        \\svc #8
        \\b #28
        \\bl #24
        \\b.ne #20
        \\tbz w0, #1, #16
        \\tbz w1, #30, #-4
        \\tbnz w0, #1, #12
        \\cbz x0, #8
        \\cbnz x0, #4
        \\nop
        \\b #-4
        \\b.ne #-8
        \\tbz w0, #1, #-12
        \\cbz x0, #-16
        \\nop
        \\
    , text.items);
}

test "arm64 canonical form" {
    return error.SkipZigTest;
}

test "arm64 crc32" {
    return error.SkipZigTest;
}

test "arm64 crypto" {
    return error.SkipZigTest;
}

test "arm64 invalid logical" {
    return error.SkipZigTest;
}

test "arm64 logical" {
    return error.SkipZigTest;
}

test "arm64 memory" {
    return error.SkipZigTest;
}

test "arm64 non apple fmov" {
    return error.SkipZigTest;
}

test "arm64 scalar fp" {
    return error.SkipZigTest;
}

test "arm64 system" {
    return error.SkipZigTest;
}

test "armv8.1a atomic" {
    return error.SkipZigTest;
}

test "armv8.1a lor" {
    return error.SkipZigTest;
}

test "armv8.1a pan" {
    return error.SkipZigTest;
}

test "armv8.1a rdma" {
    return error.SkipZigTest;
}

test "armv8.1a vhe" {
    return error.SkipZigTest;
}

test "armv8.2a at" {
    return error.SkipZigTest;
}

test "armv8.2a crypto" {
    return error.SkipZigTest;
}

test "armv8.2a dotprod" {
    return error.SkipZigTest;
}

test "armv8.2a mmfr2" {
    return error.SkipZigTest;
}

test "armv8.2a persistent memory" {
    return error.SkipZigTest;
}

test "armv8.2a statistical profiling" {
    return error.SkipZigTest;
}

test "armv8.2a uao" {
    return error.SkipZigTest;
}

test "armv8.3a complex" {
    return error.SkipZigTest;
}

test "armv8.3a ID_ISAR6_EL1" {
    return error.SkipZigTest;
}

test "armv8.3a js" {
    return error.SkipZigTest;
}

test "armv8.3a rcpc" {
    return error.SkipZigTest;
}

test "armv8.3a signed pointer" {
    return error.SkipZigTest;
}

test "armv8.4a actmon" {
    return error.SkipZigTest;
}

test "armv8.4a dit" {
    return error.SkipZigTest;
}

test "armv8.4a flag" {
    return error.SkipZigTest;
}

test "armv8.4a ldst" {
    return error.SkipZigTest;
}

test "armv8.4a mpam" {
    return error.SkipZigTest;
}

test "armv8.4a pmu" {
    return error.SkipZigTest;
}

test "armv8.4a ras" {
    return error.SkipZigTest;
}

test "armv8.4a tlb" {
    return error.SkipZigTest;
}

test "armv8.4a trace" {
    return error.SkipZigTest;
}

test "armv8.4a virt" {
    return error.SkipZigTest;
}

test "armv8.4a vncr" {
    return error.SkipZigTest;
}

test "armv8.5a bti" {
    return error.SkipZigTest;
}

test "armv8.5a dataproc" {
    return error.SkipZigTest;
}

test "armv8.5a mte" {
    return error.SkipZigTest;
}

test "armv8.5a persistent memory" {
    return error.SkipZigTest;
}

test "armv8.5a predres" {
    return error.SkipZigTest;
}

test "armv8.5a rand" {
    return error.SkipZigTest;
}

test "armv8.5a sb" {
    return error.SkipZigTest;
}

test "armv8.5a specrestrict" {
    return error.SkipZigTest;
}

test "armv8.5a ssbs" {
    return error.SkipZigTest;
}

test " armv8.6a amvs.s" {
    return error.SkipZigTest;
}

test "armv8.6a bf16" {
    return error.SkipZigTest;
}

test "armv8.6a ecv" {
    return error.SkipZigTest;
}

test "armv8.6a fgt" {
    return error.SkipZigTest;
}

test "armv8.6a simd matmul" {
    return error.SkipZigTest;
}

test "armv8.7a hcx" {
    return error.SkipZigTest;
}

test "armv8.7a ls64" {
    return error.SkipZigTest;
}

test "armv8.7a wfxt" {
    return error.SkipZigTest;
}

test "armv8.7a xs" {
    return error.SkipZigTest;
}

test "armv8a fpmul err" {
    return error.SkipZigTest;
}

test "armv8a fpmul" {
    return error.SkipZigTest;
}

test "armv9a rme" {
    return error.SkipZigTest;
}

test "basic a64 instructions" {
    return error.SkipZigTest;
}

test "basic a64 undefined" {
    return error.SkipZigTest;
}

test "basic a64 unpredictable" {
    return error.SkipZigTest;
}

test "brbe" {
    return error.SkipZigTest;
}

test "ete" {
    return error.SkipZigTest;
}

test "fullfp16 neg" {
    return error.SkipZigTest;
}

test "fullfp16 neon neg" {
    return error.SkipZigTest;
}

test "gicv3 regs" {
    return error.SkipZigTest;
}

test "ldp offset predictable" {
    return error.SkipZigTest;
}

test "ldp postind.predictable" {
    return error.SkipZigTest;
}

test "ldp preind.predictable" {
    return error.SkipZigTest;
}

test "lit.local.cfg" {
    return error.SkipZigTest;
}

test "neon instructions" {
    return error.SkipZigTest;
}

test "ras extension" {
    return error.SkipZigTest;
}

test "speculation barriers" {
    return error.SkipZigTest;
}

test "tme" {
    return error.SkipZigTest;
}

test "trace regs" {
    return error.SkipZigTest;
}

test "trbe" {
    return error.SkipZigTest;
}

test "udf" {
    return error.SkipZigTest;
}

test "ignored fields" {
    return error.SkipZigTest;
}
