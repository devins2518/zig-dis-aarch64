const std = @import("std");
const Instruction = @import("instruction.zig").Instruction;
const AddSubInstr = @import("instruction.zig").AddSubInstr;
const LogInstr = @import("instruction.zig").LogInstr;
const MovInstr = @import("instruction.zig").MovInstr;
const ExtractInstr = @import("instruction.zig").ExtractInstr;
const Register = @import("utils.zig").Register;
const Width = @import("utils.zig").Width;
const Field = @import("utils.zig").Field;
const bytes = @import("utils.zig").bytes;

const Error = error{
    EndOfStream,
    Unallocated,
    Unimplemented,
};

const Disassembler = struct {
    const Self = @This();

    code: []const u8,
    stream: std.io.FixedBufferStream([]const u8),

    pub fn init(code: []const u8) Self {
        return .{
            .code = code,
            .stream = std.io.fixedBufferStream(code),
        };
    }

    fn next(self: *Self) Error!?Instruction {
        const reader = self.stream.reader();

        const op = reader.readIntLittle(u32) catch return null;

        const op0 = op >> 31;
        const op1 = @truncate(u4, op >> 25);

        switch (op1) {
            0b0000 => return try if (op0 == 0) decodeReserve(op) else decodeSME(op), // Reserved and SME
            0b0001 => return error.Unallocated,
            0b0010 => return try decodeSVE(op), // SVE encoding
            0b0011 => return error.Unallocated,
            0b1000, 0b1001 => return try decodeDataProcImm(op), // Data processing - Imm
            0b1010, 0b1011 => return try decodeBranchExcpSysInstr(op), // Branches, exceptions, system instructions
            0b0100, 0b0110, 0b1100, 0b1110 => return error.Unimplemented, // Load/Store
            0b0101, 0b1101 => return try decodeDataProcReg(op), // Data processing - Reg
            0b0111, 0b1111 => return error.Unimplemented, // Data processing - Scalar FP and SIMD
        }
    }

    fn decodeReserve(op: u32) Error!Instruction {
        _ = op;
        return error.Unimplemented;
    }

    fn decodeSME(op: u32) Error!Instruction {
        _ = op;
        return error.Unimplemented;
    }

    fn decodeSVE(op: u32) Error!Instruction {
        _ = op;
        return error.Unimplemented;
    }

    fn decodeDataProcImm(op: u32) Error!Instruction {
        const op0 = @truncate(u3, op >> 23);

        return switch (op0) {
            0b000, 0b001 => error.Unimplemented,
            0b010 => error.Unimplemented,
            0b011 => error.Unimplemented,
            0b100 => blk: {
                const width = Width.from(op >> 31);
                const n = @truncate(u1, op >> 22);
                const opc = @truncate(u2, op >> 29);
                const payload = LogInstr{
                    .s = opc == 0b11,
                    .n = @truncate(u1, op >> 22),
                    .width = width,
                    .rn = Register.from(op >> 5, width, true),
                    .rd = Register.from(op, width, false),
                    .payload = .{ .imm = .{
                        .immr = @truncate(u6, op >> 16),
                        .imms = @truncate(u6, op >> 10),
                    } },
                };
                break :blk if (width == .w and n == 1) error.Unallocated else switch (opc) {
                    0b00, 0b11 => Instruction{ .@"and" = payload },
                    0b01 => Instruction{ .orr = payload },
                    0b10 => Instruction{ .eor = payload },
                };
            },
            0b101 => blk: {
                const width = Width.from(op >> 31);
                const opc = @truncate(u2, op >> 29);
                const hw = @truncate(u2, op >> 21);
                break :blk if (opc == 0b01 or (width == .w and (hw == 0b10 or hw == 0b11)))
                    error.Unimplemented
                else .{ .mov = .{
                    .ext = @intToEnum(Field(MovInstr, .ext), opc),
                    .imm16 = bytes(u16, op >> 5),
                    .rd = Register.from(op, width, false),
                } };
            },
            0b110 => error.Unimplemented,
            0b111 => error.Unimplemented,
        };
    }

    fn decodeBranchExcpSysInstr(op: u32) Error!Instruction {
        const op0 = @truncate(u3, op >> 29);
        return switch (op0) {
            else => error.Unimplemented,
        };
    }

    fn decodeDataProcReg(op: u32) Error!Instruction {
        const op0 = @truncate(u1, op >> 30);
        const op1 = @truncate(u1, op >> 28);
        const op2 = @truncate(u4, op >> 21);
        const op3 = @truncate(u6, op >> 10);
        _ = op0;
        _ = op2;
        _ = op3;
        if (op1 == 0) {
            return error.Unimplemented;
        } else {
            return error.Unimplemented;
        }
    }
};

test "disassembler functionality" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var disassembler = Disassembler.init(&.{
        0x41, 0x01, 0x80, 0xD2, // mov x1, #xa
        0x5f, 0x01, 0x80, 0x72, // movk wzr, #0xa
        0x5f, 0x01, 0x80, 0x92, // movn wzr, #0xa
        0xa0, 0x0c, 0x00, 0x12, // and  w0, w5, #0xf
        0xa0, 0x0c, 0x00, 0x32, // orr  w0, w5, #0xf
        0xa0, 0x0c, 0x00, 0x52, // eor  w0, w5, #0xf
        0xa0, 0x0c, 0x00, 0x72, // ands w0, w5, #0xf
        0xa0, 0x0c, 0x40, 0x92, // and  x0, x5, #0xf
        0xa0, 0x0c, 0x40, 0xb2, // orr  x0, x5, #0xf
        0xa0, 0x0c, 0x40, 0xd2, // eor  x0, x5, #0xf
        0xa0, 0x0c, 0x40, 0xf2, // ands x0, x5, #0xf
        0x00, 0x00, 0x7c, 0x92, // and  x0, x0, #0x10
        0x00, 0x00, 0x7a, 0x92, // and x0, x0, #0x40
    });

    var text = std.ArrayList(u8).init(gpa.allocator());
    defer text.deinit();

    while (try disassembler.next()) |inst| {
        try inst.fmtPrint(text.writer());
        try text.append('\n');
    }

    try std.testing.expectEqualStrings(
        \\movz x1, #0xa
        \\movk wzr, #0xa
        \\movn xzr, #0xa
        \\and  w0, w5, #0xf
        \\orr  w0, w5, #0xf
        \\eor  w0, w5, #0xf
        \\ands w0, w5, #0xf
        \\and  x0, x5, #0xf
        \\orr  x0, x5, #0xf
        \\eor  x0, x5, #0xf
        \\ands x0, x5, #0xf
        \\and  x0, x0, #0x10
        \\and  x0, x0, #0x40
        \\
    , text.items);
}
