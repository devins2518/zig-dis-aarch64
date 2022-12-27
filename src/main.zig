const std = @import("std");
const lib = @import("lib.zig");
const Disassembler = lib.Disassembler;

pub fn main() anyerror!void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer std.debug.assert(!gpa.deinit());
    const allocator = gpa.allocator();
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len == 1) {
        std.debug.print("Send hex input in through arguments\n", .{});
        std.process.exit(1);
    }
    const input_hex = args[1];
    const hex_len = @divExact(input_hex.len, 2);

    var i: usize = 0;
    var bytes = std.ArrayList(u8).init(allocator);
    try bytes.ensureTotalCapacity(hex_len);
    defer bytes.deinit();

    while (i < hex_len) : (i += 1) {
        const next_hex = input_hex[i * 2 .. (i + 1) * 2];
        bytes.appendAssumeCapacity(try std.fmt.parseInt(u8, next_hex, 16));
    }

    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();

    var disassembler = Disassembler.init(bytes.items);
    i = 0;
    while (try disassembler.next()) |inst| {
        try std.fmt.format(buf.writer(), "0x{x:0>16}: {X:0>2} {X:0>2} {X:0>2} {X:0>2}\t", .{
            i * 4,
            bytes.items[i * 4],
            bytes.items[(i * 4) + 1],
            bytes.items[(i * 4) + 2],
            bytes.items[(i * 4) + 3],
        });
        try inst.fmtPrint(buf.writer());
        try buf.append('\n');
        i += 1;
    }

    const stdout = std.io.getStdOut().writer();
    try stdout.writeAll("disassembled:\n");
    try stdout.print("{s}", .{buf.items});
}
