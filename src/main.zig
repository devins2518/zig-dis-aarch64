const std = @import("std");

pub fn main() anyerror!void {
    // Note that info level log messages are by default printed only in Debug
    // and ReleaseSafe build modes.
    std.log.info("All your codebase are belong to us.", .{});
}

test "functionality" {
    _ = @import("encoder.zig");
    _ = @import("decoder.zig");
    _ = @import("Instruction.zig");
}