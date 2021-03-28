const std = @import("std");

const info = std.log.info;
const warn = std.log.warn;
const net = std.net;
const Sha1 = std.crypto.hash.Sha1;
const base64 = std.base64;
const ArrayList = std.ArrayList;

const MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const SEC_WEBSOCKET_KEY = "Sec-WebSocket-Key: ";
const HANDSHAKE_RESPONSE_FMT = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {s}\r\n\r\n";

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const base64_encoded_key_len = base64.Base64Encoder.calcSize(Sha1.digest_length);

// basic-tcp-chat.zig https://gist.github.com/andrewrk/34c21bdc1600b0884a3ab9fa9aa485b8
// https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers
// https://www.honeybadger.io/blog/building-a-simple-websockets-server-from-scratch-in-ruby/

const Room = struct {
    clients: std.AutoHashMap(*Client, void),

    fn broadcast(room: *Room, msg: []const u8, sender: *Client) void {
        var it = room.clients.iterator();

        while (it.next()) |entry| {
            const client = entry.key;
            if (client == sender) continue;
            client.connection.stream.writer().writeAll(msg) catch |e| std.debug.warn("Unable to send: {}\n", .{e});
        }
    }
};

const Client = struct {
    connection: net.StreamServer.Connection,
    handle_frame: @Frame(handle),

    fn handle(self: *Client, room: *Room) !void {
        const allocator = &gpa.allocator;
        var handshake_data = ArrayList(u8).init(allocator);
        defer handshake_data.deinit();

        var payload_data = ArrayList(u8).init(allocator);
        defer payload_data.deinit();

        var writer = self.connection.stream.writer();
        var reader = self.connection.stream.reader();

        var handshake_done = false;
        while (true) {
            info("Reading...", .{});

            if (!handshake_done) {
                handshake_done = handshakeIncoming(allocator, reader, writer, &handshake_data) catch {
                    self.connection.stream.close();
                    break;
                };
                info("Handshake done: {}", .{handshake_done});
            }

            var first_byte = try reader.readByte();
            const fin = first_byte & 0b10000000;
            const opcode = first_byte & 0b00001111;

            info("Fin: {} opcode: {}", .{ fin, opcode });

            if (fin == 0) return error.UnsupportedContinuations; // TODO support continuations.
            if (opcode != 1) return error.UnsupportedOpcode; // TODO support other opcodes different than 1.

            var second_byte = try reader.readByte();
            const is_masked = second_byte & 0b10000000;
            const payload_len = second_byte & 0b01111111;

            if (is_masked == 0) return error.IncomingFramesMustBeMasked;
            if (payload_len >= 126) return error.UnsupportedLength; // TODO Support pay loads larger than 126 bytes.

            info("Masked:{} payload_len:{}", .{ is_masked, payload_len });

            // Since we're only expecting payload lengths < 126 we'll skip extended payload length,
            // extended payload length continued and go straight to the masking key which has 4 bytes.

            var mask: [4]u8 = undefined;
            const amt = try reader.read(&mask);
            if (amt != 4) return error.MaskReadFail;

            info("Mask: {} | {} | {} | {}", .{ mask[0], mask[1], mask[2], mask[3] });

            // Read the payload.
            payload_data.shrinkRetainingCapacity(0);
            var idx: u8 = 0;
            while (idx < payload_len) : (idx += 1) {
                var a = try reader.readByte();
                var unmasked = a ^ mask[idx % 4];
                try payload_data.append(unmasked);
            }

            const payload = payload_data.items;
            info("Payload: {s}", .{payload});

            // room.broadcast(payload, self); // TODO send a correct frame to the other clients.
        }

        info("Exiting handle", .{});
    }
};

fn handshakeIncoming(allocator: anytype, reader: anytype, writer: anytype, list: *ArrayList(u8)) !bool {
    try readRequestInto(reader, list);
    const value = try parseSecWebSocketKey(list);

    if (value.len != 0) {
        info("Got:{s} {s}", .{ SEC_WEBSOCKET_KEY, value });
    } else {
        warn("No {s}, closing connection?", .{SEC_WEBSOCKET_KEY});
        // TODO This is probably not correct. A response should be sent?
        return error.HandshakeError;
    }

    const accept_value = createSecWebSocketAccept(value);
    info("Accepting with:{s}->{s}", .{ value, accept_value });

    const response_str = try std.fmt.allocPrint(allocator, HANDSHAKE_RESPONSE_FMT, .{accept_value});
    defer allocator.free(response_str);

    info("Writing:{s}", .{response_str});
    try writer.writeAll(response_str);

    return true;
}

fn createSecWebSocketAccept(key: []const u8) [28]u8 {
    const magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    var hash = Sha1.init(.{});
    hash.update(key);
    hash.update(magic);

    var hashed_key: [Sha1.digest_length]u8 = undefined;
    hash.final(&hashed_key);

    var encoded: [base64_encoded_key_len]u8 = undefined;
    _ = base64.standard_encoder.encode(&encoded, &hashed_key);

    return encoded;
}

fn parseSecWebSocketKey(request: *std.ArrayList(u8)) ![]const u8 {
    // TODO We probably should verify if the other headers make sense.

    var lines = std.mem.split(request.items, "\n");
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, SEC_WEBSOCKET_KEY)) {
            var value = line[SEC_WEBSOCKET_KEY.len..(line.len - 1)]; // Do not include \r at the end.
            return value;
        }
    }

    return "";
}

fn readRequestInto(reader: anytype, list: *std.ArrayList(u8)) !void {
    list.shrinkRetainingCapacity(0);

    const max_size: usize = 1000;
    var prev_byte: u8 = 0;
    while (true) {
        var byte: u8 = try reader.readByte();

        if (list.items.len == max_size) {
            list.shrinkRetainingCapacity(0);
            return error.StreamTooLong;
        }

        try list.append(byte);

        const len = list.items.len;
        if (len >= 3) {
            const a = list.items[len - 3];
            const b = list.items[len - 2];
            const c = list.items[len - 1];

            if (a == '\n' and b == '\r' and c == '\n') {
                return;
            }
        }
    }

    list.shrinkRetainingCapacity(0);
    return error.NoEnd;
}

pub fn main() anyerror!void {
    info("Hi.", .{});
    const allocator = &gpa.allocator;

    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    _ = args.skip();

    var raw_port = try args.next(allocator) orelse return error.NoPortGiven catch {
        info("Couldport number.", .{});
        return;
    };

    const port = std.fmt.parseInt(u16, raw_port, 10) catch {
        info("Could not parse port number.", .{});
        return;
    };

    info("Using port: {}", .{port});

    var server = net.StreamServer.init(.{});
    defer server.deinit();

    const address = net.Address.parseIp("127.0.0.1", port) catch unreachable;
    try server.listen(address);

    info("Server listening on {s}", .{address});

    var clients = std.AutoHashMap(*Client, void).init(allocator);
    defer clients.deinit();
    var room = Room{ .clients = clients };

    while (true) {
        const client = try allocator.create(Client);
        client.* = Client{
            .connection = try server.accept(),
            .handle_frame = async client.handle(&room),
        };

        try room.clients.putNoClobber(client, {});
    }

    // TODO close connections
    info("Bye.", .{});
}