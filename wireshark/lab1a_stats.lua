-- Command-line companion for lab1a.lua.
--
-- Load both scripts and let tshark replay the capture:
--
--   tshark -X lua_script:wireshark/lab1a.lua \
--          -X lua_script:wireshark/lab1a_stats.lua \
--          -r demo.pcap
--
-- The output is one row per tcp.stream with packet/byte counts, first/last
-- timestamps and LAB1A message-type counters.  This is the fallback for
-- Wireshark builds whose GUI menu API is unavailable.

local f_stream = Field.new("tcp.stream")
local f_time = Field.new("frame.time_epoch")
local f_len = Field.new("frame.len")
local f_type = Field.new("lab1a.msg_type")

local stats = {}

local function format_epoch(ts)
    if not ts or ts <= 0 then
        return "-"
    end
    local seconds = math.floor(ts)
    local millis = math.floor((ts - seconds) * 1000 + 0.5)
    if millis >= 1000 then
        seconds = seconds + 1
        millis = millis - 1000
    end
    return os.date("%H:%M:%S", seconds) .. string.format(".%03d", millis)
end

local tap = Listener.new("tcp", "lab1a")

function tap.packet(pinfo, tvb, tapdata)
    local stream_field = f_stream()
    if not stream_field then
        return
    end
    local stream = tostring(stream_field)
    local ts = tonumber(tostring(f_time())) or 0
    local bytes = tonumber(tostring(f_len())) or 0
    local msg_type = tonumber(tostring(f_type())) or 0

    local rec = stats[stream]
    if not rec then
        rec = {
            packets = 0,
            bytes = 0,
            first = ts,
            last = ts,
            request = 0,
            response = 0,
            heartbeat = 0,
            other = 0,
        }
        stats[stream] = rec
    end

    rec.packets = rec.packets + 1
    rec.bytes = rec.bytes + bytes
    if rec.first == 0 or (ts > 0 and ts < rec.first) then
        rec.first = ts
    end
    if ts > rec.last then
        rec.last = ts
    end

    if msg_type == 1 then
        rec.request = rec.request + 1
    elseif msg_type == 2 then
        rec.response = rec.response + 1
    elseif msg_type == 3 then
        rec.heartbeat = rec.heartbeat + 1
    else
        rec.other = rec.other + 1
    end
end

function tap.reset()
    stats = {}
end

function tap.draw()
    io.write(
        string.format(
            "%-8s %8s %10s %13s %13s %7s %7s %7s %7s\n",
            "TCP流", "包数", "字节", "首包时间", "末包时间",
            "请求", "应答", "心跳", "其他"
        )
    )
    io.write(string.rep("-", 92) .. "\n")

    local keys = {}
    for stream, _ in pairs(stats) do
        keys[#keys + 1] = stream
    end
    table.sort(keys, function(a, b)
        return (tonumber(a) or 0) < (tonumber(b) or 0)
    end)

    local total_packets = 0
    local total_bytes = 0
    for _, stream in ipairs(keys) do
        local rec = stats[stream]
        total_packets = total_packets + rec.packets
        total_bytes = total_bytes + rec.bytes
        io.write(
            string.format(
                "%-8s %8d %10d %13s %13s %7d %7d %7d %7d\n",
                stream,
                rec.packets,
                rec.bytes,
                format_epoch(rec.first),
                format_epoch(rec.last),
                rec.request,
                rec.response,
                rec.heartbeat,
                rec.other
            )
        )
    end
    io.write(string.rep("-", 92) .. "\n")
    io.write(
        string.format(
            "合计: %d 包, %d 字节, %d 条 TCP 流\n",
            total_packets,
            total_bytes,
            #keys
        )
    )
end

-- In tshark the listener sees packets as the file is read.  retap_packets()
-- is a GUI-only API; calling it from tshark raises "GUI not available".
if gui_enabled() and retap_packets then
    retap_packets()
end
