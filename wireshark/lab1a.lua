-- LAB1A Wireshark dissector (Wireshark 4.6.x / Lua 5.4).
--
-- Wire format (network byte order, 10-byte header):
--   offset 0  magic       4 bytes  "L1A1"
--   offset 4  version     1 byte   currently 1
--   offset 5  msg_type    1 byte   1=request, 2=response, 3=heartbeat
--   offset 6  seq         2 bytes  uint16
--   offset 8  payload_len 2 bytes  uint16
--   offset 10 payload     payload_len bytes
--
-- Load from the command line with:
--   tshark -X lua_script:wireshark/lab1a.lua -r demo.pcap -V
-- or copy this file to %APPDATA%\Wireshark\plugins\ and restart Wireshark.

-- Loading the plugin both from the personal plugin directory and via
-- -X lua_script: would register the same protocol twice.  Treat the second
-- load as a no-op so the command-line tests work on an installed copy too.
local proto_ok, p_lab1a = pcall(Proto, "lab1a", "LAB1A 实验协议")
if not proto_ok then
    return
end

local TYPE_NAMES = {
    [1] = "请求",
    [2] = "应答",
    [3] = "心跳",
}

local f_magic = ProtoField.string("lab1a.magic", "魔数")
local f_version = ProtoField.uint8("lab1a.version", "版本", base.DEC)
local f_msg_type = ProtoField.uint8(
    "lab1a.msg_type", "消息类型", base.DEC, TYPE_NAMES
)
local f_seq = ProtoField.uint16("lab1a.seq", "序号", base.DEC)
local f_length = ProtoField.uint16("lab1a.length", "载荷长度", base.DEC)
local f_payload = ProtoField.bytes("lab1a.payload", "载荷")

p_lab1a.fields = {
    f_magic,
    f_version,
    f_msg_type,
    f_seq,
    f_length,
    f_payload,
}

local e_short_header = ProtoExpert.new(
    "lab1a.short_header",
    "LAB1A 头部不足 10 字节",
    expert.group.MALFORMED,
    expert.severity.ERROR
)
local e_bad_magic = ProtoExpert.new(
    "lab1a.bad_magic",
    "LAB1A 魔数不是 L1A1",
    expert.group.MALFORMED,
    expert.severity.ERROR
)
local e_bad_version = ProtoExpert.new(
    "lab1a.bad_version",
    "LAB1A 版本不是 1",
    expert.group.PROTOCOL,
    expert.severity.WARN
)
local e_unknown_type = ProtoExpert.new(
    "lab1a.unknown_type",
    "LAB1A 消息类型未知",
    expert.group.PROTOCOL,
    expert.severity.WARN
)
local e_length_mismatch = ProtoExpert.new(
    "lab1a.length_mismatch",
    "LAB1A 载荷长度与头部声明不符",
    expert.group.MALFORMED,
    expert.severity.ERROR
)
local e_trailing_data = ProtoExpert.new(
    "lab1a.trailing_data",
    "LAB1A 载荷之后还有多余字节",
    expert.group.MALFORMED,
    expert.severity.WARN
)

p_lab1a.experts = {
    e_short_header,
    e_bad_magic,
    e_bad_version,
    e_unknown_type,
    e_length_mismatch,
    e_trailing_data,
}

-- Add a compact final summary to the packet list.  The text is deliberately
-- ASCII-safe for the protocol column; Chinese details live in the tree.
local function set_info(pinfo, text)
    pinfo.cols.protocol = "LAB1A"
    pinfo.cols.info = text
end

function p_lab1a.dissector(buffer, pinfo, tree)
    local length = buffer:len()
    local subtree = tree:add(p_lab1a, buffer(), "LAB1A 实验协议")

    if length < 4 then
        set_info(pinfo, "头部过短")
        if length > 0 then
            subtree:add(buffer(0, length), "原始数据")
        end
        subtree:add_proto_expert_info(e_short_header)
        return
    end

    local magic = buffer(0, 4):string()
    subtree:add(f_magic, buffer(0, 4))
    if magic ~= "L1A1" then
        set_info(pinfo, "魔数错误")
        subtree:add_proto_expert_info(e_bad_magic)
        if length > 4 then
            subtree:add(buffer(4, length - 4), "原始数据")
        end
        return
    end

    if length < 10 then
        set_info(pinfo, "头部过短")
        subtree:add_proto_expert_info(e_short_header)
        if length > 4 then
            subtree:add(buffer(4, length - 4), "原始数据")
        end
        return
    end

    local version = buffer(4, 1):uint()
    local msg_type = buffer(5, 1):uint()
    local seq = buffer(6, 2):uint()
    local declared = buffer(8, 2):uint()

    subtree:add(f_version, buffer(4, 1))
    subtree:add(f_msg_type, buffer(5, 1))
    subtree:add(f_seq, buffer(6, 2))
    subtree:add(f_length, buffer(8, 2))

    local actual = length - 10
    local type_name = TYPE_NAMES[msg_type]
    local info = string.format(
        "%s seq=%d len=%d",
        type_name or "未知类型",
        seq,
        declared
    )

    if version ~= 1 then
        subtree:add_proto_expert_info(e_bad_version)
        info = info .. " [版本=" .. tostring(version) .. "]"
    end
    if type_name == nil then
        subtree:add_proto_expert_info(e_unknown_type)
    end
    if declared > actual then
        subtree:add_proto_expert_info(e_length_mismatch)
        info = info .. " [长度不足]"
    elseif declared < actual then
        subtree:add_proto_expert_info(e_trailing_data)
        info = info .. " [尾部多余数据]"
    end

    if actual > 0 then
        subtree:add(f_payload, buffer(10, actual))
    end

    set_info(pinfo, info)
end

local tcp_port = DissectorTable.get("tcp.port")
if tcp_port then
    tcp_port:add(9999, p_lab1a)
end

local udp_port = DissectorTable.get("udp.port")
if udp_port then
    udp_port:add(9999, p_lab1a)
end

-- ---------------------------------------------------------------------------
-- GUI statistics: Tools -> LAB1A -> TCP 流统计
--
-- A Listener sees the current capture after Wireshark has dissected it, so
-- tcp.stream and the LAB1A fields are available.  The window is rebuilt from
-- the tap every time the listener redraws.
-- ---------------------------------------------------------------------------

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

local function show_stats_window()
    if not gui_enabled() then
        return
    end

    local window = TextWindow.new("LAB1A TCP 流统计")
    local stats = {}
    local tap = nil

    local f_stream = Field.new("tcp.stream")
    local f_time = Field.new("frame.time_epoch")
    local f_len = Field.new("frame.len")
    local f_type = Field.new("lab1a.msg_type")

    local function remove_tap()
        if tap then
            tap:remove()
            tap = nil
        end
    end

    window:set_atclose(remove_tap)

    tap = Listener.new("tcp", "lab1a")

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
        window:clear()
    end

    function tap.draw()
        window:clear()
        window:append(
            string.format(
                "%-8s %8s %10s %13s %13s %7s %7s %7s %7s\n",
                "TCP流", "包数", "字节", "首包时间", "末包时间",
                "请求", "应答", "心跳", "其他"
            )
        )
        window:append(string.rep("-", 92) .. "\n")

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
            window:append(
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
        window:append(string.rep("-", 92) .. "\n")
        window:append(
            string.format(
                "合计: %d 包, %d 字节, %d 条 TCP 流\n",
                total_packets,
                total_bytes,
                #keys
            )
        )
    end

    -- Replay the already loaded capture through the new listener.
    if retap_packets then
        retap_packets()
    end
end

-- Also expose the function for the Lua console and for GUI smoke tests.
lab1a_show_stats = show_stats_window

if gui_enabled() and register_menu then
    register_menu("LAB1A/流统计", show_stats_window, MENU_TOOLS_UNSORTED)
end
