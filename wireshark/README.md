# LAB1A Wireshark 插件

本目录是 1A 实验的 Wireshark 二次开发部分，目标环境为 Wireshark 4.6.9 / Lua 5.4。

- `lab1a.lua`：LAB1A 协议解析器、专家信息、GUI 流统计菜单。
- `lab1a_stats.lua`：无 GUI 环境下的流统计脚本，供 tshark 使用。
- `lab1a_colorfilters`：按请求/应答/心跳着色的规则文件。

## 协议格式

TCP/UDP 端口 9999，网络字节序，固定 10 字节头部：

| 偏移 | 长度 | 字段 | 说明 |
| ---: | ---: | --- | --- |
| 0 | 4 | magic | 固定 ASCII `L1A1` |
| 4 | 1 | version | 当前为 1 |
| 5 | 1 | msg_type | 1=请求，2=应答，3=心跳 |
| 6 | 2 | seq | uint16 序号 |
| 8 | 2 | length | 载荷长度 |
| 10 | length | payload | 载荷 |

插件注册的字段为 `lab1a.magic`、`lab1a.version`、`lab1a.msg_type`、`lab1a.seq`、`lab1a.length`、`lab1a.payload`，可直接用于显示过滤，例如：

```text
lab1a.msg_type == 1
lab1a.seq == 7
lab1a.payload contains 47:45:54
```

## 安装到 Wireshark GUI

也可以直接运行 `wireshark\install.bat`，它会复制 `lab1a.lua` 并提示着色规则导入位置。手动安装步骤：

1. 关闭 Wireshark。
2. 把 `lab1a.lua` 复制到个人 Lua 插件目录：

   ```bat
   mkdir "%APPDATA%\Wireshark\plugins" 2>nul
   copy wireshark\lab1a.lua "%APPDATA%\Wireshark\plugins\"
   ```

3. 启动 Wireshark。加载抓包文件后，端口 9999 的 TCP/UDP 载荷会显示为 `LAB1A`。
4. 统计菜单：`Tools -> LAB1A -> 流统计`，窗口按 `tcp.stream` 显示包数、字节数、首末时间以及请求/应答/心跳计数。
5. 着色规则：`View -> Coloring Rules... -> Import`，选择 `wireshark/lab1a_colorfilters`。也可以把这些行追加到 `%APPDATA%\Wireshark\colorfilters`；如果该文件已存在，不要直接覆盖。

如果端口 9999 被其他协议占用，先在 `Analyze -> Decode As...` 里把 TCP/UDP 9999 指定为 LAB1A，或修改 `lab1a.lua` 末尾的端口注册。

## tshark 验收

在仓库根目录执行（把 `demo.pcap` 换成实际抓包文件）：

```bat
"C:\Program Files\Wireshark\tshark.exe" ^
  -X lua_script:wireshark/lab1a.lua ^
  -r demo.pcap -Y lab1a -V
```

只看字段：

```bat
"C:\Program Files\Wireshark\tshark.exe" ^
  -X lua_script:wireshark/lab1a.lua ^
  -r demo.pcap -Y lab1a ^
  -T fields -e frame.number -e tcp.stream -e lab1a.msg_type -e lab1a.seq -e lab1a.length
```

流统计（必须同时加载两个脚本）：

```bat
"C:\Program Files\Wireshark\tshark.exe" ^
  -X lua_script:wireshark/lab1a.lua ^
  -X lua_script:wireshark/lab1a_stats.lua ^
  -r demo.pcap
```

单包详情里应能看到协议树 `LAB1A 实验协议`，以及魔数、版本、消息类型、序号、载荷长度、载荷；畸形包会带专家信息。

## 生成演示流量

### 实时流量

先启动抓包（本实验嗅探器选择 loopback/Npcap Loopback Adapter，过滤 `tcp port 9999`），再运行：

```bat
python tools/lab1a_demo.py --rounds 5
```

脚本会在 `127.0.0.1:9999` 起一个临时 TCP 服务，发送请求、应答和心跳，抓包文件可直接用本插件打开。

### 可重复的离线 pcap

```bat
python tools/make_lab1a_pcap.py --out _setup/lab1a_demo.pcap
```

生成的 pcap 包含两条 TCP 流、UDP 请求/应答，以及魔数错误、未知类型、长度不符、头部过短四类畸形报文，适合报告截图和自动化测试。

## 验证要点

- `-Y lab1a` 能筛出 LAB1A 报文。
- `-Y 'lab1a.msg_type == 1'` 只保留请求。
- `-Y 'lab1a.bad_magic || lab1a.unknown_type || lab1a.length_mismatch || lab1a.short_header'` 能筛出四类专家信息。
- `lab1a_stats.lua` 输出每个 `tcp.stream` 的包数、字节数和首末时间。
- GUI 中协议列显示 `LAB1A`，`Tools -> LAB1A -> 流统计` 可打开统计窗口。
