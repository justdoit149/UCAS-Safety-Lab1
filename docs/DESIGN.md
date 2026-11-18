# 1A 网络嗅探器 / 协议分析器 设计说明

本文是实现的唯一设计依据。代码按第 12 节的里程碑逐步落地，每个里程碑单独提交、单独验收；未确认的设计点不提前写代码。

## 1. 目标与评分映射

实验要求把系统分成两层：

- NPS（Network Packet Sniffer）：从网卡抓取原始数据帧，能选网卡、开始/停止、统计收包与丢包。这是硬性要求，缺了直接不合格。
- NPA（Network Protocol Analyzer）：把原始帧逐层解析成可读字段，提供协议过滤、三栏界面、流追踪等分析能力。NPA 的完整度决定分数上限。

本实现对应的能力：

| 要求 | 实现方式 |
|---|---|
| NPS 抓包 | ctypes 直接调用 Npcap 的 `wpcap.dll`，走 libpcap API |
| 网卡选择 | `pcap_findalldevs` 枚举，界面标注回环/虚拟网卡 |
| 协议解析 | 自研 L2–L7 解析器，不依赖 scapy/tshark |
| 协议过滤逻辑 | 内核 BPF 抓包过滤 + 用户态显示过滤表达式 |
| GUI | PySide6 三栏布局：包列表 / 字段树 / 十六进制 |
| 加分：TCP 流追踪 | 五元组归并流、TCP 状态机、流表 |
| 加分：按进程归流 | psutil 把本地端点映射到 PID/进程名 |
| 加分：Wireshark 二次开发 | Lua 插件（自定义协议/字段着色/统计） |

运行平台：Windows 11 + Python 3.11 + PySide6 6.4.3 + Npcap 1.90。抓包依赖 Npcap 驱动，程序启动时检测并给出明确提示。

## 2. 总体架构

```
┌─────────────────────────────────────────────────────┐
│ UI 层（PySide6，主线程）                             │
│  MainWindow / PacketModel / DetailView / HexView     │
│  FlowModel / StatsView / FilterBar                   │
├─────────────────────────────────────────────────────┤
│ 应用服务层                                           │
│  CaptureController（生命周期）                       │
│  FlowManager（归流/状态机）                          │
│  ProcessMapper（进程映射）                           │
│  StatsCollector（统计）                              │
│  DisplayFilter（显示过滤表达式）                     │
├─────────────────────────────────────────────────────┤
│ 核心层                                               │
│  PcapDriver（ctypes 封装 wpcap.dll）                 │
│  Dissector（L2–L7 解析）                             │
│  PcapIO（pcap 文件读写）                             │
├─────────────────────────────────────────────────────┤
│ 系统层                                               │
│  Npcap 驱动 + 内核 BPF；psutil；文件系统             │
└─────────────────────────────────────────────────────┘
```

数据流：

```
网卡 → wpcap.dll → 原始帧(bytes) → Dissector → Packet
                                     ├→ PacketTableModel（批量插入）
                                     ├→ FlowManager（更新流表）
                                     ├→ StatsCollector（计数）
                                     └→ PcapWriter（可选落盘）
```

线程模型：

- 抓包线程 `CaptureWorker(QThread)` 持有 `PcapHandle`，循环 `pcap_next_ex`，在本线程完成解析，按 128 包或 100 ms 批量发信号给 UI。
- UI 线程只做模型插入和绘制，不做阻塞 IO。
- 停止抓包时 UI 置停止标志，抓包线程在 50 ms 超时内退出循环并 `pcap_close`，避免跨线程关闭句柄。
- 进程映射在后台定时刷新（默认 3 s），结果以快照方式交给 UI。

## 3. 目录结构

```
山雨冬_202628014629002_ex1A_src/
├── main.py
├── requirements.txt
├── run.bat
├── README.md
├── docs/
│   └── DESIGN.md
├── app/
│   ├── __init__.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── pcap_driver.py     # ctypes 封装
│   │   ├── models.py          # Packet/Field/Layer/Flow 数据类
│   │   ├── dissector.py       # 协议解析
│   │   └── pcap_io.py         # pcap 文件读写
│   ├── services/
│   │   ├── __init__.py
│   │   ├── capture.py         # CaptureWorker
│   │   ├── display_filter.py  # 显示过滤表达式
│   │   ├── flows.py           # FlowManager
│   │   ├── process_map.py     # 进程映射
│   │   └── stats.py           # 统计
│   └── ui/
│       ├── __init__.py
│       ├── main_window.py
│       ├── packet_model.py
│       ├── detail_view.py
│       ├── hex_view.py
│       ├── flow_model.py
│       ├── stats_view.py
│       └── theme.py
└── tests/
    ├── test_dissector.py
    ├── test_display_filter.py
    └── test_flows.py
```

## 4. 数据模型

### 4.1 字段与层

```python
@dataclass
class Field:
    name: str          # 显示名，如 "Source Port"
    value: str         # 已格式化的值，如 "52344"
    offset: int        # 相对帧首的字节偏移，用于十六进制高亮
    length: int        # 字节长度
    children: list["Field"] = field(default_factory=list)

@dataclass
class Layer:
    name: str          # "Ethernet" / "IPv4" / "TCP" / "HTTP"
    fields: list[Field]
    offset: int
    length: int
```

字段树用 `QTreeWidget` 展示，`offset/length` 让选中字段时十六进制视图高亮对应字节。

### 4.2 Packet

```python
@dataclass
class Packet:
    index: int                 # 全局包序号，从 1 开始
    ts: float                  # 秒级浮点时间戳
    caplen: int                # 抓到的长度
    orig_len: int             # 原始帧长度
    raw: bytes                 # 原始帧（snaplen 截断）
    linktype: int
    layers: list[Layer]
    src: str = ""              # 链路层源地址（MAC）
    dst: str = ""
    ip_src: str = ""
    ip_dst: str = ""
    sport: int = 0
    dport: int = 0
    transport: str = ""        # "TCP"/"UDP"/"ICMP"/""
    proto_label: str = ""      # 列表 Protocol 列，最高层能识别的协议
    summary: str = ""          # Info 列
    tcp_flags: str = ""        # "SYN,ACK"
    app: str = ""              # "HTTP"/"DNS"/"TLS"
    flow_key: tuple | None = None
    truncated: bool = False    # 抓包截断或解析不完整
```

`proto_label` 取最高可见层（如 HTTP over TCP over IPv4 显示 HTTP）；`summary` 生成 Wireshark 风格的摘要。

### 4.3 Flow

```python
@dataclass
class Flow:
    key: tuple                 # 规范化五元组
    proto: str                 # TCP/UDP
    endpoint_a: tuple          # (ip, port)，首包发送方
    endpoint_b: tuple
    packets: int
    bytes: int
    first_ts: float
    last_ts: float
    initiator: tuple           # 首包方向
    state: str                 # NEW/SYN_SENT/SYN_RCVD/ESTABLISHED/...
    closed: bool
    app: str
    syn_count: int
    fin_count: int
    rst_count: int
    pid: int | None = None
    process_name: str = ""
```

五元组规范化：对两端 `(ip, port)` 打包比较排序，保证双向包落到同一条流；`initiator` 保留首包方向，用于展示 `A → B`。

## 5. 抓包层（PcapDriver）

### 5.1 库加载

按顺序尝试：

1. `C:\Windows\System32\Npcap\wpcap.dll`（Npcap 默认位置）
2. `wpcap.dll`（PATH）
3. `C:\Windows\System32\wpcap.dll`（旧 WinPcap 安装方式）

全部失败时抛 `NpcapNotFoundError`，UI 显示安装提示而不是崩溃。

### 5.2 需要声明的 libpcap 函数

```c
int     pcap_findalldevs(pcap_if_t **alldevs, char *errbuf);
void    pcap_freealldevs(pcap_if_t *alldevs);
pcap_t *pcap_open_live(const char *device, int snaplen, int promisc,
                       int to_ms, char *errbuf);
pcap_t *pcap_open_offline(const char *fname, char *errbuf);
int     pcap_datalink(pcap_t *p);
int     pcap_compile(pcap_t *p, struct bpf_program *fp, const char *str,
                     int optimize, bpf_u_int32 netmask);
int     pcap_setfilter(pcap_t *p, struct bpf_program *fp);
void    pcap_freecode(struct bpf_program *fp);
int     pcap_next_ex(pcap_t *p, struct pcap_pkthdr **hdr,
                     const u_char **data);
int     pcap_stats(pcap_t *p, struct pcap_stat *ps);
void    pcap_close(pcap_t *p);
const char *pcap_lib_version(void);
```

结构体：`pcap_if`、`pcap_addr`、`timeval`、`pcap_pkthdr`、`bpf_program`、`pcap_stat`。所有函数显式设置 `argtypes/restype`，避免 64 位指针截断。

### 5.3 设备枚举

`Device` 数据类保存 `name`（`\Device\NPF_{GUID}`）、`description`、`flags`、`addresses`。

- `PCAP_IF_LOOPBACK` 标记回环；名字含 `NPF_Loopback` 也视为回环。
- 描述含 VMware/VirtualBox/TAP/aTrust 等关键字标记为虚拟网卡，下拉框中显示 `[虚拟]` 前缀但不禁用。
- 默认选择第一块非回环、非虚拟且已启用的网卡。

### 5.4 打开与读取

- `snaplen = 262144`，`promisc = 1`，`timeout_ms = 50`。
- `next_packet()` 返回 `(ts, caplen, orig_len, raw)`；返回码 0 表示超时，-1 表示错误，-2 表示 EOF（离线文件）。
- `raw` 用 `ctypes.string_at(ptr, caplen)` 拷贝，不持有驱动缓冲。
- `set_filter(expr)`：先 `pcap_compile` 再 `pcap_setfilter`，失败返回驱动错误文本，由 UI 提示，不静默忽略。
- `stats()` 读取 `ps_recv/ps_drop/ps_ifdrop`。

### 5.5 链路类型适配

解析前读取 `pcap_datalink()`：

- `DLT_EN10MB = 1`：以太网，14 字节头；识别 802.1Q（`0x8100`/`0x88a8`）VLAN 标签并继续。
- `DLT_NULL = 0`：Windows 回环，前 4 字节为地址族（小端：2=IPv4，23/24/28/30=IPv6），IP 头从偏移 4 开始。
- `DLT_RAW = 12`（Windows 上部分虚拟网卡）：直接是 IP 头。
- 其他类型：只展示原始字节并标注不支持的链路类型，不崩溃。

## 6. 解析层（Dissector）

解析原则：

1. 所有读取先做边界检查，任何长度不足都返回已解析部分并置 `truncated=True`，绝不抛异常到抓包线程。
2. 每个字段记录相对帧首的绝对偏移，供十六进制高亮。
3. 只在完整包上解析传输层以上内容；IP 分片仅首片解析 L4，后续分片标注 `IPv4 Fragment`。

### 6.1 以太网

字段：目的 MAC、源 MAC、类型/长度。类型 `0x0800`→IPv4，`0x86DD`→IPv6，`0x0806`→ARP，`0x8100`→VLAN。

### 6.2 ARP

字段：硬件类型、协议类型、硬件/协议长度、操作码（Request/Reply）、发送方 MAC/IP、目标 MAC/IP。摘要：`Who has 192.168.1.1? Tell 192.168.1.2`。

### 6.3 IPv4

字段：版本、首部长度、DSCP/ECN、总长度、标识、标志（DF/MF）、分片偏移、TTL、协议、首部校验和、源/目的地址、选项。协议号映射：1=ICMP，6=TCP，17=UDP，其他显示数字。

### 6.4 IPv6

固定 40 字节头：版本、流量类别、流标签、载荷长度、下一个头、跳数限制、源/目的地址。依次遍历扩展头：Hop-by-Hop(0)、Routing(43)、Fragment(44)、Destination Options(60)，直到 TCP(6)/UDP(17)/ICMPv6(58)。扩展头在字段树中单列。

### 6.5 TCP

字段：源端口、目的端口、序号、确认号、数据偏移、保留位、标志（NS/CWR/ECE/URG/ACK/PSH/RST/SYN/FIN）、窗口、校验和、紧急指针、选项（MSS、窗口缩放、SACK、时间戳）。标志格式化为 `SYN,ACK`。

### 6.6 UDP

字段：源端口、目的端口、长度、校验和。

### 6.7 ICMP / ICMPv6

字段：类型、代码、校验和；Echo Request/Reply 额外解析标识符与序号；ICMPv6 解析 NS/NA/RS/RA 的类型与目标地址。摘要：`Echo (ping) request  id=0x0001, seq=1/256`。

### 6.8 应用层识别

识别顺序：端口表 → 载荷特征 → 默认按传输层显示。

- HTTP：端口 80/8080/8000/8888 或载荷以请求方法/`HTTP/` 开头。解析请求行/状态行、头部字典、`Host`、`User-Agent`、`Content-Type`、`Content-Length`；摘要 `GET /index.html HTTP/1.1` 或 `HTTP/1.1 200 OK`。
- DNS：端口 53（UDP/TCP）。解析头部（ID、QR、Opcode、RD、RA、RCODE、QD/AN 计数）、问题名（支持压缩指针 0xC0）、类型、应答记录 A/AAAA/CNAME。摘要 `Standard query 0x1a2b A example.com`。
- TLS：端口 443/8443 或记录类型 20–23。解析记录层 Content Type/Version/Length；Handshake 为 ClientHello 时解析版本、随机数、Session ID、Cipher Suites、扩展；提取 SNI、ALPN、supported_versions（过滤 GREASE：高字节等于低字节且低 4 位为 0xA 的值）。摘要 `Client Hello (SNI=www.example.com)`。

不做 TCP 流重组（不跨包拼接 HTTP 正文），在报告中明确为设计取舍；单包内可解析的头部与载荷足够满足实验要求。

## 7. 过滤设计

分两层，职责不同：

### 7.1 抓包过滤（内核 BPF）

- 开始抓包前把表达式交给 `pcap_compile` + `pcap_setfilter`，由内核执行，性能最好。
- UI 提供下拉框（可编辑）+ 常用预设：`tcp`、`udp`、`icmp`、`ip`、`ipv6`、`arp`、`tcp port 80`、`tcp port 443`、`udp port 53`、`host 192.168.1.1`。
- 表达式非法时显示驱动返回的错误，不开始抓包。
- 抓包过程中修改过滤条件需要重新打开网卡（M3 先要求停止后修改，M6 再评估热切换）。

### 7.2 显示过滤（用户态表达式）

对已抓到的包做二次筛选，不丢包。支持的最小语法：

```
expr    := or_expr
or_expr := and_expr ("or" and_expr)*
and_expr:= not_expr ("and" not_expr)*
not_expr:= "not" not_expr | primary
primary := "(" expr ")" | predicate
predicate := proto | "port" NUMBER | "host" IP
           | ("src"|"dst") ("port" NUMBER | "host" IP)
proto   := "tcp" | "udp" | "icmp" | "icmp6" | "ip" | "ipv6"
         | "arp" | "http" | "dns" | "tls"
```

实现为词法分析 + 递归下降，编译成谓词函数（`Packet -> bool`），由 `QSortFilterProxyModel` 调用。非法表达式在输入框标红并显示错误位置。

预设按钮与抓包过滤一致，另加 `http`、`dns`、`tls`。

## 8. 流追踪与进程映射

### 8.1 归流

- TCP/UDP 都用 `(proto, ip_a, port_a, ip_b, port_b)` 规范化键。
- IP 用 `ipaddress.ip_address(...).packed` 比较，保证 IPv6 文本形式不同也能归到同一流。
- 每条流维护包数、字节数（用 `orig_len`）、首末时间、应用层协议、TCP 标志计数。
- TCP 状态机：
  - 无 SYN 的单向包 → `NEW`
  - SYN → `SYN_SENT`
  - SYN+ACK → `SYN_RCVD`
  - ACK → `ESTABLISHED`
  - FIN → `FIN_WAIT`，双向 FIN 或收到 RST → `CLOSED`
  - 只做启发式展示，不追求完整 RFC 状态机。
- 流表按最近活跃时间排序；超过 2 分钟无包的非 TCP 流可标记 `EXPIRED`。

### 8.2 进程映射

- 后台每 3 s 调 `psutil.net_connections(kind="tcp")`，建立 `(ip, port) -> (pid, name)` 快照。
- 一个本地端口可能对应监听 socket 和已建立连接，优先取状态为 `ESTABLISHED` 的记录。
- 流的两个端点分别查表；命中本地端点的记为 `pid/process`，都未命中显示 `-`（混杂模式抓到其他主机流量时正常）。
- 无权限读取某进程时跳过该条，不中断刷新。
- 流表增加「进程」列；双击某进程/流可筛选出该流的所有包；提供「按进程筛选」把所有属于该 PID 的 TCP 流列出来（加分项要求）。

## 9. 文件存储

### 9.1 保存

- 标准 pcap 格式：24 字节全局头 `<IHHiIII>`（magic `0xA1B2C3D4`、主次版本 2.4、时区 0、时间戳精度 0、snaplen、linktype），每包 16 字节记录头 `<IIII>`（秒、微秒、caplen、orig_len）+ 原始字节。
- 只允许保存同一 linktype 的包；混合来源时提示并只保存当前设备/文件的包。
- 支持「保存全部」和「保存显示过滤结果」。

### 9.2 打开

- `pcap_open_offline` 读取，复用同一套解析、流追踪、过滤逻辑；界面标题显示文件名，状态栏显示 `离线`。
- 打开文件期间禁用开始抓包按钮。

## 10. 界面设计

三栏 + 底部选项卡：

```
┌ 工具栏：网卡▾ | 抓包过滤[____] | ●开始 ■停止 | 打开 保存 清空 | 显示过滤[____] ┐
├──────────────────────────── 包列表 ────────────────────────────────────────────┤
│ No. | Time | Source | Destination | Protocol | Length | Info                  │
├──────────────────────────────┬─────────────────────────────────────────────────┤
│ 字段树（可展开）              │ 十六进制 + ASCII，选中字段高亮                  │
├──────────────────────────────┴─────────────────────────────────────────────────┤
│ [流表] [统计]                                                                  │
└ 状态栏：已抓 N 包 | 显示 M 包 | 丢包 D | 状态：抓包中/已停止/离线               ┘
```

- 包列表用 `QAbstractTableModel` + `QSortFilterProxyModel`；批量插入用 `beginInsertRows/endInsertRows`。
- 字段树用 `QTreeWidget`，双击字段联动十六进制高亮；选中包时重建树。
- 十六进制视图自绘：偏移列、16 字节十六进制、ASCII；高亮当前字段区间。
- 流表列：协议、源、目的、状态、包数、字节、时长、进程、应用。
- 统计页：协议分布柱状图、包速率曲线（pyqtgraph），以及收包/丢包计数。
- 状态栏实时刷新；界面使用深色主题，抓包中「开始」禁用、「停止」启用。
- 关闭窗口时先停止抓包线程并等待退出，避免 Qt 报线程未结束。

## 11. 错误处理与性能

- Npcap 未安装/驱动未启动：启动时检测，弹窗给出安装说明，NPS 功能禁用但界面可打开。
- 无管理员权限：Npcap 已配置 `restrict_access=no`，普通用户可抓包；若打开失败，提示以管理员运行。
- 网卡被拔出/驱动错误：抓包线程发 `error` 信号，UI 停止并保留已抓数据。
- 单包解析异常：捕获异常，生成只含链路层和原始字节的 Packet，标记 `truncated`。
- 包缓存上限默认 200,000 条；超过后停止插入并提示，防止内存无限增长。
- 批量刷新（128 包/100 ms）避免逐包刷新表格造成卡顿。

## 12. 里程碑与验收标准

| 里程碑 | 内容 | 验收标准 |
|---|---|---|
| M1 | 项目骨架、依赖、Npcap 检测、网卡枚举、开始/停止、原始包计数 | 启动程序能列出网卡；选中网卡开始后计数增长、停止后不再增长；UI 不卡死；错误有提示 |
| M2 | 链路层适配、IPv4/IPv6/ARP/TCP/UDP/ICMP 解析、三栏界面、十六进制联动 | WLAN 与回环都能解析；包列表协议/摘要正确；字段树与十六进制偏移一致；畸形包不崩溃 |
| M3 | 抓包过滤 + 显示过滤表达式 + 预设 | 非法表达式有错误提示；`tcp and port 80` 等组合生效；显示过滤只影响列表不丢包 |
| M4 | HTTP/DNS/TLS 识别与字段解析 | 回环 HTTP 请求可读；DNS 查询/应答可读；HTTPS ClientHello 能取到 SNI 与 TLS 版本 |
| M5 | TCP/UDP 归流、流表、TCP 状态、进程映射 | 双向包归入同一流；状态随握手/挥手变化；流表显示进程名；可按进程筛选全部 TCP 流 |
| M6 | pcap 保存/打开、统计图表、性能与内存上限、打包 | 保存文件可用 Wireshark 打开且包数一致；打开后解析一致；1000+ 包/秒 UI 可用 |
| M7 | Wireshark Lua 插件、PyInstaller 打包、报告与演示脚本 | 插件在 Wireshark 中加载并生效；打包程序在无 Python 环境可运行（需 Npcap）；报告含仓库链接 |

每个里程碑完成后：运行对应测试 → 更新 README/设计文档 → 单独 commit，提交信息写清功能范围。M1 之前不写 M2 的代码。

## 13. 测试策略

- 单元测试（pytest）：
  - 用构造字节测试 IPv4 选项、IPv6 扩展头、TCP 选项、畸形/截断包。
  - 显示过滤：合法/非法表达式、优先级、括号、`not`。
  - 流状态机：SYN/SYN-ACK/ACK/FIN/RST 序列。
- 集成测试：
  - 本机起 `http.server`，curl 访问回环，验证 HTTP 解析与归流。
  - `ping 127.0.0.1` 验证 ICMP。
  - `nslookup` 验证 DNS。
  - 访问 HTTPS 站点验证 SNI。
- 手工验收：按第 12 节里程碑表逐项过。
- 性能：WLAN 抓 10 秒统计包数/丢包，确认 UI 可操作。

## 14. Git 规范

- 每个里程碑一个或多个提交，提交信息用 `feat:` / `fix:` / `docs:` / `test:` 前缀，中文描述。
- 不提交 `__pycache__`、虚拟环境、抓包文件、构建产物（见 `.gitignore`）。
- 最终把仓库地址写进报告；提交历史需完整体现开发过程。

## 15. 已知取舍与风险

- 不做 TCP 流重组：HTTP 分块、TLS 多记录跨包场景只解析单包可见部分；报告中说明。
- WLAN 混杂模式在部分驱动上只收到本机流量；验收以实际可抓到的流量为准。
- 进程映射依赖 psutil 权限，系统进程可能读不到；界面显示 `-` 并说明原因。
- PyInstaller 不打包 Npcap 驱动（许可证与驱动安装限制），发行说明要求用户先安装 Npcap。
- IPv6 扩展头顺序与分片组合是解析器最易出错处，用构造用例覆盖。
