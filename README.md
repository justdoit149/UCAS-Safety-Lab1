# 1A 网络嗅探器 / 协议分析器

当前进度：**M7 Wireshark Lua 二次开发**。在 M6 的流跟踪与进程映射基础上，已实现自定义 LAB1A 协议解析器、专家信息、着色规则、按 `tcp.stream` 的流统计菜单，以及供 tshark 使用的命令行统计脚本。插件目标环境为 Wireshark 4.6.9 / Lua 5.4。

## 环境

- Windows 10/11
- Python 3.11
- Npcap 1.90（安装时勾选 WinPcap 兼容模式）
- Wireshark 4.6.9（仅 M7 插件验收需要，可选）
- `pip install -r requirements.txt`

## 运行

```bat
python main.py
```

或双击 `run.bat`。

## M7 Wireshark 二次开发

- `wireshark/lab1a.lua`：注册 TCP/UDP 9999 的 `LAB1A` 协议，解析魔数 `L1A1`、版本、消息类型（请求/应答/心跳）、序号、载荷长度和载荷；字段 `lab1a.magic`、`lab1a.version`、`lab1a.msg_type`、`lab1a.seq`、`lab1a.length`、`lab1a.payload` 可直接用于显示过滤。
- 专家信息：魔数错误、头部过短、长度与声明不符标为 error；未知版本、未知消息类型、尾部多余数据标为 warning。
- 着色规则：`wireshark/lab1a_colorfilters` 按请求/应答/心跳给包列表着色。
- 流统计：GUI `Tools -> LAB1A -> 流统计` 按 `tcp.stream` 汇总包数、字节数、首末时间和消息类型计数；无 GUI 时用 `wireshark/lab1a_stats.lua` 配合 tshark 输出同样的表。
- 演示：`tools/lab1a_demo.py` 在回环 9999 端口生成请求/应答/心跳；`tools/make_lab1a_pcap.py` 生成可重复的离线 pcap（含畸形报文）。
- 安装与 tshark 验收命令见 `wireshark/README.md`，也可运行 `wireshark/install.bat` 安装插件。

## M6 流跟踪与进程映射

- 底部 `[流表]`：TCP/UDP 按规范化五元组双向归并；TCP 状态从 SYN / SYN+ACK / ACK / FIN / RST 推导，UDP 空闲 120 秒标记过期。
- 流表列：协议、源、目的、状态、包数、字节、时长、应用、进程、最后活动；默认按最后活动倒序，可点表头排序。
- 选中流后，右侧显示该流的包时序（序号、相对时间、A→B/B→A、TCP 标志、长度、摘要）；双击时序行跳到包列表并高亮。
- 「显示所选流数据包」把包列表过滤到选中流；清除显示过滤恢复全部。
- 「按进程筛选 TCP」下拉框列出当前 TCP 流涉及的进程，选中后只显示该 PID 的全部 TCP 流；「刷新进程」手动更新 `psutil` 快照。
- 抓包期间每 3 秒自动刷新进程映射；普通用户可能读不到部分系统进程，界面显示 `-` 并保留错误提示。
- 包列表可选显示「进程」列（默认隐藏）；先查源端点、再查目的端点，请求与响应都能显示本地进程。

## M5 文件与统计

- 「打开 pcap」读取经典 pcap（支持大小端、微秒/纳秒时间戳）；标题显示文件名，底部状态栏进入离线状态。
- 「保存全部」导出当前列表，「保存显示结果」导出当前显示过滤后的包，均为标准 pcap，可直接用 Wireshark 打开。
- 底部 `[计数]` 显示抓包/列表/显示包数与丢包；`[统计图表]` 显示协议分布柱状图和最近 60 秒包速率曲线。
- 缓存上限 200,000 包；达到上限后停止插入新行但仍继续统计，清空列表可恢复实时抓包。

## 测试

```bat
python -m unittest discover -s tests -v
```

测试包含九部分：`test_pcap_driver.py` 枚举网卡、在回环上发本地流量并验证 BPF 过滤；`test_dissector.py` 用构造帧和随机畸形帧验证 IPv4/IPv6/ARP/TCP/UDP/ICMP、VLAN、回环链路类型及字段偏移；`test_filtering.py` 覆盖显示过滤语法、优先级、别名、端口/IP 条件和错误位置；`test_app_protocols.py` 覆盖 HTTP/DNS/TLS 的识别、字段、压缩指针、TCP 长度前缀、SNI/ALPN/supported_versions、GREASE 过滤和畸形载荷；`test_pcap_io.py` 覆盖 pcap 往返、大小端/纳秒时间戳、截断文件、混合 linktype 和缓存上限；`test_stats.py` 覆盖协议计数、字节数、速率分桶与滑动窗口；`test_flows.py` 覆盖双向归并、IPv6 规范化、TCP 状态机、UDP 过期、进程筛选与映射保留；`test_process_map.py` 用伪造连接验证 ESTABLISHED 优先、IPv6 压缩、权限异常回退和进程名缓存；`test_wireshark_plugin.py` 用 tshark 验证 LAB1A 协议树、显示过滤、专家信息和流统计脚本（未安装 tshark 时自动跳过）。
