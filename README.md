# 1A 网络嗅探器 / 协议分析器

当前进度：**M5 文件与统计**。在 M4 的 HTTP/DNS/TLS 识别基础上，已加入经典 pcap 保存/打开、协议分布与包速率图表，以及 200,000 包缓存上限。保存支持全部包和当前显示过滤结果，写出标准 pcap，可直接用 Wireshark 打开；打开文件时复用同一套解析和显示过滤逻辑，标题显示文件名并进入离线状态。TCP/UDP 归流、进程映射和流时序视图在 M6 实现。

## 环境

- Windows 10/11
- Python 3.11
- Npcap 1.90（安装时勾选 WinPcap 兼容模式）
- `pip install -r requirements.txt`

## 运行

```bat
python main.py
```

或双击 `run.bat`。

## M5 文件与统计

- 「打开 pcap」读取经典 pcap（支持大小端、微秒/纳秒时间戳）；标题显示文件名，底部状态栏进入离线状态。
- 「保存全部」导出当前列表，「保存显示结果」导出当前显示过滤后的包，均为标准 pcap，可直接用 Wireshark 打开。
- 底部 `[计数]` 显示抓包/列表/显示包数与丢包；`[统计图表]` 显示协议分布柱状图和最近 60 秒包速率曲线。
- 缓存上限 200,000 包；达到上限后停止插入新行但仍继续统计，清空列表可恢复实时抓包。

## 测试

```bat
python -m unittest discover -s tests -v
```

测试包含六部分：`test_pcap_driver.py` 枚举网卡、在回环上发本地流量并验证 BPF 过滤；`test_dissector.py` 用构造帧和随机畸形帧验证 IPv4/IPv6/ARP/TCP/UDP/ICMP、VLAN、回环链路类型及字段偏移；`test_filtering.py` 覆盖显示过滤语法、优先级、别名、端口/IP 条件和错误位置；`test_app_protocols.py` 覆盖 HTTP/DNS/TLS 的识别、字段、压缩指针、TCP 长度前缀、SNI/ALPN/supported_versions、GREASE 过滤和畸形载荷；`test_pcap_io.py` 覆盖 pcap 往返、大小端/纳秒时间戳、截断文件、混合 linktype 和缓存上限；`test_stats.py` 覆盖协议计数、字节数、速率分桶与滑动窗口。
