# 1A 网络嗅探器 / 协议分析器

当前进度：**M4 应用层识别**。在 M3 的内核 BPF 抓包过滤和显示过滤基础上，已加入 HTTP、DNS、TLS 的识别与字段解析：HTTP 请求行/状态行、头部与正文；DNS 头部、问题名、A/AAAA/CNAME 应答（支持压缩指针和 TCP 长度前缀）；TLS 记录层、ClientHello、SNI、ALPN、supported_versions（过滤 GREASE）。`Packet.app` 已填充，`http`/`https`/`dns`/`tls` 显示过滤现在可用。统计图表和 TCP 流追踪在后续里程碑实现。

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

## 测试

```bat
python -m unittest discover -s tests -v
```

测试包含四部分：`test_pcap_driver.py` 枚举网卡、在回环上发本地流量并验证 BPF 过滤；`test_dissector.py` 用构造帧和随机畸形帧验证 IPv4/IPv6/ARP/TCP/UDP/ICMP、VLAN、回环链路类型及字段偏移；`test_filtering.py` 覆盖显示过滤语法、优先级、别名、端口/IP 条件和错误位置；`test_app_protocols.py` 覆盖 HTTP/DNS/TLS 的识别、字段、压缩指针、TCP 长度前缀、SNI/ALPN/supported_versions、GREASE 过滤和畸形载荷。
