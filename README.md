# 1A 网络嗅探器 / 协议分析器

当前进度：**M3 过滤**。在 M2 的链路/网络/传输层解析与三栏界面上，已加入内核 BPF 抓包过滤、显示过滤表达式（`and/or/not`、括号、`port`、`host`、`src/dst`）和常用预设；应用层协议识别、统计和 TCP 流追踪在后续里程碑实现。

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

测试包含三部分：`test_pcap_driver.py` 枚举网卡、在回环上发本地流量并验证 BPF 过滤；`test_dissector.py` 用构造帧和随机畸形帧验证 IPv4/IPv6/ARP/TCP/UDP/ICMP、VLAN、回环链路类型及字段偏移；`test_filtering.py` 覆盖显示过滤语法、优先级、别名、端口/IP 条件和错误位置。
