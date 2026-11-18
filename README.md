# 1A 网络嗅探器 / 协议分析器

当前进度：**M2 协议解析与三栏界面**。已支持以太网/VLAN/Windows 回环/裸 IP 链路层适配，IPv4、IPv6、ARP、TCP、UDP、ICMP/ICMPv6 解析，以及包列表、协议字段树和十六进制高亮联动；过滤、应用层协议识别、统计和 TCP 流追踪在后续里程碑实现。

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

测试包含两部分：`test_pcap_driver.py` 枚举网卡并在回环上发本地 TCP 流量，验证原始帧和驱动统计；`test_dissector.py` 用构造帧和随机畸形帧验证 IPv4/IPv6/ARP/TCP/UDP/ICMP、VLAN、回环链路类型及字段偏移。
