# 1A 网络嗅探器 / 协议分析器

当前进度：**M1 抓包骨架**。本阶段只验证 Npcap 抓包、网卡枚举和原始帧计数；协议解析、三栏界面、过滤与流追踪在后续里程碑实现。

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

测试会枚举网卡，并在回环网卡上发一段本地 TCP 流量，验证能读到原始帧和驱动统计。
