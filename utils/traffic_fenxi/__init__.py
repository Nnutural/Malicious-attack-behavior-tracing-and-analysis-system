"""
网络流量分析模块（traffic_fenxi）

说明：
- 离线上传解析 pcap/pcapng 入库
- 在线抓包（start/stop）流式入库
- 可选：会话重建、异常检测、隐蔽信道检测

该模块被 Flask 蓝图 traffic_view.py 调用。
"""