# 洛杉矶 DC03 协议测速

测试日期为 2026 年 11 月 25 日。共 22 种协议和传输配置、511 条记录，包含直连对照。所有组都使用 1 MiB 的不可压缩响应。原始 JSON 包含每次请求的状态、收到的字节数、首包时间和耗时。算法与复现步骤见 [README](README.md)。

- [各轮完整统计](results/summary.md)
- [公网主矩阵](results/overview.png)
- [原始样本](results/)

## 公网选型对照

首尔主测中，Hysteria 1 的 20 Mbps 配置和 Hysteria 2 Salamander 都完成了 6/6，吞吐中位数分别为 2.39 和 1.55 Mbps。同轮直连 2/6，TUIC BBR 5/6。Hysteria 2 默认、Hysteria 2 Brutal 和 TUIC CUBIC 在该组各为 0/6。

换一批临时端口补测后，Hysteria 1 继续完成 4/4，吞吐中位数 2.72 Mbps。Hysteria 2 默认和 Brutal 各完成 4/4，Salamander 转为 0/4，直连完成 4/4。复测同时更换了端口和测量时段，数据无法单独归因到端口、拥塞或协议参数。Hysteria 1 是这两批首尔样本中完成率最一致的配置。

桌面 TUN 主测中，Hysteria 1、Hysteria 2 Brutal 和 TUIC BBR 都达到 6/6，中位吞吐分别为 1.43、1.28 和 1.89 Mbps。TUIC BBR 的吞吐变异系数为 6.3%，首尔后续窗口为 0/4。Hysteria 1 在三个公网窗口合计 16/16，桌面组首包 P95 仍有 7.72 秒。高完成率与低首包波动是两个独立指标。

## 小众协议补测

| 配置 | 机内回环 | 公网记录 |
|---|---|---|
| XHTTP/TLS | 7/7，188.90 Mbps | 桌面 TUN 5/7，1.35 Mbps |
| VMess mKCP | 7/7，41.96 Mbps | 桌面 TUN 5/7，1.10 Mbps |
| Naïve H2 | 7/7，259.64 Mbps | 桌面 TUN 0/6，六次均收到部分响应。同窗口直连 0/6。 |
| Mieru TCP | 7/7，183.66 Mbps | 桌面 TUN 0/6。首尔 1/6，唯一完成样本 0.66 Mbps。 |
| Mieru UDP | 7/7，66.46 Mbps | 桌面 TUN 和首尔各 0/6，大多数请求收到了部分响应。 |
| ShadowTLS v3 | 首轮 SS2022 组合 0/7。保持连接和更换 SS AEAD 的对照仍提前断开。 | 详见公网主矩阵。 |

表中 Mbps 是完成样本的吞吐中位数。机内数值反映这台机器处理本地链路时的速度。XHTTP 和 mKCP 补测窗口的直连也只完成了 5/7。ShadowTLS 对照里，未套 ShadowTLS 的 SS2022 和 SS AEAD 均通过 7/7。ShadowTLS 的结论只适用于此处的 sing-box 构建和两套串联配置。

## 测试边界

每组样本覆盖本晚的有限窗口。不同组的背景流量与接入拥塞会变化，公网结果也依赖实际路径及随机高位端口。几组公网直连本身未在时限内完成，因此把同窗口直连和部分下载都保留。测试环境修正与剔除规则见 [协议调研](RESEARCH.md#测试环境预检)。
