# Proxy Protocol Bench

在自己的 VPS 上对照测试各代理协议。仓库包含测试脚本、设备与配置说明、原始记录和可重新计算的统计。首轮使用洛杉矶 DC03 的单台测试 VPS。

- [实测结果](RESULTS.md)
- [主矩阵图](results/overview.png)
- [原始记录](results/)
- [协议调研与选型](RESEARCH.md)

## 测量口径

每条路径使用同一台 VPS、同一段随机字节和同一份测试证书。每轮随机化配置顺序，逐项下载 1 MiB，每项使用新的 curl 进程。两端协议进程在多轮之间保持运行，连接复用由协议实现决定。代理模式下客户端经同样的本地 SOCKS5 API 访问 VPS 回环 HTTPS 源站。直连对照使用 VPS 上的同一 HTTPS 处理器和同一负载。

成功须满足 HTTP 200、curl 正常退出、下载完整且 SHA-256 一致。吞吐按首字节至下载结束的有效载荷计算，Mbps 使用十进制。首包时间包含客户端代理连接和源站 TLS。P10、P95 用线性插值，CV 是成功样本吞吐的总体标准差除以均值。网络失败计入成功率，测试进程崩溃单独计数，成功样本才进入延迟与吞吐分位数。

UDP 标签表示代理对端的外层传输。负载仍是 HTTPS 下载，覆盖应用 TCP 流量。这里的稳定性指在所列窗口内的完成率、延迟尾部和吞吐波动。本报告未测周级稳定性、原生 UDP 应用、上传、抗封锁能力或服务器满载容量。

## 覆盖范围

| 实现 | 配置 |
|---|---|
| sing-box | VLESS TLS、REALITY/Vision、gRPC/TLS，VMess WS/TLS，Trojan，AnyTLS，HTTP CONNECT/TLS，Naïve H2，Shadowsocks AEAD 和 2022，ShadowTLS v3 分别串联 SS2022 和 SS AEAD，Hysteria 1，Hysteria 2 原生、Salamander 与 20 Mbps Brutal，TUIC BBR 与 CUBIC |
| Xray-core | VLESS XHTTP/TLS，VMess mKCP |
| mieru/mita | Mieru TCP 和 UDP |

指标随完整配置组合变化。低位常用端口的可达性超出本轮高位临时端口实验范围。WireGuard、OpenVPN 等整机隧道以及 Sudoku、Snell 本轮未测。

## 复现

客户端和远端需要 Python 3.11+、OpenSSH 和 curl。运行 `bench.py` 的控制端还需 OpenSSL 3，SSH 使用已有 `known_hosts` 和免交互认证。允许本地客户端访问测试服务器的高位 TCP 和 UDP 端口。

```sh
# 在本地装客户端，在受控 VPS 上装服务端
python3 install_engines.py "$PWD/.engines" --role client
ssh benchnode 'python3 - "$HOME/proxy-bench-engines" --role server' < install_engines.py

# 将地址换成你控制的 IPv4，服务端路径使用绝对路径
python3 bench.py --ssh benchnode --host 192.0.2.10 \
  --bin-dir "$PWD/.engines" --server-bin-dir /home/runner/proxy-bench-engines \
  --label client-a --region lab --rounds 7 --round-gap 35 --timeout 18 \
  --out results/client-a.json

python3 summarize.py results/client-a.json
```

可用 `--client-ssh` 和 `--client-bin-dir` 从第二个已授权的 SSH 主机发起请求。可用 `--cases` 筛选协议，例如 `hysteria2,tuic-bbr,mieru-udp`。安装器仅处理 Linux x86-64，下载自上游并核对固定 SHA-256。仓库无需分发上游二进制。

临时监听使用随机端口和单次认证材料。代理服务的出站只允许测试源站，直连 HTTPS 路径需要随机令牌。结束时进程和配置随 SSH 会话或限时退出清理。只在自己管理的测试节点运行。

## 本轮环境说明

桌面客户端使用其现有 Clash TUN 路由。首尔客户端运行在独立 VPS，按其默认路由直达洛杉矶。桌面诊断流量曾经由首尔节点转出，因此两组视角可能共享首尔到洛杉矶一段。各轮内部按配置串行下载，部分补测的时间窗口与主矩阵重叠。

洛杉矶回环复核在 VPS 内同时运行客户端、服务端和源站，用于验证协议配置及测试工具。它主要反映本机处理和建立连接的成本，吞吐数据与公网视角分开列出。
