# 协议调研与选型

目标是在同一台洛杉矶 VPS 和同一源站，对照测试多个代理协议及传输变体，公开原始结果和复现方法。主要指标为下载完成率、首字节时间、吞吐及重复样本的波动。按数据决定哪些配置适合当前链路，每次发布记录实际使用的软件版本。

| 候选 | 可复用部分 | 取舍 |
|---|---|---|
| [Prisma Proxy benchmarks](https://prisma-proxy.github.io/prisma-docs/docs/features/benchmarks/) | 同一 SOCKS5 入口测单流吞吐 | 官方基准在 runner 回环运行，不能描述洛杉矶公网路径 |
| [proxybench](https://github.com/drsoft-oss/proxybench) | HTTP、SOCKS、Shadowsocks 探活和测速 | 目标协议覆盖较少，不负责测试机监听和固定负载 |
| [sing-box](https://sing-box.sagernet.org/configuration/inbound/) 和 [Xray-core](https://xtls.github.io/en/config/transport.html) | 复用两端实现和配置语义 | 单独发布编排、数据和文档，上游二进制独立安装 |

采用成熟协议实现，自建薄测试层。固定下载源和负载，随机化测量顺序，保留失败和传输不完整的记录。每条路线均包含直连对照。论坛里关于 UDP 可用性的讨论用于形成待检验假设，不能归因到某个运营商或过滤设备。参考 [Reddit 的 WireGuard 讨论](https://www.reddit.com/r/selfhosted/comments/1sv8jlo/) 和 [USENIX wails 的性能实验](https://www.usenix.org/system/files/usenixsecurity25-wails.pdf)。

协议来源包括 [Shadowsocks 2022](https://shadowsocks.org/doc/sip022.html)、[ShadowTLS](https://github.com/ihciah/shadow-tls)、[Hysteria 2](https://v2.hysteria.network/docs/developers/Protocol/)、[TUIC](https://github.com/tuic-protocol/tuic)、[AnyTLS](https://github.com/anytls/anytls-go) 和 [Mieru](https://github.com/enfein/mieru)。TCP、TLS、WebSocket、gRPC、XHTTP、mKCP 属于不同层，结果按完整配置命名。

## 测试环境预检

- Xray 和 Mieru 默认限制回环目标。本次用一次性配置将这类请求收窄到测试源站。修改前的失败属于测试配置错误，从正式统计中剔除。
- Naïve 使用 sing-box 1.14.4 依赖的 [Cronet 固定构建](https://github.com/SagerNet/cronet-go/tree/c10c03c318db/lib/linux_amd64)，进程与其余 sing-box 配置隔离。预检错误版本造成的进程退出已剔除。
- [Sudoku](https://github.com/SUDOKU-ASCII/sudoku) 有独立公开实现。其接入和配置未进入本轮正式测量，待后续对照。
