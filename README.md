# Glasswing

> **玻璃翼蝶，在规则下透明穿行**
> 校园网动态监测规则与受限网络环境下的自愈工具包
>  顺便致敬山西某个最开放最有魅力最支持学生个人发展的高校
> 对就是你

Glasswing 用 Python 标准库写成，用于在被观测、被限制的网络环境里
摸清上游阻断方式，并让连接存活。

此项目名取自 *Greta oto*（玻璃翼蝶）：即翅膀透明，在注视之下飞过而不被看见。

---

## 用法

```bash
python -m glasswing probe        # 四类探测：DNS 劫持 / SNI 黑名单 / 端口策略 / 代理数据面
python -m glasswing rules        # 依据探测结果输出规则推测
python -m glasswing report       # 生成 Markdown 报告（含原始数据）
python -m glasswing guard        # 常驻守护：通道失效时自动切换
python -m glasswing gen-config   # 生成带分流的代理配置（国内直连 + 境外代理）
python -m glasswing proxy        # 查看 / 设置 / 关闭系统代理
```

常用参数：

```bash
python -m glasswing probe --ports 7890,7891 --json out/probe.json
python -m glasswing guard --ports 7890,7891,7892 --interval 10 --threshold 2
python -m glasswing guard --once --dry-run        # 只检查一次，不改系统代理
python -m glasswing gen-config -i nodes.yaml -o out/config.yaml
python -m glasswing proxy --set 127.0.0.1:7890
```

> `probe` 会主动检测本机代理是否在干扰探测（系统代理 / TUN / fake-ip），
> 想要准确的上游结论，请先关闭代理再测。

---

## 实测：某高校校园网上游规则

| 层面 | 现象 | 判定 |
|---|---|---|
| DNS | 自设 `223.5.5.5` 仍返回假地址（`google.com → 127.0.0.1`），DoH(443) 可用 | 53/UDP 被劫持，换 DNS 无效 |
| 端口 | 443/80 及 8080/8443/2053/2096 均可连，22 可连，仅 53 受限 | 无端口封锁，隧道端口自由 |
| IP | 境外 IP 普遍可 TCP 连通 | 非「一刀切封境外」 |
| SNI | `google`/`chatgpt`/`ao3`/`dlsite`/`pixiv`/`reddit`/`microsoft.com` 稳定超时；`github`/`cloudflare` 时通时不通；`apple`/`bing` 正常 | 选择性 + 动态 SNI 黑名单 |
| 代理流量 | 小请求 71 分钟无异常、750MB 下载无异常；**实际使用（多域名 + 多连接 + 长会话）3~20 分钟内必被掐** | 识别代理会话后施加间歇性数据干扰 |
| 失效特征 | `TCP 握手 OK` 但**数据传输全丢**；节点约 13~16 分钟后自行恢复 | 干扰型，非永久封 IP |

---

## 设计要点

1. **健康检查必须发真实请求** —— 只看「端口是否监听」识别不出「TCP 通但数据被丢」的干扰
2. **判定要连续 N 次失败** —— 代理重启有几秒空窗，否则会误切
3. **健康检查目标不能选被墙站点** —— 默认用 `apple.com`，否则会把「通」判成「断」
4. **分流必须做** —— 国内域名直连，否则校内应用会被代理拖死
5. **探测前先关代理** —— fake-ip 会接管 DNS，让结果失真

---

## 安全

- 工具本身**不含任何凭据**，也不读取订阅链接；
- 节点配置与输出目录已在 `.gitignore` 中排除（`config.yaml` / `nodes/` / `out/` / `.env` / 日志）；
- 需要密钥时一律走环境变量。

```bash
git check-ignore config.yaml .env out/ -v     # 提交前自检
```

---

## 环境

Python 3.9+ / Windows / macOS / Linux（Windows 下可读写系统代理，其它平台自动降级）

---

## 合规声明

本工具用于**网络诊断与自身连接可用性维护**，面向被屏蔽环境下的学习与技术研究。
使用者应自行遵守所在国家/地区的法律法规及所在学校的网络管理规定。
请勿用于任何未经授权的用途。

## License

MIT
