# fork 与统计镜像发布计划

- ✅ 1. fork 官方仓库，并以 1.12.9 固定提交创建独立构建分支。
- ✅ 2. 完成固定构建参数、双架构 CI 和真实协议／用户计数验证材料。
- ✅ 3. 通过静态检查并执行 GitHub Actions 构建和发布。
- ✅ 4. 核实 GHCR 产物与 digest，验证服务器拉取并记录交付。

本轮只发布镜像，不直接切换生产节点。达到构建、协议、统计和产物验证要求后停止。

2026-11-14 完成：运行 `43585079972` 的两个原生架构任务和发布任务全部成功。发布 `v1.12.9-v2ray-api-2`，多架构 digest 为 `sha256:d9edd64387dfafad2eb1e15efdcf4bd904a2d0939a577107c678f3f8d033ce94`。包已公开；试点服务器使用空的 Docker 登录配置成功拉取并核对版本及标签。生产服务未切换。

最小验证：actionlint、hadolint、Go 格式／语法、差异空白及相关文档链接检查通过；CI 中 AnyTLS／TUIC 的 TCP／UDP 回显、对应用户双向计数、Clash API 和 V2Ray gRPC API 全部通过。首轮 protobuf 字段名问题已修复；保留 Docker Actions 的 Node 20 迁移提示，实际 Node 24 运行成功，不继续额外优化。

## 2026-11-17 发布 latest 默认标签

用户要求 sbctl 和 sing-box 使用 latest，只改仓库并提交，不更新服务器。

- [x] ✅ 1. 工作流增加 latest，与双架构验证通过的版本同时发布；保持内核源码和 with_v2ray_api 不变。
- [ ] 2. 通过工作流与文档静态检查，提交推送并等待 CI 发布。
- [ ] 3. 核对匿名读取 latest 的清单与架构，记录发行结果后停止。

编译、协议验证和 Docker 操作只在 GitHub Actions 执行；不重启或升级服务器。
