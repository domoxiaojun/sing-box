# sing-box 统计镜像

此分支保留官方 1.12.9 内核源码，只增加构建和验证材料。上游提交固定为 `328a6de7976182700aaa4f7e2c134bd568b47d88`，Go 固定为 1.25.1；builder 与官方运行时基础镜像均固定 digest。默认八个构建标签全部保留，并增加 `with_v2ray_api`。

## 构建与发布

工作流 `.github/workflows/sbctl-image.yml` 在 `codex/v2ray-api` 分支构建材料变更时运行，也支持手动运行。amd64 与 arm64 使用各自原生 Linux runner。编译及测试均在 GitHub Actions 执行；开发 Mac 不使用 Docker。

每个平台先构建本地候选镜像，验证版本和所有标签、Clash API、V2Ray gRPC API，以及 AnyTLS、TUIC 的 TCP／UDP 回环流量和对应用户双向计数增长，再推送同一个已测试的镜像。两平台都成功后才发布多架构版本。

发布地址为 `ghcr.io/domoxiaojun/sing-box`：

- `v1.12.9-v2ray-api-<run_number>`：对应工作流运行的版本标签。
- `v1.12.9-v2ray-api`：最近一次两架构均通过验证的别名。
- `build-<run_id>-<run_attempt>-<arch>`：各架构的候选产物。

工作流运行摘要记录版本、二进制 SHA-256、架构镜像 digest 和多架构 digest。部署时使用 `ghcr.io/domoxiaojun/sing-box@sha256:…`，不要将可移动标签当作已验收版本。重跑某个工作流仍可能更新该运行编号的标签；digest 才是不变的产物标识。

测试只使用 CI 临时生成的凭据与证书，不包含 VPS 的配置或秘密，也不部署到生产节点。统计编译标签不会自动启用统计；实际节点还需配置 `experimental.v2ray_api`、回环监听及 `stats.users`，验证用户映射和真实计数。此镜像不包含 sbctl 的宿主工具、账本或授权守卫。

许可证继承上游 GPL-3.0-or-later，镜像中保留 `LICENSE`。

## 上游资料

- [官方构建选项](https://sing-box.sagernet.org/installation/build-from-source/)
- [1.12.9 官方 Dockerfile](https://github.com/SagerNet/sing-box/blob/v1.12.9/Dockerfile)
- [V2Ray API 配置](https://sing-box.sagernet.org/configuration/experimental/v2ray-api/)
