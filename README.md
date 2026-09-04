# fnOS 反向代理

面向飞牛 fnOS 的原生多协议反向代理应用。界面采用紧凑的磨砂质感，会随系统自动切换亮色或暗色，并同时适配桌面端和移动端。

项目地址：<https://github.com/BearHero520/fnos-reverse-proxy>

## 主要功能

- HTTP、HTTPS、WebSocket、WSS、TCP、UDP 协议按需选择
- 来源端口支持离散端口和连续范围；目标可使用共享端口或等数量顺序映射
- 规则新增、编辑、复制、启停、删除、搜索、筛选和在线状态检测
- PEM、CRT、CER、KEY、DER、PFX、P12 多文件导入与证书自动解析
- 域名、请求头、真实 IP、访问控制、超时、上传限制、HSTS 和目标证书校验
- 配置导入导出、运行日志和诊断包

## 证书有什么用

证书只用于本应用直接接收 HTTPS 或 WSS 请求时完成 TLS 握手、解密流量，再把请求转发到目标服务。HTTP 不加密；TCP / UDP 原样转发也不需要在本应用中选择证书。

建议优先导入应用自己的证书。读取 fnOS 系统证书属于实验性只读兼容能力，fnOS 升级后可能失效；应用会尽量保留上一份验证通过的证书作为回退。

## 本地开发与验证

```bash
npm install
npm --prefix backend install
npm run start:local
npm run check
```

本地预览地址为 `http://127.0.0.1:5178/app/reverse-proxy/`。演示模式不会监听规则中的真实端口。

## 生成 FPK

```bash
npm run package:fpk
```

脚本会构建前端、复制生产后端依赖，并使用官方 `fnpack` 生成及校验 `dist/reverse-proxy.fpk`。也可通过 `FNPACK_PATH` 指定 `fnpack` 路径。

仓库仅保留可复现构建所需的源码、fnOS 元数据和脚本；依赖、构建目录、本机缓存、运行数据、设计校验素材及证书私钥不会提交。可安装的 FPK 请从 GitHub Releases 下载。

## 安全说明

应用以独立 fnOS 应用用户运行，仅申请监听低端口需要的 `CAP_NET_BIND_SERVICE`。证书私钥以 `0600` 权限存放于应用数据目录，不会出现在页面、API、诊断包或配置导出文件中。

Copyright © 2026 BearHero. All rights reserved.
