# fnOS 反向代理

面向飞牛 fnOS 的原生多协议反向代理应用。界面采用紧凑的磨砂质感，会随系统自动切换亮色或暗色，并同时适配桌面端和移动端。

项目地址：<https://github.com/BearHero520/fnos-reverse-proxy>

当前源码版本：**1.0.16**。

## 主要功能

- HTTP、HTTPS、WebSocket、WSS、TCP、UDP 协议按需选择
- 来源端口支持离散端口和连续范围；目标可使用共享端口或等数量顺序映射
- 规则新增、编辑、复制、启停、删除、搜索、筛选和在线状态检测
- PEM、CRT、CER、KEY、DER、PFX、P12 多文件导入与证书自动解析
- 域名、请求头、真实 IP、访问控制、超时、上传限制、HSTS 和目标证书校验
- 规则内直接选择、上传或申请 HTTPS 证书；替换证书时保留规则绑定
- 阿里云中国站免费证书 V1/V2 自动申请、AliDNS 验证、进度日志及临期轮换；仅使用可用免费额度或已领取实例，不购买付费套餐
- Let’s Encrypt / ACME，通过独立 Cloudflare 凭据完成 DNS-01 验证
- Cloudflare、阿里云 DNS、腾讯云 DNSPod DDNS，支持 NAS 侧公网 IPv4/IPv6 检测
- 系统 HTTPS 证书替换集成于“域名与证书”，支持预检、确认、备份、验证及失败回退（实验性）
- Webhook 通知、局域网目标发现、配置导入导出、运行日志和诊断包

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

Web 和代理进程以独立 fnOS 应用用户运行，仅申请监听低端口需要的 `CAP_NET_BIND_SERVICE`。主安装包内的 root 生命周期脚本管理一个仅监听本地 Unix Socket 的受限系统证书工作进程，无需额外安装助手。证书私钥以 `0600` 权限存放于应用数据目录，不会出现在页面、API、诊断包或配置导出文件中。

系统证书替换仅支持 fnOS 中手动导入、已核验的目标证书，不覆盖系统自带证书。新旧域名需匹配，替换前备份，失败回退；自动部署须先完成一次成功的手动验证。系统私钥保持 root 所有，仅授予经核验的 Web 服务组读取权限。

阿里云 V2 自动化不会替用户领取实例；额度耗尽时停止。DDNS 只更新解析记录，不解决运营商 CGNAT 或公网入站限制。

Copyright © 2026 BearHero. All rights reserved.
