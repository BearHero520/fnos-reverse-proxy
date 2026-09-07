# DDNS 云服务商配置

DDNS 支持 Cloudflare、阿里云 DNS、中国站腾讯云 DNSPod。每次同步一个服务商中的一个 A（IPv4）或 AAAA（IPv6）记录，支持手动和定时同步。它不负责证书签发，也不会更改飞牛系统证书。

## 在应用中设置

1. 打开「DDNS → 设置」，选择 **DNS 服务商**。域名的权威 DNS 应已指向该服务商；只在该公司购买域名并不等于使用它的 DNS。
2. 填写当前服务商的凭据。阿里云填写凭据和完整记录名称后，会自动匹配空白的 **DNS 主域名**，也可点击“自动识别”重新查询或手动填写。腾讯云仍需填写控制台中管理的主域名。不要通过截取最后两段猜测 `example.com.cn` 等域名的解析区域。
3. 填写 **完整记录名称**，例如 `home.example.com`；根域名直接填写 `example.com`，应用会转换为主机记录 `@`。选择 A 或 AAAA。
4. 阿里云 / 腾讯云建议 TTL 为 **600 秒**；套餐最低 TTL 以云端限制为准。Cloudflare 支持 `1` 表示自动 TTL，开启代理时使用自动 TTL。
5. 保存后先点 **测试连接**。它只查询记录，不检测公网 IP、不修改 DNS、不写入同步成功时间；查询通过不代表拥有写入权限。
6. 点 **立即同步**进行首次真实写入，确认解析正确后开启定时同步（5–1440 分钟）。没有记录时会创建；已有记录按 ID 更新；地址与设置均未变化时不写入。

切换服务商时界面会暂停定时同步，需要明确重新开启。原服务商的密钥保留，不会删除或迁移其云端记录。当前不支持一次向多个服务商或同时向 A / AAAA 两条记录同步。

## 服务商与权限

### Cloudflare

填写目标解析区域的 Zone ID 和 API Token，给 Token 授予该区域的 DNS 编辑权限。Cloudflare 代理选项只对该服务商显示，代理不适用于任意 TCP / UDP 端口。[Cloudflare DNS 记录 API](https://developers.cloudflare.com/api/resources/dns/subresources/records/)

### 阿里云 DNS

使用 RAM 用户的 AccessKey ID / AccessKey Secret，推荐把授权范围限制到目标域名。DDNS 使用以下操作，不需要删除解析或操作证书的权限：

- `alidns:DescribeDomainRecords`
- `alidns:DescribeDomains`（仅自动识别主域名需要；该只读查询需 Resource 为 `*`，不授予时可手动填写）
- `alidns:AddDomainRecord`
- `alidns:UpdateDomainRecord`

默认线路填写 `default`。需要其他线路时，在「解析线路与权限」填写阿里云的线路代码。采用官方 AliDNS SDK 和固定 HTTPS 端点；与证书签发的 AccessKey 分开保存。[阿里云 API 及授权说明](https://help.aliyun.com/zh/dns/api-alidns-2015-01-09-overview)

自动识别只使用 DDNS 自己的凭据，不复用证书签发的 AccessKey。按完整记录名称逐级精确匹配账号中存在的区域，优先独立托管的子区域；仅查询草稿，不自动保存、开启定时同步或修改解析。识别失败可手动填写，手填值不被自动结果覆盖。查询到区域不代表已经验证公网 NS 委派或具备写权限。[解析区域查询与权限](https://help.aliyun.com/zh/dns/api-alidns-2015-01-09-describedomains)

### 腾讯云 DNSPod

使用腾讯云 CAM 子用户的 **SecretId / SecretKey**，不是旧版 DNSPod 的 ID / Token，也不是 DNSPod 国际版凭据。推荐限制到目标解析区域，允许：

- `dnspod:DescribeRecordList`
- `dnspod:CreateRecord`
- `dnspod:ModifyRecord`

默认线路填写中文 `默认`；其他线路填写 DNSPod 控制台对应的线路名称。采用官方 DNSPod SDK、API 版本 `2021-03-23`、TC3-HMAC-SHA256 签名及固定中国站 HTTPS 端点。[腾讯云 API 说明](https://cloud.tencent.com/document/product/1427/56194)，[查询记录参数](https://cloud.tencent.com/document/product/1427/56166)

## 安全与失败处理

- 密钥不回显、不进入导出或诊断包。留空表示保留旧密钥，勾选清除后才删除本地密钥。换账号 ID 时需同时填写新密钥。密钥保存在应用本机配置中（限制文件权限，非加密保险库），请保护数据目录与 NAS 管理员账号；不要把真实密钥粘贴到聊天中。
- 只修改完整名称、记录类型和线路都匹配的目标。同名同类型同线路有多条记录时停止，不随意选择一条；同名 CNAME、子域 NS 委派、URL 转发、暂停、锁定或负载均衡记录需要先在云端处理。其他主机和线路不会被改写。
- 查询失败、响应不完整或 IP 类型不符时不创建记录。API 有超时限制，不在 SDK 内自动重试写请求；结果不确定时，下次同步会先重新查询。
- 公网 IPv4 / IPv6 使用相应的 ipify HTTPS 检测服务，需 NAS 能访问该服务。AAAA 要求 NAS 具备可用的公网 IPv6；DDNS 不会解决运营商 CGNAT、防火墙或端口转发问题。
- `DEMO_MODE=1` 不访问云 API、不读取公网 IP、不修改 DNS，也不记为真实同步成功。自动测试通过注入模拟 SDK / HTTP 响应验证请求、错误、隔离和恢复逻辑，不能代替真实账号联调。

## 升级兼容

原 Cloudflare DDNS 的凭据、域名、开关及同步状态保持可读；旧版证书 / DDNS 合并配置仍按既有逻辑一次性拆分。更新新 DDNS 配置不会更改证书签发的域名、订单、密钥或轮换计划。
