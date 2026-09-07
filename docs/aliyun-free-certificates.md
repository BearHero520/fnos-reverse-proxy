# 阿里云免费证书与自动轮换（v1.0.8）

## 新版 V2.0

1. 在阿里云中国站领取个人测试证书实例：选择「个人测试证书（免费）＋基础版＋不需要人工服务」，确认应付 ¥0。可提前领取备用实例，供后续轮换使用。应用没有购买、续购、退款接口，也不启用阿里云收费自动托管。
2. 在本应用「证书签发 → 设置」选择「新版 V2.0 · 已领取实例」。填写 AccessKey ID / Secret 和单个普通证书域名；DNS 主域名从该账号自动识别，可手动修正。签发凭据与 DDNS 独立。
3. 联系人优先复用所选实例的信息；若没有，账号只有一个联系人时自动使用。多个联系人时，在高级设置填一个联系人 ID，无需在应用保存姓名、电话、邮箱。
4. 查询实例后点击「立即签发」。应用依次完成实例配置、提交申请、AliDNS 验证、下载和热更新。首次成功后在规则中选择证书，后续保留该证书 ID。
5. 开启到期前自动轮换后，每次使用下一张空闲实例。库存用完会停止并提示领取，保留旧证书；年度领取不是自动操作。

旧设置保留 V1.0，不会静默更换接口。请显式切换到 V2.0；切换暂停自动轮换。处理中的申请不允许改域名、区域、账号或接口版本，避免丢失申请。

## 实例边界

只选取当前适配的短期 TEST / DV、ss.dv.t、单域名且不超过 100 天的已购周期，要求购买时间完整、未升级。正式证书、PRO、未知规格和缺少元数据的实例排除。仅使用未签发、未提交、没有其他 CSR、无其他域名或云产品绑定的实例，优先匹配当前域名，再选择空白实例。操作前再读详情核对。此规格适配需真实账号验证；不符合条件时不会放宽检查。

免费数量表示已领取且可供当前域名使用的实例，不等于年度剩余可领取额度。应用不会把控制台的年度 20 张权益伪造成实例库存。

## RAM 权限

V2.0：

- yundun-cert:ListInstances
- yundun-cert:GetInstanceDetail
- yundun-cert:UpdateInstance
- yundun-cert:ApplyCertificate
- GetTaskAttribute（官方文档暂未列出授权信息，以云端鉴权为准）
- yundun-cert:GetUserCertificateDetail
- yundun-cert:ListContact（仅自动选择联系人时需要）

AliDNS：alidns:DescribeDomainInfo、alidns:DescribeDomains（自动识别区域）、alidns:DescribeSubDomainRecords、alidns:AddDomainRecord、alidns:DeleteDomainRecord。尽量限定目标区域；DescribeDomains 查询不支持资源级授权。无需 BSS 购买权限。

## 恢复和轮换

- 在修改云端前保存实例 ID、CSR 和本地私钥。提交前持久化状态；提交超时或重启后，只用实例 ID 查询任务，不再次提交、不另取实例。
- GetTaskAttribute 的 TaskId 使用实例 ID，不使用 ApplyCertificate 的 RequestId。
- 云端 CSR、域名或验证设置被外部改变时停止。DNS 验证逐条核对域名、根域与所选解析区域；不覆盖冲突记录，只清理由本应用创建且未被外部修改的记录。
- 使用本地私钥匹配下载的证书；云端返回的私钥不使用、不保存。证书格式、域名、有效期或热更新失败时保留旧证书和原申请，随后重试同一实例。
- CA 提交失败需要人工处理后显式重试，仅在任务明确失败且实例仍待申请时允许。
- 凭据、CSR、私钥不回显、不进入导出；DEMO_MODE=1 不访问云端，不伪造签发成功。

## 旧版 V1.0

仍使用 digicert-free-1-free 免费资源包接口。最多可申请量按 TotalCount - IssuedCount 估算；UsedCount 包含失败申请，不能等同已消耗额度。V1.0 订单继续原流程，不能关联 V2.0 实例 ID。

## 验证与参考

本地测试覆盖新旧设置隔离、实例筛选、DNS、重启/超时恢复、同 ID 轮换、失败保留、清理重试和禁止购买路径。尚未用真实账号提交 V2.0 证书或在 NAS 验证。

- [V2.0 API 公告](https://help.aliyun.com/zh/ssl-certificate/product-overview/announcement-ssl-certificate-v2-0-api-interface-release-notes)
- [实例列表](https://help.aliyun.com/zh/ssl-certificate/developer-reference/api-cas-2020-04-07-listinstances)
- [更新实例](https://help.aliyun.com/zh/ssl-certificate/developer-reference/api-cas-2020-04-07-updateinstance)
- [提交申请](https://help.aliyun.com/zh/ssl-certificate/developer-reference/api-cas-2020-04-07-applycertificate)
- [任务状态](https://help.aliyun.com/zh/ssl-certificate/developer-reference/api-cas-2020-04-07-gettaskattribute)
- [免费证书领取](https://help.aliyun.com/zh/ssl-certificate/purchase-an-individual-test-certificate)
