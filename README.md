# snmpv3-security-policy-analyzer

Python SNMPv3 安全策略分析库，处理认证加密组合、用户权限和视图边界。

现有审计工具往往只检查 USM 用户是否存在。本库进一步把 USM、VACM 和
session 配置组合起来，回答两个核心问题：

1. 某个用户对某个 OID 的**最终权限**是什么（read / write / notify）？
2. 配置里有哪些**安全隐患**：弱 HMAC、弱加密、空 context、过宽 view、
   noAuthNoPriv 用户读取管理子树、缺失密钥、session 降级等。

## 输入模型

`SnmpV3Config` 聚合五类配置（见 `snmpv3_analyzer/models.py`）：

- `UsmUser`：USM 用户，auth/priv 协议（`HMAC-MD5`、`HMAC-SHA-256`、
  `DES`、`AES-128` 等）及密钥是否已设置。
- `SecurityToGroup`：vacmSecurityToGroupTable，把 securityName 映射到 group。
- `AccessEntry`：vacmAccessTable，含 contextPrefix / contextMatch /
  securityLevel 和 read/write/notify view。
- `View` + `ViewSubtree`：vacmViewTreeFamilyTable，支持 included/excluded
  子树和 RFC 3415 的 view mask（位掩码通配）。
- `SessionConfig`：一次管理会话的用户、security level、context 和请求类型。

## 用法

```python
from snmpv3_analyzer import (
    AccessEntry, SecurityLevel, SecurityToGroup, SnmpV3Analyzer,
    SnmpV3Config, UsmUser, View, ViewSubtree, parse_oid,
)

config = SnmpV3Config(
    users=[UsmUser("guest"), UsmUser("ops", auth_protocol="HMAC-MD5",
                                     auth_key_set=True)],
    groups=[SecurityToGroup("usm", "guest", "guest-grp"),
            SecurityToGroup("usm", "ops", "ops-grp")],
    access=[AccessEntry("guest-grp", read_view="mgmt"),
            AccessEntry("ops-grp", security_level=SecurityLevel.AUTH_NO_PRIV,
                        read_view="mgmt")],
    views={"mgmt": View("mgmt", [ViewSubtree(parse_oid("1.3.6.1.2.1.1"))])},
)

analyzer = SnmpV3Analyzer(config)

# 最终权限解析：定位 user / group / view / 命中的子树
result = analyzer.effective_permission("guest", parse_oid("1.3.6.1.2.1.1.1.0"))
print(result.allowed, result.group, result.view, result.reason)

# 全量审计：每条 Finding 都携带 user/group/view/oid 定位信息
for finding in analyzer.audit():
    print(finding)
```

权限解析规则（简化自 RFC 3415）：

- securityName → group 查 vacmSecurityToGroupTable；无映射即拒绝。
- vacmAccess 按 group + context（exact/prefix）+ securityLevel ≤ 会话级别
  过滤，取要求级别最高、context 前缀最长的条目。
- view 内按**最长前缀**匹配 family，included/excluded 同长时 excluded 生效；
  mask 按位决定子标识符是否参与比较。

## 审计检查项

| check | 严重级 | 含义 |
| --- | --- | --- |
| `noauth-management-read` | critical | noAuthNoPriv 用户可读管理子树（system/interfaces/USM/VACM MIB） |
| `weak-auth-protocol` | high | 使用弱 HMAC（MD5），应迁移到 SHA-2 家族 |
| `weak-priv-protocol` | high | 使用 DES 加密，应迁移到 AES |
| `missing-auth-key` / `missing-priv-key` | high | 配了协议但没有密钥 |
| `session-level-mismatch` | high | 会话安全级别超过用户能力 |
| `empty-context` | medium | 空 contextPrefix + prefix 匹配，覆盖所有 context |
| `broad-view` | medium | view 包含 1.3.6.1 及以上的整个 internet 子树 |
| `session-downgrade` | medium | 用户配了认证但会话跑 noAuthNoPriv |
| `unknown-group` / `session-unknown-user` / `orphan-access-entry` | medium/low | 引用完整性问题 |

## 测试

```bash
python -m unittest
```

覆盖子树重叠（最长前缀优先）、excluded 节点、不同 security level 门控、
未知 group、只读请求（无 write view 时写被拒绝）、view mask 通配以及
全部审计检查项。

## 与真实设备编译选项的差异

本库是**静态配置分析器**，行为与真实 SNMP 协议栈（如 Net-SNMP、设备厂商
固件）存在以下差异，解读结果时需要注意：

- **协议可用性取决于编译选项。** Net-SNMP 只有在 `--with-openssl`（或
  对应加密库）编译时才提供 SHA-2 认证和 AES 加密；`--disable-openssl`
  或裁剪固件里可能只剩 MD5/SHA-1 + DES。本库把 MD5/DES 一律标记为弱，
  但在某些设备上它们可能是**唯一可用**的协议，整改建议需结合设备实际
  编译的 crypto 支持列表。
- **AES-192/256 不是标准 USM 协议。** RFC 3826 只定义了 AES-128；
  AES-192/256 是厂商扩展（且 Cisco 等实现与 Net-SNMP 的密钥本地化
  算法不同）。本库按名称识别，不模拟厂商特定的密钥派生差异。
- **不做运行时验证。** 真实设备的 vacmViewTreeFamilyTable 有 storage
  type、行状态（RowStatus）和默认视图（如 Net-SNMP 编译时内置的
  `systemview`）；本库假设输入即生效配置，不模拟行未激活、默认视图
  注入或 `snmpd.conf` 的 `rouser`/`createUser` 展开逻辑。
- **context 匹配简化。** 真实 agent 可能按编译选项启用多 context
  （如 VRF、社区映射）；本库只做字符串 exact/prefix 比较。
- **管理子树集合是启发式的。** 默认把 system、interfaces、USM/VACM MIB
  视为敏感管理 OID，可通过 `SnmpV3Config.management_subtrees` 按设备
  实际 MIB 支持（同样受编译选项影响）调整。
