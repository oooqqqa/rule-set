# AdGuard DNS filter → Surge

将 [AdGuard DNS filter](https://github.com/AdguardTeam/AdGuardSDNSFilter) 转换为 Surge 域名规则集，保留放行规则、`important` 优先级及 `badfilter` 语义。每周一北京时间 10:17 自动更新。

## 使用

适用于 Surge Mac 6.9.0+ / iOS 5.22.0+，需要支持[嵌套 Ruleset](https://manual.nssurge.com/rules/ruleset.html)。

将以下内容合并到 Surge 配置中，`[Rule]` 中的引用放在一般分流规则之前：

```ini
[Rule]
RULE-SET,AdGuardSDNSFilter,REJECT

[Ruleset AdGuardSDNSFilter]
RULE-SET,https://raw.githubusercontent.com/oooqqqa/rule-set/main/rules/block-important.list
AND,((RULE-SET,https://raw.githubusercontent.com/oooqqqa/rule-set/main/rules/block.list),(NOT,((RULE-SET,https://raw.githubusercontent.com/oooqqqa/rule-set/main/rules/allow.list))))
```

Surge 会自动刷新远程列表。最新配置见 [surge-remote.conf](rules/surge-remote.conf)；若规则类别发生变化，需同步更新配置中的引用。

本地使用时，将 [rules](rules) 下的 `.list` 文件放到配置所在目录，并使用 [surge-rules.conf](rules/surge-rules.conf)。

放行规则仅跳过本组拦截，继续后续分流，不强制 `DIRECT`。请使用完整配置，单独订阅 `block.list` 会丢失放行与优先级语义。

## 规则列表

| 文件 | 用途 |
| --- | --- |
| `block.list` | 普通拦截 |
| `allow.list` | 普通放行 |
| `block-important.list` | 高优先级拦截，覆盖普通放行 |
| `allow-important.list` | 高优先级放行，优先于所有拦截；仅在有对应规则时生成 |

按照 [AdGuard 规则优先级](https://adguard-dns.io/kb/general/dns-filtering-syntax/)，`$important` 拦截不受普通放行规则影响，因此单独保留。只有非空类别会生成列表，配置片段随转换结果一同更新。

## 转换范围

支持精确域名、域名后缀、关键词、通配符和常见阻断 hosts 条目，不生成 IP 规则。

无法等价转换的正则、URL 结构、DNS 重写及未知修饰符记录在 [unsupported.json](rules/unsupported.json) 中。跳过拦截规则可能漏拦，跳过放行规则可能误拦；转换结果不完全等同于 AdGuard DNS 的过滤效果，尚未经过 Surge 客户端实测。

源文件摘要、更新时间和转换计数见 [report.json](rules/report.json)。

## 本地生成

Python 3.9+，无需额外依赖：

```sh
python3 convert.py --download \
  --base-url https://raw.githubusercontent.com/oooqqqa/rule-set/main/rules
```

也可通过 `--source /path/to/filter.txt` 指定本地源文件，`--output` 指定输出目录（默认 `rules/`）。`--base-url` 设置远程配置片段中的列表地址。

运行测试：

```sh
python3 -m unittest -v
```

[GitHub Actions](.github/workflows/update.yml) 支持每周更新及手动触发，fork 后自动使用当前仓库地址，需允许工作流写入仓库。

## 来源与许可

源规则来自 [AdGuard DNS filter](https://github.com/AdguardTeam/AdGuardSDNSFilter)，遵循其 [GPL-3.0 许可](https://github.com/AdguardTeam/AdGuardSDNSFilter/blob/master/LICENSE)。本仓库采用 [GPL-3.0](LICENSE)。
