# AdGuard DNS filter → Surge

Converts [AdGuard DNS filter](https://github.com/AdguardTeam/AdGuardSDNSFilter) into Surge domain rulesets, preserving allow rules, `important` priority, and `badfilter` semantics. Updates automatically every Monday at 10:17 Beijing time (UTC+8).

## Usage

Requires Surge Mac 6.9.0+ / iOS 5.22.0+ with support for [nested rulesets](https://manual.nssurge.com/rules/ruleset.html).

Merge the following into your Surge configuration, placing the ruleset reference in `[Rule]` before general routing rules:

```ini
[Rule]
RULE-SET,AdGuardSDNSFilter,REJECT

[Ruleset AdGuardSDNSFilter]
RULE-SET,https://raw.githubusercontent.com/oooqqqa/rule-set/main/rules/block-important.list
AND,((RULE-SET,https://raw.githubusercontent.com/oooqqqa/rule-set/main/rules/block.list),(NOT,((RULE-SET,https://raw.githubusercontent.com/oooqqqa/rule-set/main/rules/allow.list))))
```

Surge automatically refreshes remote lists. See [surge-remote.conf](rules/surge-remote.conf) for the latest configuration. If the rule categories change, update the references in your configuration accordingly.

For local use, place the `.list` files from [rules](rules) in the same directory as your configuration and use [surge-rules.conf](rules/surge-rules.conf).

Allow rules only bypass blocking within this group and continue to subsequent routing rules; they do not force `DIRECT`. Use the complete configuration: subscribing to `block.list` alone loses allow-rule and priority semantics.

## Rule Lists

| File | Purpose |
| --- | --- |
| `block.list` | Standard blocking rules |
| `allow.list` | Standard allow rules |
| `block-important.list` | High-priority blocking rules that override standard allow rules |
| `allow-important.list` | High-priority allow rules that take precedence over all blocking rules; generated only when matching rules exist |

Under [AdGuard rule priorities](https://adguard-dns.io/kb/general/dns-filtering-syntax/), `$important` blocking rules are unaffected by standard allow rules, so they are kept separately. Lists are generated only for nonempty categories, and configuration snippets are updated alongside the conversion results.

## Conversion Scope

Supports exact domains, domain suffixes, keywords, wildcards, and common blocking entries in hosts files. No IP rules are generated.

Regular expressions, URL structures, DNS rewrites, and unknown modifiers that cannot be converted equivalently are recorded in [unsupported.json](rules/unsupported.json). Skipping blocking rules may leave some requests unblocked, while skipping allow rules may cause unintended blocking. The converted rules do not exactly reproduce AdGuard DNS filtering behavior and have not yet been tested in a Surge client.

See [report.json](rules/report.json) for the source file digest, update time, and conversion counts.

## Local Generation

Requires Python 3.9+ with no additional dependencies:

```sh
python3 convert.py --download \
  --base-url https://raw.githubusercontent.com/oooqqqa/rule-set/main/rules
```

You can also specify a local source file with `--source /path/to/filter.txt` and an output directory with `--output` (default: `rules/`). `--base-url` sets the list URLs in the remote configuration snippet.

Run the tests:

```sh
python3 -m unittest -v
```

[GitHub Actions](.github/workflows/update.yml) supports weekly updates and manual runs. Forks automatically use their own repository URL. The workflow requires permission to write to the repository.

## Source and License

The source rules come from [AdGuard DNS filter](https://github.com/AdguardTeam/AdGuardSDNSFilter) and are subject to its [GPL-3.0 license](https://github.com/AdguardTeam/AdGuardSDNSFilter/blob/master/LICENSE). This repository is licensed under [GPL-3.0](LICENSE).
