#!/usr/bin/env python3
"""Convert DNS host masks to Surge; audit unsupported syntax rather than widen it."""
import argparse
import collections
import hashlib
import ipaddress
import json
import re
import urllib.request
from pathlib import Path

SOURCE = 'https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt'
GROUPS = ('block', 'allow', 'block-important', 'allow-important')
LICENSE = 'https://github.com/AdguardTeam/AdguardSDNSFilter/blob/master/LICENSE'


def split_rule(line):
    exception = line.startswith('@@')
    body = line[2:] if exception else line
    # A regex can contain a literal dollar anchor.
    if body.startswith('/'):
        end = body.rfind('/')
        return exception, body[:end + 1], body[end + 2:].split(',') if body[end + 1:].startswith('$') else []
    body, sep, mods = body.partition('$')
    return exception, body, mods.split(',') if sep else []


def convert_mask(mask):
    if mask.startswith('/'):
        raise ValueError('regex: no general Surge domain equivalent')
    fields = mask.split()
    if len(fields) > 1:
        try:
            addr = ipaddress.ip_address(fields[0])
        except ValueError:
            raise ValueError('unrecognized whitespace')
        if str(addr) not in ('0.0.0.0', '127.0.0.1', '::'):
            raise ValueError('hosts DNS rewrite')
        return [rule for host in fields[1:] for rule in convert_mask(host)]
    # Bare host lists use exact matches, unlike unanchored adblock masks.
    label = r'[a-zA-Z0-9_](?:[a-zA-Z0-9_-]*[a-zA-Z0-9_])?'
    if re.fullmatch(label + r'(?:\.' + label + r')*\.?', mask):
        return [('DOMAIN', mask.lower().rstrip('.'))]
    suffix = mask.startswith('||')
    start = suffix or mask.startswith('|')
    body = mask[2:] if suffix else mask[1:] if start else mask
    end = body.endswith(('^', '|'))
    body = body.removesuffix('|').removesuffix('^')
    if not body or not re.fullmatch(r'[a-zA-Z0-9_.*-]+', body):
        raise ValueError('non-host mask or unsupported metacharacters')
    body = body.lower()
    if suffix and end and '*' not in body and not body.startswith('.'):
        return [('DOMAIN-SUFFIX', body)]
    if start and not suffix and end and '*' not in body:
        return [('DOMAIN', body)]
    if not start and not end and '*' not in body:
        return [('DOMAIN-KEYWORD', body)]
    pattern = body + ('' if end else '*')
    patterns = [pattern, '*.' + pattern] if suffix else [pattern if start else '*' + pattern]
    return [('DOMAIN-WILDCARD', p) for p in patterns]


def render_config(groups, base_url=''):
    prefix = base_url.rstrip('/') + '/' if base_url else ''
    config = ['# Generated configuration fragment; merge into your Surge profile.',
              '[Rule]', 'RULE-SET,AdGuardSDNSFilter,REJECT', '',
              '[Ruleset AdGuardSDNSFilter]']
    for block, allows in [('block-important', ['allow-important']),
                          ('block', ['allow-important', 'allow'])]:
        if not groups[block]:
            continue
        terms = [f'(RULE-SET,{prefix}{block}.list)']
        terms += [f'(NOT,((RULE-SET,{prefix}{a}.list)))' for a in allows if groups[a]]
        config.append('AND,(' + ','.join(terms) + ')' if len(terms) > 1
                      else f'RULE-SET,{prefix}{block}.list')
    return '\n'.join(config) + '\n'


def run(source, out, base_url=''):
    data = source.read_bytes()
    content = data.decode('utf-8-sig')
    if not content.strip() or content.lstrip().startswith('<'):
        raise ValueError('Empty or HTML input')
    lines = [(i, line.strip()) for i, line in enumerate(content.splitlines(), 1)
             if line.strip() and not line.lstrip().startswith(('!', '#'))]
    parsed = [(i, line, split_rule(line)) for i, line in lines]
    disabled = {(ex, mask, tuple(sorted(m for m in mods if m != 'badfilter')))
                for _, _, (ex, mask, mods) in parsed if 'badfilter' in mods}
    groups = {group: set() for group in GROUPS}
    counts = collections.Counter()
    skipped = []
    for number, line, (ex, mask, mods) in parsed:
        key = (ex, mask, tuple(sorted(mods)))
        if 'badfilter' in mods or key in disabled:
            counts['disabled_or_badfilter'] += 1
            continue
        try:
            if set(mods) - {'important'}:
                raise ValueError('unsupported modifiers: ' + ','.join(mods))
            rules = convert_mask(mask)
        except ValueError as error:
            skipped.append(dict(line=number, rule=line, exception=ex, reason=str(error)))
            counts['unsupported'] += 1
            continue
        group = ('allow' if ex else 'block') + ('-important' if 'important' in mods else '')
        groups[group].update(rules)
        counts[group + '_source_rules'] += 1
    if not groups['block'] and not groups['block-important']:
        raise ValueError('No supported blocking rules; refusing to replace output')
    out.mkdir(parents=True, exist_ok=True)
    header = f'# Derived from AdGuard DNS filter\n# Source: {SOURCE}\n# License: GPL-3.0; {LICENSE}\n'
    for group in GROUPS:
        path = out / (group + '.list')
        if groups[group]:
            path.write_text(header + ''.join(','.join(rule) + '\n' for rule in sorted(groups[group])), encoding='utf-8')
        else:
            path.unlink(missing_ok=True)
    (out / 'surge-rules.conf').write_text(render_config(groups), encoding='utf-8')
    if base_url:
        (out / 'surge-remote.conf').write_text(render_config(groups, base_url), encoding='utf-8')
    else:
        (out / 'surge-remote.conf').unlink(missing_ok=True)
    report = dict(source_url=SOURCE,
                  source_sha256=hashlib.sha256(data).hexdigest(),
                  source_last_modified=next((line.split(':', 1)[1].strip() for line in content.splitlines()
                                             if line.startswith('! Last modified:')), None),
                  source_rules=len(lines), counts=dict(counts),
                  generated_rules={k: len(v) for k, v in groups.items()},
                  unsupported_exceptions=sum(item['exception'] for item in skipped))
    for name, value in [('unsupported', skipped), ('report', report)]:
        (out / (name + '.json')).write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return report


def download(path):
    with urllib.request.urlopen(SOURCE, timeout=120) as response:
        data = response.read()
    if not data or data.lstrip().startswith(b'<') or b'! Title: AdGuard DNS filter' not in data:
        raise ValueError('Unexpected AdGuard download response')
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=Path('data/adguard.txt'))
    parser.add_argument('--output', type=Path, default=Path('rules'))
    parser.add_argument('--download', action='store_true', help='Download the upstream filter before converting')
    parser.add_argument('--base-url', default='', help='Published rules directory URL for surge-remote.conf')
    args = parser.parse_args()
    if args.download:
        download(args.source)
    run(args.source, args.output, args.base_url)


if __name__ == '__main__':
    main()
