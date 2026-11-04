import contextlib
import fnmatch
import io
import json
import tempfile
import unittest
from pathlib import Path

from convert import convert_mask, run, split_rule


def matches(rule, host, root):
    """Small evaluator for the generated domain/logical rule subset."""
    kind, value = rule.split(',', 1)
    if kind in ('AND', 'NOT'):
        parts, depth, start = [], 0, 0
        for index, char in enumerate(value[1:-1]):
            if char == '(':
                if depth == 0:
                    start = index + 1
                depth += 1
            elif char == ')':
                depth -= 1
                if depth == 0:
                    parts.append(value[1:-1][start:index])
        values = [matches(part, host, root) for part in parts]
        return all(values) if kind == 'AND' else not values[0]
    if kind == 'RULE-SET':
        return any(matches(line, host, root) for line in (root / value).read_text().splitlines()
                   if line and not line.startswith('#'))
    if kind == 'DOMAIN':
        return host == value
    if kind == 'DOMAIN-SUFFIX':
        return host == value or host.endswith('.' + value)
    if kind == 'DOMAIN-KEYWORD':
        return value in host
    if kind == 'DOMAIN-WILDCARD':
        return fnmatch.fnmatchcase(host, value)
    raise AssertionError(kind)


class ConversionTests(unittest.TestCase):
    def convert(self, root, text, base_url=''):
        source = root / 'source.txt'
        source.write_text(text, encoding='utf-8')
        with contextlib.redirect_stdout(io.StringIO()):
            return run(source, root / 'rules', base_url)

    def test_boundaries(self):
        self.assertEqual(convert_mask('||example.com^'), [('DOMAIN-SUFFIX', 'example.com')])
        self.assertEqual(convert_mask('|example.com^|'), [('DOMAIN', 'example.com')])
        self.assertEqual(convert_mask('Example.COM'), [('DOMAIN', 'example.com')])
        self.assertEqual(convert_mask('||ads*.example.com^'), [
            ('DOMAIN-WILDCARD', 'ads*.example.com'), ('DOMAIN-WILDCARD', '*.ads*.example.com')])
        self.assertEqual(convert_mask('.example.com^'), [('DOMAIN-WILDCARD', '*.example.com')])
        self.assertEqual(convert_mask('-ads-'), [('DOMAIN-KEYWORD', '-ads-')])
        self.assertEqual(convert_mask('||example.com'), [
            ('DOMAIN-WILDCARD', 'example.com*'), ('DOMAIN-WILDCARD', '*.example.com*')])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rules = [','.join(r) for r in convert_mask('||ads*.example.com^')]
            for host, expected in [('ads.example.com', True), ('a.ads1.example.com', True),
                                   ('badads.example.com', False), ('ads.example.com.evil', False)]:
                self.assertEqual(any(matches(rule, host, root) for rule in rules), expected)

    def test_unsupported_and_hosts(self):
        self.assertEqual(split_rule('/foo$/'), (False, '/foo$/', []))
        self.assertEqual(convert_mask('0.0.0.0 a.test b.test'), [('DOMAIN', 'a.test'), ('DOMAIN', 'b.test')])
        for mask in ['/foo$/', '1.2.3.4 example.com', 'https://example.com/path']:
            with self.assertRaises(ValueError):
                convert_mask(mask)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = self.convert(root, '||ok.test^\n@@/foo$/\n||x.test^$dnstype=A\n')
            self.assertEqual(report['unsupported_exceptions'], 1)
            skipped = json.loads((root / 'rules/unsupported.json').read_text())
            self.assertEqual([r['line'] for r in skipped], [2, 3])
            self.assertEqual(report['counts']['unsupported'], 2)

    def test_priorities_by_matching(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.convert(root, '\n'.join([
                '||ads.test^', '@@||ok.ads.test^',
                '||hard.ok.ads.test^$important', '@@||soft.hard.ok.ads.test^$important',
                '@@||soft.ads.test^$important', '||off.test^', '||off.test^$badfilter']))
            out = root / 'rules'
            config = (out / 'surge-rules.conf').read_text()
            rules = config.split('[Ruleset AdGuardSDNSFilter]\n')[1].splitlines()
            self.assertNotIn('DIRECT', config)
            for host, expected in [('ads.test', True), ('ok.ads.test', False),
                                   ('hard.ok.ads.test', True), ('soft.hard.ok.ads.test', False),
                                   ('soft.ads.test', False), ('off.test', False), ('badads.test', False)]:
                with self.subTest(host=host):
                    self.assertEqual(any(matches(rule, host, out) for rule in rules), expected)

    def test_badfilter_modifier_order_and_exception(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = self.convert(root, '||keep.test^\n||off.test^$important\n'
                                  '||off.test^$badfilter,important\n@@||keep.test^\n@@||keep.test^$badfilter\n')
            self.assertEqual(report['counts']['disabled_or_badfilter'], 4)
            self.assertFalse((root / 'rules/block-important.list').exists())
            self.assertFalse((root / 'rules/allow.list').exists())

    def test_config_and_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.convert(root, '||ads.test^\n@@||ok.ads.test^\n||hard.test^$important\n', 'https://example.org/rules')
            out = root / 'rules'
            config = (out / 'surge-rules.conf').read_text()
            self.assertIn('[Rule]\nRULE-SET,AdGuardSDNSFilter,REJECT', config)
            self.assertIn('RULE-SET,block-important.list\nAND,((RULE-SET,block.list),(NOT,((RULE-SET,allow.list))))', config)
            self.assertIn('RULE-SET,https://example.org/rules/block.list', (out / 'surge-remote.conf').read_text())
            self.assertEqual(len(list(out.glob('*.list'))), 3)
            self.convert(root, '||ads.test^\n')
            self.assertEqual(len(list(out.glob('*.list'))), 1)
            self.assertFalse((out / 'surge-remote.conf').exists())

    def test_invalid_input_preserves_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.convert(root, '||keep.test^\n')
            original = (root / 'rules/block.list').read_bytes()
            for value in ['', '<html>error</html>', '! comment only', '/unsupported/']:
                with self.assertRaises(ValueError):
                    self.convert(root, value)
                self.assertEqual((root / 'rules/block.list').read_bytes(), original)

    def test_deterministic_output_and_deduplication(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            text = '||z.test^\n||a.test^\n||z.test^\n'
            report = self.convert(root, text)
            self.assertEqual(report['generated_rules']['block'], 2)
            first = {p.name: p.read_bytes() for p in (root / 'rules').iterdir()}
            self.convert(root, text)
            self.assertEqual(first, {p.name: p.read_bytes() for p in (root / 'rules').iterdir()})


if __name__ == '__main__':
    unittest.main()
