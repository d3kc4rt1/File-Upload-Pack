#!/usr/bin/env python3
"""Offline structural verification. No payload URLs, scripts or archives are executed."""

import argparse
import base64
import csv
import hashlib
import io
import json
import posixpath
import re
import stat
import sys
import xml.etree.ElementTree as ET
import zipfile
from collections import Counter
from pathlib import Path, PurePosixPath

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
CHECKS = Counter()


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--baseline-snapshot', type=Path, help='Optional path-to-SHA256 JSON used to prove valid/abnormal fixtures were preserved.')
    args = parser.parse_args()
    from PIL import Image
    from pypdf import PdfReader
    from lxml import etree

    root = args.root.resolve()
    manifest = json.loads((root / 'manifest.json').read_text())
    cases = manifest['cases']
    entries = {e['path']: e for e in cases}
    require(len(entries) == len(cases), 'Duplicate manifest path')
    actual = {p.relative_to(root).as_posix(): p for c in ('valid', 'abnormal', 'malicious') for p in root.glob('*/' + c + '/*') if p.is_file() and not p.name.startswith('.')}
    require(set(entries) == set(actual), f'Manifest/inventory mismatch: {set(entries)^set(actual)}')
    for rel, p in actual.items():
        e = entries[rel]; d = p.read_bytes()
        require(e['size_bytes'] == len(d), rel + ': size mismatch')
        require(e['sha256'] == hashlib.sha256(d).hexdigest(), rel + ': hash mismatch')
        require(e['category'] == p.parent.name and e['extension'] == p.parent.parent.name, rel + ': category/extension mismatch')
        CHECKS['manifest_hashes'] += 1
    with (root / 'manifest.csv').open(newline='') as f:
        csv_entries = {e['path']: e for e in csv.DictReader(f)}
    require(set(csv_entries) == set(entries), 'CSV and JSON manifests disagree on paths')
    for rel, e in entries.items():
        for key, value in e.items():
            expected = json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else '' if value is None else str(value)
            require(csv_entries[rel][key] == expected, f'CSV differs: {rel}: {key}')
    CHECKS['manifest_csv_rows'] = len(csv_entries)
    if args.baseline_snapshot:
        baseline = json.loads(args.baseline_snapshot.read_text())
        for rel, sha in baseline.items():
            if '/valid/' in rel or '/abnormal/' in rel:
                require(rel in actual and hashlib.sha256(actual[rel].read_bytes()).hexdigest() == sha, 'Changed baseline: ' + rel)
                CHECKS['unchanged_baseline_fixtures'] += 1

    class MemoryResolver(etree.Resolver):
        def __init__(self, expected, value):
            super().__init__(); self.expected = expected; self.value = value; self.seen = []

        def resolve(self, url, public_id, context):
            require(url == self.expected, 'Unexpected resolver request: ' + url)
            self.seen.append(url)
            return self.resolve_string(self.value, context)

    def parse_xml(data):
        return etree.fromstring(data, etree.XMLParser(resolve_entities=False, load_dtd=False, no_network=True))

    def exercise_xml_probe(data, e):
        # The only positive-control expansion uses an in-memory resolver. It
        # never reads the configured file or opens a socket.
        if b'<!ENTITY probe SYSTEM ' in data:
            uri = e.get('canary_uri') or e.get('callback_url')
            require(bool(uri), e['path'] + ': no entity target metadata')
            marker = 'OFFLINE_CANARY_NOT_IN_FIXTURE_7c1e'
            require(marker.encode() not in data, 'Positive-control marker is present in input')
            resolver = MemoryResolver(uri, marker)
            xp = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=True)
            xp.resolvers.add(resolver)
            tree = etree.fromstring(data, xp)
            require(resolver.seen == [uri], e['path'] + ': entity was not requested exactly once')
            require(marker in ''.join(tree.itertext()), e['path'] + ': entity did not reach parsed text')
            negative = parse_xml(data)
            require(marker not in ''.join(negative.itertext()), 'Negative control unexpectedly expanded')
            CHECKS['xxe_positive_and_negative_controls'] += 1
        elif re.search(rb'<!DOCTYPE\s+\S+\s+SYSTEM\s', data):
            uri = e.get('callback_url')
            require(bool(uri), 'Missing external DTD URL')
            resolver = MemoryResolver(uri, '')
            xp = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=True)
            xp.resolvers.add(resolver); etree.fromstring(data, xp)
            require(resolver.seen == [uri], 'DTD was not requested')
            CHECKS['dtd_in_memory_controls'] += 1

    def jpeg_xmp(data):
        off = 2
        while off + 4 <= len(data) and data[off] == 255:
            tag = data[off + 1]; off += 2
            if tag in (0xda, 0xd9): break
            size = int.from_bytes(data[off:off + 2], 'big')
            block = data[off + 2:off + size]
            prefix = b'http://ns.adobe.com/xap/1.0/\x00'
            if tag == 0xe1 and block.startswith(prefix): return block[len(prefix):]
            off += size
        return None

    for rel, e in entries.items():
        if e['category'] != 'malicious': continue
        for key in ('processing_stage', 'target_processor', 'version_scope', 'prerequisites', 'trigger', 'expected_evidence', 'user_interaction', 'affected_actor', 'verification_status', 'proof_strength'):
            require(bool(e.get(key)), rel + ': missing ' + key)
        if e.get('callback_url'):
            require(e['callback_url'].startswith(manifest['configuration']['callback_base'].rstrip('/') + '/'), rel + ': stale callback URL')
        p = actual[rel]; data = p.read_bytes(); ext = e['extension']
        if ext in ('png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp'):
            with Image.open(io.BytesIO(data)) as image:
                require(image.format == {'jpg': 'JPEG', 'jpeg': 'JPEG'}.get(ext, ext.upper()), rel + ': wrong actual image format')
                image.verify()
            with Image.open(io.BytesIO(data)) as image:
                count = getattr(image, 'n_frames', 1)
                for i in range(count): image.seek(i); image.load()
                if e['payload_type'] == 'bounded-frame-count': require(count == 8, rel + ': missing animation frames')
                if e['payload_type'] == 'bounded-image-dimensions': require(image.size == (1024, 1024), rel + ': wrong dimensions')
                if e['payload_type'] == 'xmp-xxe-probe':
                    xmp = jpeg_xmp(data) if ext in ('jpg', 'jpeg') else image.info.get('XML:com.adobe.xmp') if ext == 'png' else image.info.get('xmp')
                    require(bool(xmp), rel + ': XMP not found')
                    if isinstance(xmp, str): xmp = xmp.encode()
                    parse_xml(xmp); exercise_xml_probe(xmp, e)
                if e['payload_type'] == 'metadata-injection':
                    values = [str(v) for v in image.info.values()]
                    values.extend(str(v) for v in image.getexif().values())
                    require(any('script' in v or '&lt;script' in v for v in values), rel + ': hostile metadata not found')
            CHECKS['fully_decoded_images'] += 1
        elif ext == 'pdf':
            reader = PdfReader(io.BytesIO(data), strict=True)
            require(len(reader.pages) == 1, rel + ': wrong page count')
            require('pentest' in reader.pages[0].extract_text(), rel + ': missing visible marker')
            if e['payload_type'] == 'pdf-xfa-xxe':
                xfa = reader.trailer['/Root']['/AcroForm']['/XFA'].get_data()
                parse_xml(xfa); exercise_xml_probe(xfa, e)
            if e['payload_type'] == 'pdf-form-submit':
                fields = reader.get_fields()
                require(fields and fields['value']['/V'] == 'pentest' and 'pentest' in fields, rel + ': broken canonical form fields')
                widget = reader.pages[0]['/Annots'][0].get_object()
                require(widget['/A']['/S'] == '/SubmitForm' and widget['/A']['/F'] == e['callback_url'], 'Broken SubmitForm action')
                require(widget['/A']['/Fields'][0].get_object()['/V'] == 'pentest', 'SubmitForm references wrong field')
            if e['payload_type'] in ('pdf-embedded-file', 'pdf-attachment-path-traversal'):
                names = reader.trailer['/Root']['/Names']['/EmbeddedFiles']['/Names']
                spec = names[1].get_object()
                require(spec['/EF']['/F'].get_data() == b'pentest\n', rel + ': attachment content wrong')
                if 'traversal' in e['payload_type']: require(spec['/F'].startswith('../'), rel + ': missing traversal')
            if e['payload_type'] == 'pdf-uri-action':
                require(reader.pages[0]['/Annots'][0].get_object()['/A']['/URI'] == e['callback_url'], 'Wrong PDF URI')
            CHECKS['strictly_parsed_pdfs'] += 1
        elif ext in ('docx', 'xlsx', 'zip'):
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                for item in z.infolist():
                    with z.open(item) as source: source.read()  # Includes CRC verification, including duplicate names.
                if ext in ('docx', 'xlsx'):
                    names = set(z.namelist())
                    require('[Content_Types].xml' in names and '_rels/.rels' in names, rel + ': not an OOXML package')
                    parsed = {}
                    for name in names:
                        if name.endswith(('.xml', '.rels')):
                            xml = z.read(name); parsed[name] = parse_xml(xml); exercise_xml_probe(xml, e)
                    content_types = parsed['[Content_Types].xml']
                    defaults = {v.get('Extension'): v.get('ContentType') for v in content_types if v.tag.endswith('Default')}
                    overrides = {v.get('PartName').lstrip('/'): v.get('ContentType') for v in content_types if v.tag.endswith('Override')}
                    for name in names - {'[Content_Types].xml'}:
                        require(bool(overrides.get(name, defaults.get(name.rsplit('.', 1)[-1]))), rel + ': missing content type for ' + name)
                    for name, tree in parsed.items():
                        if not name.endswith('.rels'): continue
                        base = '' if name == '_rels/.rels' else str(PurePosixPath(name).parent.parent)
                        ids = set()
                        for relationship in tree:
                            require(relationship.get('Id') not in ids, rel + ': duplicate relationship ID'); ids.add(relationship.get('Id'))
                            target = relationship.get('Target')
                            if relationship.get('TargetMode') != 'External':
                                target = posixpath.normpath(target.lstrip('/') if target.startswith('/') else posixpath.join(base, target))
                                require(target in names, rel + ': missing relationship target ' + target)
                    require(not any('vbaProject' in n for n in names), rel + ': unexpected macro part')
                    if ext == 'xlsx' and e['payload_type'] == 'spreadsheet-formula':
                        sheet = parsed['xl/worksheets/sheet1.xml']
                        formulas = sheet.findall('.//{http://schemas.openxmlformats.org/spreadsheetml/2006/main}f')
                        require(len(formulas) == 1 and formulas[0].text, rel + ': missing formula')
                    CHECKS['ooxml_packages'] += 1
                else:
                    if e['payload_type'] == 'archive-symlink-escape':
                        require(stat.S_ISLNK(z.getinfo('pentest-link').external_attr >> 16), rel + ': missing symlink mode')
                        require(z.read('pentest-link') == b'..', rel + ': symlink points to wrong parent')
                    if e['payload_type'] == 'archive-duplicate-entry':
                        infos = z.infolist(); require(infos[0].filename == infos[1].filename and z.read(infos[0]) != z.read(infos[1]), rel + ': not a differential duplicate')
                    if e['payload_type'] == 'bounded-archive-expansion': require(sum(i.file_size for i in z.infolist()) == 131072, 'Wrong expansion bound')
                    CHECKS['zip_archives'] += 1
        elif ext in ('xml', 'svg'):
            parse_xml(data); exercise_xml_probe(data, e)
            if e['payload_type'] == 'bounded-entity-expansion':
                tree = etree.fromstring(data, etree.XMLParser(resolve_entities=True, load_dtd=False, no_network=True))
                require(len(''.join(tree.itertext()).encode()) == 1792, 'Wrong entity expansion bound')
            CHECKS['xml_documents'] += 1
        elif ext == 'json':
            json.loads(data)
            if e['payload_type'] == 'duplicate-key-disagreement':
                first = json.loads(data, object_pairs_hook=lambda pairs: dict(reversed(pairs)))
                last = json.loads(data)
                require(first['probe'] is False and last['probe'] is True, 'Duplicate-key differential not observed')
                CHECKS['json_parser_differentials'] += 1
            CHECKS['json_documents'] += 1
        elif ext == 'csv':
            rows = list(csv.reader(io.StringIO(data.decode()), strict=True))
            require(len(rows) == 2 and all(len(row) == 1 for row in rows), rel + ': formula split into multiple cells')
            require(rows[1][0].lstrip('\t').startswith('='), rel + ': no formula prefix')
            CHECKS['strict_csv_formulas'] += 1
        elif ext in ('php', 'phtml', 'jsp', 'aspx', 'cfm', 'txt', 'html'):
            data.decode('utf-8')
            if e['payload_type'].startswith('server-'):
                require(not re.search(rb'\$_(?:GET|POST|REQUEST)|getParameter\(|Request\.(?:QueryString|Form)', data), rel + ': unexpected request-controlled operation')
                if e['payload_type'] == 'server-canary-write': require(b'CREATE_NEW' in data or b'FileMode.CreateNew' in data or b'fopen($p,"x")' in data or b'createNewFile' in data, rel + ': no exclusive marker creation')
            CHECKS['source_only_review_candidates'] += 1
        if e['payload_type'] == 'server-side-code-execution':
            baseline = (root / ext / 'valid' / ('pentest.' + ext)).read_bytes()
            require(data == baseline + b'\n<?php echo "pentest"; ?>\n', rel + ': trailing PHP differs from declared marker')
            CHECKS['trailing_php_markers'] += 1

    summary = {'status': 'PASS', 'fixture_counts': dict(Counter(e['category'] for e in cases)), 'checks': dict(CHECKS),
               'limitations': ['No PHP/JSP/ASPX/CFM server runtime is executed.', 'No JavaScript, spreadsheet formula, external callback or target-side file access is executed.', 'XXE positive/negative controls resolve only synthetic in-memory canaries.', 'Structural checks are not complete ISO/schema conformance certification.', 'No archive is extracted.']}
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (AssertionError, ValueError, OSError, ImportError) as error:
        print('FAIL: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
