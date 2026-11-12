<div align="center">

# File Upload Payload Pack

**File upload test cases for penetration testers.**

Valid baselines, malformed files, and impact-oriented payloads — organized by extension.

<p>
  <a href="#browse-the-pack"><img src="https://img.shields.io/badge/fixtures-155-2563eb?style=flat-square" alt="155 fixtures"></a>
  <a href="#supported-formats"><img src="https://img.shields.io/badge/extensions-21-0891b2?style=flat-square" alt="21 extensions"></a>
  <a href="#quick-start"><img src="https://img.shields.io/badge/marker-pentest-16a34a?style=flat-square" alt="pentest proof marker"></a>
</p>

[Quick Start](#quick-start) · [Browse](#browse-the-pack) · [Coverage](#coverage) · [Usage Notes](#usage-notes)

</div>

---

A ready-to-use collection for testing what happens **after a file is uploaded**:
validation, storage, preview, parsing, conversion, extraction, and execution.
Every fixture uses **`pentest`** as its visible or semantic marker. Images display
it, documents contain it, and execution probes return it.

- **Compare behavior** with a valid baseline and abnormal inputs for each extension.
- **Demonstrate impact** with probes for script execution, file access, external
  requests, metadata injection, formula evaluation, and archive extraction.
- **Test the processing pipeline** across browsers, document viewers, parsers,
  renderers, importers, and archive extractors.
- **Recognize the result** with a consistent `pentest` marker throughout the pack.

<details>
<summary><strong>Contents</strong></summary>

- [Browse the Pack](#browse-the-pack)
- [Supported Formats](#supported-formats)
- [Coverage](#coverage)
- [Quick Start](#quick-start)
- [Usage Notes](#usage-notes)
- [Contributing](#contributing)
- [References and Inspiration](#references-and-inspiration)

</details>

## Browse the Pack

**155 fixtures · 21 extensions · one consistent layout**

| Directory | Files | Purpose | Example |
| --- | ---: | --- | --- |
| `valid/` | **21** | Benign files matching their extension. | [PNG baseline](png/valid/pentest.png) |
| `abnormal/` | **30** | Empty, truncated, malformed, or encoding-dependent inputs. | [Truncated PDF](pdf/abnormal/truncated.pdf) |
| `malicious/` | **104** | Impact probes, security policy checks, and bounded limit tests. | [PDF XFA XXE](pdf/malicious/xfa-xxe-local-canary.pdf) |

The extension is the top-level directory. For example,
[`png/`](png/) contains [`valid/`](png/valid/), [`abnormal/`](png/abnormal/), and
[`malicious/`](png/malicious/).

The `malicious` category describes a test's intent. Some fixtures are valid
active documents; others deliberately exercise unsafe parsing or extraction.
Choose the case according to the file feature and the processor used by the target.

## Supported Formats

| Family | Browse by extension |
| --- | --- |
| Images | [BMP](bmp/) · [GIF](gif/) · [JPG](jpg/) · [JPEG](jpeg/) · [PNG](png/) · [WebP](webp/) |
| Web documents | [HTML](html/) · [SVG](svg/) |
| Documents and workbooks | [PDF](pdf/) · [DOCX](docx/) · [XLSX](xlsx/) |
| Text and structured data | [TXT](txt/) · [CSV](csv/) · [JSON](json/) · [XML](xml/) |
| Server-side scripts | [PHP](php/) · [PHTML](phtml/) · [JSP](jsp/) · [ASPX](aspx/) · [CFM](cfm/) |
| Archives | [ZIP](zip/) |

JPG and JPEG are separate extension directories for the same underlying format.

## Coverage

| Test area | Included probes | Start here |
| --- | --- | --- |
| **Server-side execution** | Original command-execution fixtures, fixed canary reads/writes, and fixed-URL HTTP requests. | [PHP](php/malicious/) · [ASPX](aspx/malicious/) |
| **Stored XSS** | Active HTML/SVG, script elements, and unsafe text previews. | [HTML](html/malicious/stored-xss.html) · [SVG](svg/malicious/script-element.svg) |
| **XXE and XML processing** | Local/HTTP entities, external DTDs, PDF XFA, OOXML parts, image XMP, XInclude, and XSLT resource loading. | [XML](xml/malicious/) · [PDF XFA](pdf/malicious/xfa-xxe-local-canary.pdf) |
| **External resource fetching** | HTML/SVG resources, DOCX linked images/templates, and renderer-dependent local-file access. | [SVG callback](svg/malicious/external-image-callback.svg) · [HTML-to-PDF](html/malicious/pdf-attachment-local-canary.html) |
| **Metadata injection** | JPEG EXIF/COM, PNG text, GIF comments, WebP XMP, and PDF metadata reflected into HTML. | [JPEG EXIF](jpg/malicious/exif-metadata-xss.jpg) · [PNG metadata](png/malicious/metadata-xss.png) |
| **Spreadsheet formulas** | Correctly quoted CSV, tab-prefixed input, formula markers, HYPERLINK, and WEBSERVICE. | [CSV](csv/malicious/) · [XLSX](xlsx/malicious/) |
| **PDF actions and attachments** | PDF JavaScript, URI links, form submission, embedded files, and attachment-name traversal. | [PDF](pdf/malicious/) |
| **Archive extraction** | Relative/absolute/Windows traversal, symlink escape, duplicate entries, and nested PHP/ZIP. | [ZIP](zip/malicious/) |
| **JSON and template handling** | Prototype keys, duplicate-key disagreement, and Jinja-compatible evaluation markers. | [JSON](json/malicious/) · [Template marker](txt/malicious/ssti-jinja-marker.txt) |
| **Resource limits** | Bounded pixels, animation frames, archive expansion/count, JSON depth, and XML entity expansion. | [Image dimensions](bmp/malicious/dimensions-bounded.bmp) · [ZIP expansion](zip/malicious/expansion-bounded.zip) |

## Quick Start

**Use the files directly. No installation is required.**

1. Download or clone the repository.
2. Open the directory matching the extension accepted by the target.
3. Upload a `valid/` file to establish the normal behavior.
4. Select an `abnormal/` case to test handling of malformed or unusual input,
   or a `malicious/` case matching the processing step you want to assess.
5. Trigger the relevant action: preview the file, render a document, import a
   spreadsheet, extract an archive, or request an executable upload.
6. Record the observed result and identify the affected server, worker, scanner,
   viewer, or browser.

For example, an image upload can be checked with the
[valid PNG](png/valid/pentest.png), [truncated PNG](png/abnormal/truncated.png),
and [PNG metadata injection](png/malicious/metadata-xss.png) cases. Each tests a
separate behavior; metadata injection takes effect only if the application
reflects the extracted text into HTML unsafely.

## Usage Notes

Select payloads according to **what the application does with the file**.
A filename or extension alone does not determine whether a payload takes effect.

| Probe family | Trigger | Evidence to look for |
| --- | --- | --- |
| HTML/SVG scripts | The file is served in an active document context. | Script execution in the tested document origin. |
| Metadata injection | Extracted metadata is inserted into HTML without escaping. | The marker script executes in the metadata preview. |
| XXE/XInclude/XSLT | A parser or transform engine processes the relevant XML feature with unsafe access enabled. | A controlled canary appears in output or a correlated external request occurs. |
| PDF actions | A supporting viewer opens the document or the user activates the link/form. | An alert, navigation, or marker-only form submission. |
| Spreadsheet formulas | A supporting spreadsheet application imports or recalculates the cell. | A computed value or the expected request/click. |
| Archive traversal/symlink | An unsafe extractor uses paths or follows links without confinement. | A marker is written outside the test extraction directory. |
| Server-side scripts | The uploaded file is processed by the corresponding executable handler. | The server performs the operation implemented in the file. |
| Prototype/template probes | The application performs the vulnerable merge or template evaluation. | Changed object behavior or an evaluated marker expression. |
| Bounded resource probes | The processor applies its size, frame, depth, or expansion policies. | Documented acceptance/rejection and resource usage within the fixture's bounds. |

> [!IMPORTANT]
> Callback payloads contain the non-resolving placeholder
> `https://callback.example.invalid/pentest`. Configure an endpoint you control
> before expecting a request. File-read probes also need a canary on the target
> processing host.

The default canary path is `/tmp/pentest-canary.txt`; the corresponding URI is
`file:///tmp/pentest-canary.txt`. Use values appropriate to the target operating
system. Paths and URLs are embedded in the files. Edit text payloads with a text
editor; modify PDF, Office, and image metadata with format-aware tooling and
re-save the file. Blind binary replacement can break offsets or checksums.

For TXT filename traversal, upload
[`path-traversal-source.txt`](txt/malicious/path-traversal-source.txt) with the
supplied filename `../../pentest-upload-test.txt`. Its contents alone are a
benign marker. ZIP/PDF traversal cases instead carry paths inside the archive
or attachment metadata.

A callback establishes a fetch. Identify its source and the intended network
boundary before reporting SSRF. For file-read tests, prepare a canary value
absent from the uploaded payload. Seeing the cached word `pentest` alone is not
proof that a file was read or a formula was recalculated.

<details>
<summary><strong>Behavior and limitations worth checking before a test</strong></summary>

- An accepted upload proves acceptance. Record the downstream behavior to
  establish execution, disclosure, or an unsafe write.
- Identify the source of a callback: application server, worker, scanner,
  document viewer, or browser. A fetch alone does not establish server-side SSRF.
- Use a target-side canary whose content is absent from the fixture. Cached
  `pentest` in an XLSX cell or Word field is not file-read/recalculation proof.
- OOXML XXE fixtures contain DTDs prohibited by OPC. Image XMP probes likewise
  need an unsafe downstream XML consumer; ordinary image decoding is insufficient.
- DOCX/XLSX are macro-free formats. This pack has no disguised macro fixtures.
- Original `command-execution.*` files accept OS commands and have no built-in
  authentication. Fixed-operation canary and HTTP probes are also provided.
- Archive/PDF traversal extraction can overwrite a same-named marker. Use a
  disposable extraction directory or host. Server write probes reserve a new
  temp marker; CFM's reserve/write sequence assumes no hostile concurrent writer.
- Bounded resource probes are limit checks. They are not unbounded bombs or
  universal decoder RCE exploits.
- Target-side PHP/JSP/ASPX/CFM execution, Office recalculation, and renderer
  behavior still require validation in the actual runtime.

</details>

## Contributing

New formats, processor-specific cases, documentation fixes, and reproducible
verification improvements are welcome.

For a new fixture:

1. Place it under the appropriate extension and category.
2. Preserve `pentest` as the visible or semantic marker.
3. Document the processor, trigger, prerequisites, and observable evidence.
4. Declare structural validity honestly and include explicit resource bounds
   where applicable.
5. Describe how the case was validated, including any processor/version limitations.
6. Update the documented counts when coverage changes.

Keep local environments, credentials, render outputs, and temporary files out of
the repository.

## References and Inspiration

- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [OWASP — File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [OWASP — Testing Upload of Malicious Files](https://wstg.owasp.org/stable/4-Web_Application_Security_Testing/10-Business_Logic_Testing/09-Test_Upload_of_Malicious_Files/)
- [OWASP — XML External Entity Prevention](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [Apache Tika — PDF XFA XXE](https://www.cve.org/CVERecord?id=CVE-2025-66516)
- [Apache POI — OOXML XXE advisory](https://solr.apache.org/security-news2.html)
- [Apache PDFBox — Security](https://pdfbox.apache.org/security.html)
- [Apache Batik — Security](https://xmlgraphics.apache.org/security.html)
- [WeasyPrint — Renderer Security](https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#security)
- [OWASP — CSV Injection](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/21-CSV_Injection/)
- [CodeQL — Archive Symlink Extraction](https://codeql.github.com/codeql-query-help/go/go-unsafe-unzip-symlink/)
- [Library of Congress — Open Packaging Conventions](https://www.loc.gov/preservation/digital/formats/fdd/fdd000363.shtml)

---

<p align="center">
  Built for authorized security testing.<br>
  <sub>No reverse shells, persistence, credential collection, or unbounded resource-exhaustion payloads.</sub>
</p>
