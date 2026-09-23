#!/usr/bin/env python3
"""Download an O'Reilly Learning book as EPUB using the API v2.

The `/api/v1/book/` endpoints used by `safaribooks.py` were removed by O'Reilly
(they now return 404), so this script rebuilds the EPUB from the v2 endpoints:

    /api/v2/epubs/urn:orm:book:<ID>/         book metadata
    /api/v2/epubs/urn:orm:book:<ID>/files/   every file of the EPUB (OPF, NCX, CSS, fonts, images, chapters)

Usage:
    python download_v2.py <BOOK_ID>

Requires a valid `cookies.json` (with `orm-jwt` / `orm-rt`) next to this script,
see README ("How to get cookies.json"). Already downloaded files are skipped, so
an interrupted run can simply be launched again.
"""
import json
import os
import re
import sys
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor

import requests
from lxml import etree, html

PATH = os.path.dirname(os.path.realpath(__file__))
COOKIES_FILE = os.path.join(PATH, "cookies.json")
BASE_URL = "https://learning.oreilly.com"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/128.0.0.0 Safari/537.36",
    "Referer": BASE_URL + "/home/",
}
WORKERS = 4
RETRIES = 5
TEXT_TYPES = ("text/css", "text/html", "application/oebps-package+xml", "application/x-dtbncx+xml")


def get(session, url):
    """GET with retries and exponential backoff (Akamai answers 403/429 when hammered)."""
    for attempt in range(RETRIES):
        response = session.get(url)
        if response.status_code == 200:
            return response
        if response.status_code not in (403, 429, 500, 502, 503, 504):
            break
        time.sleep(2 ** attempt)
    return response


def strip_injected(root):
    """Remove the anti-bot markup Akamai injects into HTML responses."""
    for el in root.xpath('//script | //link[starts-with(@href, "/")] | //div[@id="sec-overlay"]'):
        el.getparent().remove(el)


def chapter_to_xhtml(fragment, title):
    root = html.fromstring(fragment)
    strip_injected(root)
    body = etree.tostring(root, method="xml", encoding="unicode")
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            '<html xmlns="http://www.w3.org/1999/xhtml" xmlns:epub="http://www.idpf.org/2007/ops">'
            '<head><title>%s</title><link rel="stylesheet" type="text/css" href="epub.css"/></head>'
            '<body>%s</body></html>' % (title.replace("&", "&amp;").replace("<", "&lt;"), body))


def clean_document(text):
    """Full HTML document (e.g. the EPUB3 nav): drop injected markup, keep the rest as is."""
    return re.sub(r'<script\b[^>]*>.*?</script>|<link\b[^>]*href="/[^"]*"[^>]*>|<div id="sec-overlay".*?</div></div>',
                  "", text, flags=re.S)


def patch_opf(text, info):
    """The OPF shipped by O'Reilly keeps the metadata of the original edition (e.g. English title/language
    on a translated book); use the metadata of the edition actually downloaded."""
    title = info["title"].replace("&", "&amp;").replace("<", "&lt;")
    text = re.sub(r"(<dc:title[^>]*>).*?(</dc:title>)", r"\g<1>%s\g<2>" % title, text, flags=re.S)
    text = re.sub(r'(<meta property="dcterms:title"[^>]*>).*?(</meta>)', r"\g<1>%s\g<2>" % title, text, flags=re.S)
    if info.get("language"):
        text = re.sub(r"(<dc:language[^>]*>).*?(</dc:language>)", r"\g<1>%s\g<2>" % info["language"], text)
        text = re.sub(r'(<meta property="dcterms:language"[^>]*>).*?(</meta>)', r"\g<1>%s\g<2>" % info["language"], text)
    return text


def build_epub(book_dir, epub_path):
    with zipfile.ZipFile(epub_path, "w") as z:
        z.writestr("mimetype", "application/epub+zip", compress_type=zipfile.ZIP_STORED)  # must be first, uncompressed
        for folder in ("META-INF", "OEBPS"):
            for root, _, names in os.walk(os.path.join(book_dir, folder)):
                for name in names:
                    full = os.path.join(root, name)
                    z.write(full, os.path.relpath(full, book_dir).replace(os.sep, "/"), compress_type=zipfile.ZIP_DEFLATED)


def main(book_id):
    session = requests.Session()
    session.headers.update(HEADERS)
    session.cookies.update(json.load(open(COOKIES_FILE)))

    api_url = "%s/api/v2/epubs/urn:orm:book:%s/" % (BASE_URL, book_id)
    response = get(session, api_url)
    if response.status_code != 200:
        sys.exit("[!] Unable to retrieve book info (HTTP %d). Check the book ID and `cookies.json`."
                 % response.status_code)
    info = response.json()
    title = info["title"]
    print("[*] %s" % title)

    files, url = [], api_url + "files/?limit=200"
    while url:
        page = get(session, url)
        if page.status_code != 200:
            sys.exit("[!] Unable to list book files (HTTP %d)." % page.status_code)
        page = page.json()
        files += page["results"]
        url = page["next"]
    print("[*] %d files" % len(files))

    safe_title = re.sub(r'[\\/:*?"<>|]', "", title).strip()
    book_dir = os.path.join(PATH, "Books", "%s (%s)" % (safe_title, book_id))
    oebps_dir = os.path.join(book_dir, "OEBPS")
    os.makedirs(os.path.join(book_dir, "META-INF"), exist_ok=True)

    api_prefix = "/api/v2/epubs/urn:orm:book:%s/files/" % book_id

    def relative_links(text):
        return text.replace(BASE_URL + api_prefix, "").replace(api_prefix, "")

    def fetch(f):
        dest = os.path.join(oebps_dir, f["full_path"].replace("/", os.sep))
        if os.path.isfile(dest) and os.path.getsize(dest) > 0:
            return None
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        response = get(session, f["url"])
        if response.status_code != 200:
            return "HTTP %d %s" % (response.status_code, f["full_path"])
        if f["media_type"] in TEXT_TYPES:
            text = relative_links(response.text)
            if f["kind"] == "chapter":
                text = chapter_to_xhtml(text, title)
            elif f["media_type"] == "text/html":
                text = clean_document(text)
            elif f["media_type"] == "application/oebps-package+xml":
                text = patch_opf(text, info)
            with open(dest, "w", encoding="utf-8") as out:
                out.write(text)
        else:
            with open(dest, "wb") as out:
                out.write(response.content)
        return None

    with ThreadPoolExecutor(max_workers=WORKERS) as executor:
        errors = [e for e in executor.map(fetch, files) if e]
    if errors:
        for e in errors:
            print("[!] %s" % e)
        sys.exit("[!] %d file(s) failed. Wait a few minutes and run the same command again to resume." % len(errors))

    opf = next(f["full_path"] for f in files if f["media_type"] == "application/oebps-package+xml")
    with open(os.path.join(book_dir, "META-INF", "container.xml"), "w", encoding="utf-8") as out:
        out.write('<?xml version="1.0" encoding="UTF-8"?>\n'
                  '<container version="1.0" xmlns="urn:oasis:names:tc:opendocument:xmlns:container">'
                  '<rootfiles><rootfile full-path="OEBPS/%s" media-type="application/oebps-package+xml"/></rootfiles>'
                  '</container>' % opf)

    epub_path = os.path.join(book_dir, "%s.epub" % book_id)
    build_epub(book_dir, epub_path)
    print("[-] Done: %s" % epub_path)


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # book titles are not always printable in the Windows console code page
    if len(sys.argv) != 2 or not sys.argv[1].isdigit():
        sys.exit(__doc__)
    main(sys.argv[1])
