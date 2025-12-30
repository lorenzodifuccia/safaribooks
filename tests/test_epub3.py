"""Unit tests for EPUB v3 functionality."""
import re
import sys
import os
from unittest.mock import MagicMock, patch

import pytest

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from safaribooks import SafariBooks


class TestParseNavToc:
    """Tests for the parse_nav_toc() static method."""

    def test_simple_toc_single_item(self):
        """Test parsing a single TOC item without children."""
        toc_data = [
            {
                "href": "chapter01.html",
                "label": "Chapter 1",
                "children": []
            }
        ]
        result = SafariBooks.parse_nav_toc(toc_data)
        assert '<li><a href="chapter01.xhtml">Chapter 1</a></li>' in result

    def test_simple_toc_multiple_items(self):
        """Test parsing multiple TOC items without children."""
        toc_data = [
            {"href": "chapter01.html", "label": "Chapter 1", "children": []},
            {"href": "chapter02.html", "label": "Chapter 2", "children": []},
            {"href": "chapter03.html", "label": "Chapter 3", "children": []}
        ]
        result = SafariBooks.parse_nav_toc(toc_data)
        assert '<a href="chapter01.xhtml">Chapter 1</a>' in result
        assert '<a href="chapter02.xhtml">Chapter 2</a>' in result
        assert '<a href="chapter03.xhtml">Chapter 3</a>' in result

    def test_nested_toc_with_children(self):
        """Test parsing TOC with nested children."""
        toc_data = [
            {
                "href": "part01.html",
                "label": "Part 1",
                "children": [
                    {"href": "chapter01.html", "label": "Chapter 1", "children": []},
                    {"href": "chapter02.html", "label": "Chapter 2", "children": []}
                ]
            }
        ]
        result = SafariBooks.parse_nav_toc(toc_data)
        assert '<a href="part01.xhtml">Part 1</a>' in result
        assert '<ol>' in result  # Nested list for children
        assert '<a href="chapter01.xhtml">Chapter 1</a>' in result
        assert '<a href="chapter02.xhtml">Chapter 2</a>' in result

    def test_deeply_nested_toc(self):
        """Test parsing deeply nested TOC structure."""
        toc_data = [
            {
                "href": "part01.html",
                "label": "Part 1",
                "children": [
                    {
                        "href": "chapter01.html",
                        "label": "Chapter 1",
                        "children": [
                            {"href": "section01.html", "label": "Section 1.1", "children": []}
                        ]
                    }
                ]
            }
        ]
        result = SafariBooks.parse_nav_toc(toc_data)
        assert '<a href="part01.xhtml">Part 1</a>' in result
        assert '<a href="chapter01.xhtml">Chapter 1</a>' in result
        assert '<a href="section01.xhtml">Section 1.1</a>' in result
        # Should have nested <ol> elements
        assert result.count('<ol>') == 2

    def test_html_escaping_in_labels(self):
        """Test that special HTML characters in labels are escaped."""
        toc_data = [
            {"href": "chapter01.html", "label": "Chapter <1> & \"Introduction\"", "children": []}
        ]
        result = SafariBooks.parse_nav_toc(toc_data)
        assert '&lt;1&gt;' in result
        assert '&amp;' in result
        assert '&quot;' in result

    def test_href_with_path_prefix(self):
        """Test that path prefixes in href are stripped correctly."""
        toc_data = [
            {"href": "OEBPS/Text/chapter01.html", "label": "Chapter 1", "children": []}
        ]
        result = SafariBooks.parse_nav_toc(toc_data)
        # Should only keep the filename, not the path
        assert 'href="chapter01.xhtml"' in result

    def test_empty_toc(self):
        """Test parsing an empty TOC list."""
        toc_data = []
        result = SafariBooks.parse_nav_toc(toc_data)
        assert result == ""


class TestNavXhtmlTemplate:
    """Tests for the NAV_XHTML template structure."""

    def test_nav_xhtml_structure(self):
        """Test that NAV_XHTML template has correct EPUB 3 structure."""
        template = SafariBooks.NAV_XHTML

        # Check XML declaration
        assert '<?xml version="1.0" encoding="utf-8"?>' in template

        # Check HTML5 doctype
        assert '<!DOCTYPE html>' in template

        # Check EPUB namespace
        assert 'xmlns:epub="http://www.idpf.org/2007/ops"' in template

        # Check nav element with epub:type
        assert 'epub:type="toc"' in template
        assert '<nav' in template

        # Check for ordered list structure
        assert '<ol>' in template
        assert '</ol>' in template

    def test_nav_xhtml_format_placeholders(self):
        """Test that NAV_XHTML has correct format placeholders."""
        template = SafariBooks.NAV_XHTML

        # Should have {0} for title and {1} for nav items
        assert '{0}' in template
        assert '{1}' in template


class TestContentOpfTemplate:
    """Tests for the CONTENT_OPF template (EPUB v3)."""

    def test_content_opf_version_3(self):
        """Test that CONTENT_OPF uses version 3.0."""
        template = SafariBooks.CONTENT_OPF
        assert 'version="3.0"' in template

    def test_content_opf_has_nav_item(self):
        """Test that CONTENT_OPF includes nav.xhtml in manifest."""
        template = SafariBooks.CONTENT_OPF
        assert 'nav.xhtml' in template
        assert 'properties="nav"' in template

    def test_content_opf_has_dcterms_modified(self):
        """Test that CONTENT_OPF includes dcterms:modified metadata."""
        template = SafariBooks.CONTENT_OPF
        assert 'dcterms:modified' in template
        assert '{12}' in template  # Placeholder for modified timestamp

    def test_content_opf_has_ncx_for_backwards_compat(self):
        """Test that CONTENT_OPF still includes NCX for backwards compatibility."""
        template = SafariBooks.CONTENT_OPF
        assert 'toc.ncx' in template
        assert 'application/x-dtbncx+xml' in template

    def test_content_opf_no_opf_namespace_in_metadata(self):
        """Test that CONTENT_OPF doesn't use opf: namespace (EPUB 3)."""
        template = SafariBooks.CONTENT_OPF
        # EPUB 3 doesn't require opf: namespace prefix
        assert 'xmlns:opf' not in template


class TestTocNcxTemplate:
    """Tests for the TOC_NCX template (backwards compatibility)."""

    def test_toc_ncx_structure(self):
        """Test that TOC_NCX template has correct NCX structure."""
        template = SafariBooks.TOC_NCX

        # Check NCX doctype
        assert 'DOCTYPE ncx' in template

        # Check NCX namespace
        assert 'xmlns="http://www.daisy.org/z3986/2005/ncx/"' in template

        # Check required elements
        assert '<navMap>' in template
        assert '</navMap>' in template
        assert '<docTitle>' in template
        assert '<docAuthor>' in template


class TestParseToc:
    """Tests for the original parse_toc() method (NCX generation)."""

    def test_parse_toc_simple(self):
        """Test parsing TOC for NCX format."""
        toc_data = [
            {
                "href": "chapter01.html",
                "label": "Chapter 1",
                "fragment": "ch01",
                "id": "chapter01",
                "depth": "1",
                "children": []
            }
        ]
        result, count, max_depth = SafariBooks.parse_toc(toc_data)

        assert '<navPoint' in result
        assert 'playOrder="1"' in result
        assert '<navLabel><text>Chapter 1</text></navLabel>' in result
        assert 'chapter01.xhtml' in result
        assert count == 1
        assert max_depth == 1

    def test_parse_toc_nested(self):
        """Test parsing nested TOC for NCX format."""
        toc_data = [
            {
                "href": "part01.html",
                "label": "Part 1",
                "fragment": "part1",
                "id": "part01",
                "depth": "1",
                "children": [
                    {
                        "href": "chapter01.html",
                        "label": "Chapter 1",
                        "fragment": "ch01",
                        "id": "chapter01",
                        "depth": "2",
                        "children": []
                    }
                ]
            }
        ]
        result, count, max_depth = SafariBooks.parse_toc(toc_data)

        assert result.count('<navPoint') == 2
        assert result.count('</navPoint>') == 2
        assert max_depth == 2
        assert count == 2


class TestContainerXml:
    """Tests for the CONTAINER_XML template."""

    def test_container_xml_structure(self):
        """Test that CONTAINER_XML has correct structure."""
        template = SafariBooks.CONTAINER_XML

        assert '<?xml version="1.0"?>' in template
        assert 'urn:oasis:names:tc:opendocument:xmlns:container' in template
        assert 'OEBPS/content.opf' in template
        assert 'application/oebps-package+xml' in template


class TestEpubZipStructure:
    """Tests for EPUB ZIP file structure compliance."""

    def test_create_epub_zip_mimetype_first(self, tmp_path):
        """Test that mimetype is the first file in the ZIP archive."""
        import zipfile

        # Create a mock EPUB structure
        book_path = tmp_path / "book"
        book_path.mkdir()
        oebps_path = book_path / "OEBPS"
        oebps_path.mkdir()
        meta_inf = book_path / "META-INF"
        meta_inf.mkdir()

        # Create required files
        (book_path / "mimetype").write_text("application/epub+zip")
        (meta_inf / "container.xml").write_text("<container/>")
        (oebps_path / "content.opf").write_text("<package/>")
        (oebps_path / "chapter.xhtml").write_text("<html/>")

        # Create mock SafariBooks instance
        mock_safari = MagicMock()
        mock_safari.BOOK_PATH = str(book_path)

        # Call the method
        epub_path = tmp_path / "test.epub"
        SafariBooks._create_epub_zip(mock_safari, str(epub_path))

        # Verify mimetype is first
        with zipfile.ZipFile(epub_path, 'r') as epub:
            file_list = epub.namelist()
            assert file_list[0] == "mimetype", "mimetype must be first file in archive"

    def test_create_epub_zip_mimetype_uncompressed(self, tmp_path):
        """Test that mimetype is stored uncompressed (ZIP_STORED)."""
        import zipfile

        # Create a mock EPUB structure
        book_path = tmp_path / "book"
        book_path.mkdir()
        (book_path / "mimetype").write_text("application/epub+zip")

        # Create mock SafariBooks instance
        mock_safari = MagicMock()
        mock_safari.BOOK_PATH = str(book_path)

        # Call the method
        epub_path = tmp_path / "test.epub"
        SafariBooks._create_epub_zip(mock_safari, str(epub_path))

        # Verify mimetype is uncompressed
        with zipfile.ZipFile(epub_path, 'r') as epub:
            mimetype_info = epub.getinfo("mimetype")
            assert mimetype_info.compress_type == zipfile.ZIP_STORED, \
                "mimetype must be stored uncompressed"

    def test_create_epub_zip_other_files_compressed(self, tmp_path):
        """Test that other files are compressed with DEFLATE."""
        import zipfile

        # Create a mock EPUB structure
        book_path = tmp_path / "book"
        book_path.mkdir()
        oebps_path = book_path / "OEBPS"
        oebps_path.mkdir()

        # Create files
        (book_path / "mimetype").write_text("application/epub+zip")
        # Create a larger file to ensure compression is actually applied
        large_content = "<html>" + ("x" * 1000) + "</html>"
        (oebps_path / "chapter.xhtml").write_text(large_content)

        # Create mock SafariBooks instance
        mock_safari = MagicMock()
        mock_safari.BOOK_PATH = str(book_path)

        # Call the method
        epub_path = tmp_path / "test.epub"
        SafariBooks._create_epub_zip(mock_safari, str(epub_path))

        # Verify other files are compressed
        with zipfile.ZipFile(epub_path, 'r') as epub:
            chapter_info = epub.getinfo("OEBPS/chapter.xhtml")
            assert chapter_info.compress_type == zipfile.ZIP_DEFLATED, \
                "Content files should be compressed with DEFLATE"

    def test_create_epub_zip_excludes_epub_file(self, tmp_path):
        """Test that .epub files are not included in the archive."""
        import zipfile

        # Create a mock EPUB structure
        book_path = tmp_path / "book"
        book_path.mkdir()

        # Create files including an existing .epub
        (book_path / "mimetype").write_text("application/epub+zip")
        (book_path / "existing.epub").write_bytes(b"fake epub content")

        # Create mock SafariBooks instance
        mock_safari = MagicMock()
        mock_safari.BOOK_PATH = str(book_path)

        # Call the method
        epub_path = tmp_path / "test.epub"
        SafariBooks._create_epub_zip(mock_safari, str(epub_path))

        # Verify .epub files are not included
        with zipfile.ZipFile(epub_path, 'r') as epub:
            file_list = epub.namelist()
            assert not any(f.endswith('.epub') for f in file_list), \
                ".epub files should not be included in the archive"

    def test_create_epub_zip_compression_reduces_size(self, tmp_path):
        """Test that compression actually reduces file size."""
        import zipfile

        # Create a mock EPUB structure with compressible content
        book_path = tmp_path / "book"
        book_path.mkdir()
        oebps_path = book_path / "OEBPS"
        oebps_path.mkdir()

        (book_path / "mimetype").write_text("application/epub+zip")
        # Create highly compressible content (repeated pattern)
        compressible_content = "<html>" + ("abcdefghij" * 1000) + "</html>"
        chapter_file = oebps_path / "chapter.xhtml"
        chapter_file.write_text(compressible_content)
        original_size = chapter_file.stat().st_size

        # Create mock SafariBooks instance
        mock_safari = MagicMock()
        mock_safari.BOOK_PATH = str(book_path)

        # Call the method
        epub_path = tmp_path / "test.epub"
        SafariBooks._create_epub_zip(mock_safari, str(epub_path))

        # Verify compression reduced size
        with zipfile.ZipFile(epub_path, 'r') as epub:
            chapter_info = epub.getinfo("OEBPS/chapter.xhtml")
            compressed_size = chapter_info.compress_size
            assert compressed_size < original_size, \
                f"Compression should reduce size: {compressed_size} < {original_size}"
