#!/usr/bin/env python3
# coding: utf-8
import re
import os
import sys
import copy
import json
import time
import shutil
import pathlib
import getpass
import logging
import argparse
import requests
import tinycss2 as tc
import functools
import traceback
from html import escape
from random import random
from lxml import html, etree
from bs4 import BeautifulSoup as bs
from multiprocessing import Process, Queue, Value
from urllib.parse import urljoin, urlparse, parse_qs, quote_plus


PATH = os.path.dirname(os.path.realpath(__file__))
COOKIES_FILE = os.path.join(PATH, "cookies.json")

ORLY_BASE_HOST = "oreilly.com"  # PLEASE INSERT URL HERE

SAFARI_BASE_HOST = "learning." + ORLY_BASE_HOST
API_ORIGIN_HOST = "api." + ORLY_BASE_HOST

ORLY_BASE_URL = "https://www." + ORLY_BASE_HOST
SAFARI_BASE_URL = "https://" + SAFARI_BASE_HOST
API_ORIGIN_URL = "https://" + API_ORIGIN_HOST
PROFILE_URL = SAFARI_BASE_URL + "/profile/"

SB_THEME_FILE = "override_v1.css"

APIVER = 2
APIV2_PREFIX = "chapter:"
APIV2_OPT_SEP = r"%2f"

MODERATE = True     # whether to pause between downloads to reduce load on the server
MODERATE_LEN = 0.3  # how long to pause

# DEBUG
USE_PROXY = False
PROXIES = {"https": "https://127.0.0.1:8080"}


class Display:
    BASE_FORMAT = logging.Formatter(
        fmt="[%(asctime)s] %(message)s",
        datefmt="%d/%b/%Y %H:%M:%S"
    )

    SH_DEFAULT = "\033[0m" if "win" not in sys.platform else ""  # TODO: colors for Windows
    SH_YELLOW = "\033[33m" if "win" not in sys.platform else ""
    SH_BG_RED = "\033[41m" if "win" not in sys.platform else ""
    SH_BG_YELLOW = "\033[43m" if "win" not in sys.platform else ""

    def __init__(self, log_file):
        self.output_dir = ""
        self.output_dir_set = False
        self.log_file = os.path.join(PATH, log_file)

        self.logger = logging.getLogger("SafariBooks")
        self.logger.setLevel(logging.INFO)
        logs_handler = logging.FileHandler(filename=self.log_file)
        logs_handler.setFormatter(self.BASE_FORMAT)
        logs_handler.setLevel(logging.INFO)
        self.logger.addHandler(logs_handler)

        self.columns, _ = shutil.get_terminal_size()

        self.logger.info("** Welcome to SafariBooks! **")

        self.book_ad_info = False
        self.css_ad_info = Value("i", 0)
        self.fonts_ad_info = Value("i", 0)
        self.images_ad_info = Value("i", 0)
        self.last_request = (None,)
        self.in_error = False

        self.state_status = Value("i", 0)
        sys.excepthook = self.unhandled_exception

    def set_output_dir(self, output_dir):
        self.info("Output directory:\n    %s" % output_dir)
        self.output_dir = output_dir
        self.output_dir_set = True

    def unregister(self):
        self.logger.handlers[0].close()
        sys.excepthook = sys.__excepthook__

    def log(self, message):
        try:
            self.logger.info(str(message, "utf-8", "replace"))

        except (UnicodeDecodeError, Exception):
            self.logger.info(message)

    def out(self, put):
        pattern = "\r{!s}\r{!s}\n"
        try:
            s = pattern.format(" " * self.columns, str(put, "utf-8", "replace"))

        except TypeError:
            s = pattern.format(" " * self.columns, put)

        sys.stdout.write(s)

    def info(self, message, state=False):
        self.log(message)
        output = (self.SH_YELLOW + "[*]" + self.SH_DEFAULT if not state else
                  self.SH_BG_YELLOW + "[-]" + self.SH_DEFAULT) + " %s" % message
        self.out(output)

    def error(self, error):
        if not self.in_error:
            self.in_error = True

        self.log(error)
        output = self.SH_BG_RED + "[#]" + self.SH_DEFAULT + " %s" % error
        self.out(output)

    def exit(self, error):
        self.error(str(error))

        if self.output_dir_set:
            output = (self.SH_YELLOW + "[+]" + self.SH_DEFAULT +
                      " Please delete the output directory '" + self.output_dir + "'"
                      " and restart the program.")
            self.out(output)

        output = self.SH_BG_RED + "[!]" + self.SH_DEFAULT + " Aborting..."
        self.out(output)

        self.save_last_request()
        sys.exit(1)

    def unhandled_exception(self, _, o, tb):
        self.log("".join(traceback.format_tb(tb)))
        self.exit("Unhandled Exception: %s (type: %s)" % (o, o.__class__.__name__))

    def save_last_request(self):
        if any(self.last_request):
            self.log("Last request done:\n\tURL: {0}\n\tDATA: {1}\n\tOTHERS: {2}\n\n\t{3}\n{4}\n\n{5}\n"
                     .format(*self.last_request))

    def intro(self):
        output = self.SH_YELLOW + ("""
       ____     ___         _
      / __/__ _/ _/__ _____(_)
     _\ \/ _ `/ _/ _ `/ __/ /
    /___/\_,_/_/ \_,_/_/ /_/
      / _ )___  ___  / /__ ___
     / _  / _ \/ _ \/  '_/(_-<
    /____/\___/\___/_/\_\/___/
""" if random() > 0.5 else """
 ██████╗     ██████╗ ██╗  ██╗   ██╗██████╗
██╔═══██╗    ██╔══██╗██║  ╚██╗ ██╔╝╚════██╗
██║   ██║    ██████╔╝██║   ╚████╔╝   ▄███╔╝
██║   ██║    ██╔══██╗██║    ╚██╔╝    ▀▀══╝
╚██████╔╝    ██║  ██║███████╗██║     ██╗
 ╚═════╝     ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝
""") + self.SH_DEFAULT
        output += "\n" + "~" * (self.columns // 2)

        self.out(output)

    def parse_description(self, desc):
        if not desc:
            return "n/d"

        try:
            return html.fromstring(desc).text_content()

        except (html.etree.ParseError, html.etree.ParserError) as e:
            self.log("Error parsing the description: %s" % e)
            return "n/d"

    def book_info(self, info):
        if APIVER == 1:
            relkey = "issued"
            description = info.get("description", None)
            description = self.parse_description(description).replace("\n", " ")
        elif APIVER == 2:
            relkey = "publication_date"
            description = info.get("descriptions", {})
            description = description.get("text/plain", None)
        for t in [
            ("Title", info.get("title", "")), ("Authors", ", ".join(aut.get("name", "") for aut in info.get("authors", []))),
            ("Identifier", info.get("identifier", "")), ("ISBN", info.get("isbn", "")),
            ("Publishers", ", ".join(pub.get("name", "") for pub in info.get("publishers", []))),
            ("Rights", info.get("rights", "")),
            ("Description", description[:500] + "..." if len(description) >= 500 else description),
            ("Release Date", info.get(relkey, "")),
            ("URL", info.get("web_url", ""))
        ]:
            self.info("{0}{1}{2}: {3}".format(self.SH_YELLOW, t[0], self.SH_DEFAULT, t[1]), True)

    def state(self, origin, done):
        progress = int(done * 100 / origin)
        bar = int(progress * (self.columns - 11) / 100)
        if self.state_status.value < progress:
            self.state_status.value = progress
            sys.stdout.write(
                "\r    " + self.SH_BG_YELLOW + "[" + ("#" * bar).ljust(self.columns - 11, "-") + "]" +
                self.SH_DEFAULT + ("%4s" % progress) + "%" + ("\n" if progress == 100 else "")
            )

    def done(self, epub_file):
        self.info("Done: %s\n\n" % epub_file +
                  "    If you like it, please * this project on GitHub to make it known:\n"
                  "        https://github.com/lorenzodifuccia/safaribooks\n"
                  "    e don't forget to renew your Safari Books Online subscription:\n"
                  "        " + SAFARI_BASE_URL + "\n\n" +
                  self.SH_BG_RED + "[!]" + self.SH_DEFAULT + " Bye!!")

    @staticmethod
    def api_error(response):
        message = "API: "
        if "detail" in response and "Not found" in response["detail"]:
            message += "book's not present in Safari Books Online.\n" \
                       "    The book identifier is the digits that you can find in the URL:\n" \
                       "    `" + SAFARI_BASE_URL + "/library/view/book-name/XXXXXXXXXXXXX/`"

        else:
            os.remove(COOKIES_FILE)
            message += "Out-of-Session%s.\n" % (" (%s)" % response["detail"]) if "detail" in response else "" + \
                       Display.SH_YELLOW + "[+]" + Display.SH_DEFAULT + \
                       " Use the `--cred` or `--login` options in order to perform the auth login to Safari."

        return message


class WinQueue(list):  # TODO: error while use `process` in Windows: can't pickle _thread.RLock objects
    def put(self, el):
        self.append(el)

    def qsize(self):
        return self.__len__()


class SafariBooks:
    LOGIN_URL = ORLY_BASE_URL + "/member/auth/login/"
    LOGIN_ENTRY_URL = SAFARI_BASE_URL + "/login/unified/?next=/home/"
    
    APIV1_INFO = SAFARI_BASE_URL + "/api/v1/book/{0}/"
    API_TEMPLATE = SAFARI_BASE_URL + "/api/v2/epubs/urn:orm:book:{0}/"
    API_VER_STR = "apiv2"

    IMAGES_BASE = "Images/"

    BASE_01_HTML = "<!DOCTYPE html>\n" \
                   "<html lang=\"en\" xml:lang=\"en\" xmlns=\"http://www.w3.org/1999/xhtml\"" \
                   " xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"" \
                   " xsi:schemaLocation=\"http://www.w3.org/2002/06/xhtml2/" \
                   " http://www.w3.org/MarkUp/SCHEMA/xhtml2.xsd\"" \
                   " xmlns:epub=\"http://www.idpf.org/2007/ops\">\n" \
                   "<head>\n" \
                   "{0}\n" \
                   "<style type=\"text/css\">" \
                   "body{{margin:1em;background-color:transparent!important;}}" \
                   "#sbo-rt-content *{{text-indent:0pt!important;}}#sbo-rt-content .bq{{margin-right:1em!important;}}" \
                   "img{{height: auto;max-width:100%}}" \
                   "pre {{background-color:#EEF2F6 !important;padding:0.75em 1.500em !important;}}"

    KINDLE_HTML = "#sbo-rt-content *{{word-wrap:break-word!important;" \
                  "word-break:break-word!important;}}#sbo-rt-content table,#sbo-rt-content pre" \
                  "{{overflow-x:unset!important;overflow:unset!important;" \
                  "overflow-y:unset!important;white-space:pre-wrap!important;}}"

    BASE_02_HTML = "</style>" \
                   "</head>\n" \
                   "<body><div class=\"ucvMode-{2}\"><div id=\"book-content\">{1}</div></div></body>\n</html>"

    CONTAINER_XML = "<?xml version=\"1.0\"?>" \
                    "<container version=\"1.0\" xmlns=\"urn:oasis:names:tc:opendocument:xmlns:container\">" \
                    "<rootfiles>" \
                    "<rootfile full-path=\"OEBPS/content.opf\" media-type=\"application/oebps-package+xml\" />" \
                    "</rootfiles>" \
                    "</container>"

    # Format: ID, Title, Authors, Description, Subjects, Publisher, Rights, Date, CoverId, MANIFEST, SPINE, CoverUrl
    CONTENT_OPF = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" \
                  "<package xmlns=\"http://www.idpf.org/2007/opf\" unique-identifier=\"bookid\" version=\"2.0\" >\n" \
                  "<metadata xmlns:dc=\"http://purl.org/dc/elements/1.1/\" " \
                  " xmlns:opf=\"http://www.idpf.org/2007/opf\">\n" \
                  "<dc:title>{1}</dc:title>\n" \
                  "{2}\n" \
                  "<dc:description>{3}</dc:description>\n" \
                  "{4}" \
                  "<dc:publisher>{5}</dc:publisher>\n" \
                  "<dc:rights>{6}</dc:rights>\n" \
                  "<dc:language>en-US</dc:language>\n" \
                  "<dc:date>{7}</dc:date>\n" \
                  "<dc:identifier id=\"bookid\">{0}</dc:identifier>\n" \
                  "<meta name=\"cover\" content=\"{8}\"/>\n" \
                  "</metadata>\n" \
                  "<manifest>\n" \
                  "<item id=\"ncx\" href=\"toc.ncx\" media-type=\"application/x-dtbncx+xml\" />\n" \
                  "{9}\n" \
                  "</manifest>\n" \
                  "<spine toc=\"ncx\">\n{10}</spine>\n" \
                  "<guide><reference href=\"{11}\" title=\"Cover\" type=\"cover\" /></guide>\n" \
                  "</package>"

    # Format: ID, Depth, Title, Author, NAVMAP
    TOC_NCX = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"no\" ?>\n" \
              "<!DOCTYPE ncx PUBLIC \"-//NISO//DTD ncx 2005-1//EN\"" \
              " \"http://www.daisy.org/z3986/2005/ncx-2005-1.dtd\">\n" \
              "<ncx xmlns=\"http://www.daisy.org/z3986/2005/ncx/\" version=\"2005-1\">\n" \
              "<head>\n" \
              "<meta content=\"ID:ISBN:{0}\" name=\"dtb:uid\"/>\n" \
              "<meta content=\"{1}\" name=\"dtb:depth\"/>\n" \
              "<meta content=\"0\" name=\"dtb:totalPageCount\"/>\n" \
              "<meta content=\"0\" name=\"dtb:maxPageNumber\"/>\n" \
              "</head>\n" \
              "<docTitle><text>{2}</text></docTitle>\n" \
              "<docAuthor><text>{3}</text></docAuthor>\n" \
              "<navMap>{4}</navMap>\n" \
              "</ncx>"

    HEADERS = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
        "Accept-Encoding": "gzip, deflate",
        "Referer": LOGIN_ENTRY_URL,
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/90.0.4430.212 Safari/537.36"
    }

    COOKIE_FLOAT_MAX_AGE_PATTERN = re.compile(r'(max-age=\d*\.\d*)', re.IGNORECASE)

    def __init__(self, args):
        self.args = args

        APIVER = self.args.api
        if APIVER == 1:
            SafariBooks.API_TEMPLATE = SAFARI_BASE_URL + "/api/v1/book/{0}/"
            SafariBooks.API_VER_STR = "apiv1"
        
        MODERATE_LEN = self.args.delay
        if self.args.delay == 0:
            MODERATE = False

        self.display = Display("info_%s.log" % escape(args.bookid))
        self.display.intro()
            
        if APIVER == 1:
            chapter_url_key = "chapter_list"
            filekey = "filename"
            fprefix = ""
        elif APIVER == 2:
            chapter_url_key = "chapters"
            filekey = "ourn"
            fprefix = "ourn:"
            # cover_re = re.compile("chapter:.*?(%2f){0,1}cover")
            # toc_re = re.compile("chapter:.*?(%2f){0,1}toc")

        self.session = requests.Session()
        if USE_PROXY:  # DEBUG
            self.session.proxies = PROXIES
            self.session.verify = False

        self.session.headers.update(self.HEADERS)

        self.jwt = {}

        if not args.cred:
            if not os.path.isfile(COOKIES_FILE):
                self.display.exit("Login: unable to find `cookies.json` file.\n"
                                  "    Please use the `--cred` or `--login` options to perform the login.")

            self.session.cookies.update(json.load(open(COOKIES_FILE)))

        else:
            self.display.info("Logging into Safari Books Online...", state=True)
            self.do_login(*args.cred)
            if not args.no_cookies:
                json.dump(self.session.cookies.get_dict(), open(COOKIES_FILE, 'w'))

        self.check_login()

        self.book_id = args.bookid
        self.api_url = self.API_TEMPLATE.format(self.book_id)

        self.display.info("Retrieving book info...")
        self.book_info = self.get_book_info()
        self.display.book_info(self.book_info)

        self.display.info("Retrieving book chapters...")
        self.book_chapters = self.get_book_chapters(self.book_info[chapter_url_key])
        if APIVER == 2:
            for c in self.book_chapters:
                if "cover" in self.get_filename(c):
                    c_images = c["related_assets"].get("images",[])
                    if len(c_images) : self.book_info["cover"] = c_images[0]
                    break

        self.chapters_queue = self.book_chapters[:]

        if len(self.book_chapters) > sys.getrecursionlimit():
            sys.setrecursionlimit(len(self.book_chapters))

        self.book_title = self.book_info["title"]
        self.base_url = self.book_info["web_url"]

        self.clean_book_title = "".join(self.escape_dirname(self.book_title).split(",")[:2]) \
                                + " ({0})".format(self.book_id)

        books_dir = os.path.join(PATH, "Books")
        if not os.path.isdir(books_dir):
            os.mkdir(books_dir)

        self.BOOK_PATH = os.path.join(books_dir, self.clean_book_title)
        self.display.set_output_dir(self.BOOK_PATH)
        self.css_path = ""
        self.images_path = ""
        self.create_dirs()

        self.chapter_title = ""
        self.filename = ""
        self.chapter_stylesheets = []
        self.css = []
        self.fonts = []
        self.images = []
        self.images2 = []   # used to record all image links discovered when replacing links

        self.display.info("Downloading book contents... (%s chapters)" % len(self.book_chapters), state=True)
        self.BASE_HTML = self.BASE_01_HTML + (self.KINDLE_HTML if args.kindle else "") + self.BASE_02_HTML

        self.cover = False
        self.get()
        if not self.cover:
            self.display.info(f"'cover' field is: {self.cover}")
            if "cover" in self.book_info : self.cover = self.get_default_cover()
            cover_html = self.parse_html(
                html.fromstring("<div id=\"sbo-rt-content\"><img src=\"{0}\"></div>".format(self.cover)), True
            )

            self.book_chapters = [{
                filekey: f"{fprefix}default_cover.xhtml",
                "title": "Cover"
            }] + self.book_chapters

            self.filename = self.get_filename(self.book_chapters[0])
            self.save_page_html(cover_html)

        self.css_done_queue = Queue(0) if "win" not in sys.platform else WinQueue()
        self.display.info("Downloading book CSSs... (%s files)" % len(self.css), state=True)
        self.collect_css()
        self.fonts_done_queue = Queue(0) if "win" not in sys.platform else WinQueue()
        self.display.info("Downloading book fonts... (%s files)" % len(self.fonts), state=True)
        self.collect_fonts()
        self.images_done_queue = Queue(0) if "win" not in sys.platform else WinQueue()
        self.display.info("Downloading book images... (%s files)" % len(self.images), state=True)
        self.collect_images()

        self.display.info("Creating EPUB file...", state=True)
        self.create_epub()

        if not args.no_cookies:
            json.dump(self.session.cookies.get_dict(), open(COOKIES_FILE, "w"))

        self.display.done(os.path.join(self.BOOK_PATH, self.book_id + ".epub"))
        self.display.unregister()

        if not self.display.in_error and not args.log:
            os.remove(self.display.log_file)

    @staticmethod
    def get_filename(chapter):
        if APIVER == 1:
            return chapter["filename"]
        elif APIVER == 2:
            # "ourn" looks like urn:orm:book:XXXXXXXXXXX:chapter:Text%2fcover.xhtml
            # or urn:orm:book:XXXXXXXXXXX:chapter:cover.xhtm
            return chapter["ourn"].rsplit(APIV2_PREFIX,1)[-1].rsplit(APIV2_OPT_SEP,1)[-1]
        return "NONE"

    def handle_cookie_update(self, set_cookie_headers):
        for morsel in set_cookie_headers:
            # Handle Float 'max-age' Cookie
            if self.COOKIE_FLOAT_MAX_AGE_PATTERN.search(morsel):
                cookie_key, cookie_value = morsel.split(";")[0].split("=")
                self.session.cookies.set(cookie_key, cookie_value)

    def requests_provider(self, url, is_post=False, data=None, perform_redirect=True, **kwargs):
        try:
            response = getattr(self.session, "post" if is_post else "get")(
                url,
                data=data,
                allow_redirects=False,
                **kwargs
            )

            self.handle_cookie_update(response.raw.headers.getlist("Set-Cookie"))

            self.display.last_request = (
                url, data, kwargs, response.status_code, "\n".join(
                    ["\t{}: {}".format(*h) for h in response.headers.items()]
                ), response.text
            )

        except (requests.ConnectionError, requests.ConnectTimeout, requests.RequestException) as request_exception:
            self.display.error(str(request_exception))
            return 0

        if response.is_redirect and perform_redirect:
            return self.requests_provider(response.next.url, is_post, None, perform_redirect)
            # TODO How about **kwargs?

        return response
    
    def local_provider(self, url):
        self.display.info(f"Using local file {url} instead of URL")
        with open(url,"r") as locf:
            response = locf.read()
            response = json.loads(response)
        return response


    @staticmethod
    def parse_cred(cred):
        if ":" not in cred:
            return False

        sep = cred.index(":")
        new_cred = ["", ""]
        new_cred[0] = cred[:sep].strip("'").strip('"')
        if "@" not in new_cred[0]:
            return False

        new_cred[1] = cred[sep + 1:]
        return new_cred

    def do_login(self, email, password):
        response = self.requests_provider(self.LOGIN_ENTRY_URL)
        if response == 0:
            self.display.exit("Login: unable to reach Safari Books Online. Try again...")

        next_parameter = None
        try:
            next_parameter = parse_qs(urlparse(response.request.url).query)["next"][0]

        except (AttributeError, ValueError, IndexError):
            self.display.exit("Login: unable to complete login on Safari Books Online. Try again...")

        redirect_uri = API_ORIGIN_URL + quote_plus(next_parameter)

        response = self.requests_provider(
            self.LOGIN_URL,
            is_post=True,
            json={
                "email": email,
                "password": password,
                "redirect_uri": redirect_uri
            },
            perform_redirect=False
        )

        if response == 0:
            self.display.exit("Login: unable to perform auth to Safari Books Online.\n    Try again...")

        if response.status_code != 200:  # TODO To be reviewed
            try:
                error_page = html.fromstring(response.text)
                errors_message = error_page.xpath("//ul[@class='errorlist']//li/text()")
                recaptcha = error_page.xpath("//div[@class='g-recaptcha']")
                messages = (["    `%s`" % error for error in errors_message
                             if "password" in error or "email" in error] if len(errors_message) else []) + \
                           (["    `ReCaptcha required (wait or do logout from the website).`"] if len(
                               recaptcha) else [])
                self.display.exit(
                    "Login: unable to perform auth login to Safari Books Online.\n" + self.display.SH_YELLOW +
                    "[*]" + self.display.SH_DEFAULT + " Details:\n" + "%s" % "\n".join(
                        messages if len(messages) else ["    Unexpected error!"])
                )
            except (html.etree.ParseError, html.etree.ParserError) as parsing_error:
                self.display.error(parsing_error)
                self.display.exit(
                    "Login: your login went wrong and it encountered in an error"
                    " trying to parse the login details of Safari Books Online. Try again..."
                )

        self.jwt = response.json()  # TODO: save JWT Tokens and use the refresh_token to restore user session
        response = self.requests_provider(self.jwt["redirect_uri"])
        if response == 0:
            self.display.exit("Login: unable to reach Safari Books Online. Try again...")

    def check_login(self):
        response = self.requests_provider(PROFILE_URL, perform_redirect=False)

        if response == 0:
            self.display.exit("Login: unable to reach Safari Books Online. Try again...")

        elif response.status_code != 200:
            self.display.exit(f"Authentication issue: unable to access profile page (status = {response.status_code}): {PROFILE_URL}")

        elif "user_type\":\"Expired\"" in response.text:
            self.display.exit("Authentication issue: account subscription expired.")

        self.display.info("Successfully authenticated.", state=True)

    def get_book_info(self):
        response = self.requests_provider(self.api_url)
        if response == 0:
            self.display.exit("API: unable to retrieve book info.")

        response = response.json()

        if not isinstance(response, dict) or len(response.keys()) == 1:
            self.display.exit(self.display.api_error(response))

        if "last_chapter_read" in response:
            del response["last_chapter_read"]

        for key, value in response.items():
            if value is None:
                response[key] = 'n/a'

        if APIVER == 2:
            response2 = self.requests_provider(self.APIV1_INFO.format(self.book_id))
            if response2 == 0:
                self.display.exit("API: unable to retrieve v1 book info.")

            response2 = response2.json()
            for k in ["authors", "subjects", "topics", "rights", "publishers", "web_url"]:
                if k in response2:
                    response[k] = response2[k]

        return response

    def get_book_chapters(self, chapter_url):
        # response = self.requests_provider(urljoin(self.api_url, "chapter/?page=%s" % page))
        response = self.requests_provider(chapter_url)
        if response == 0:
            self.display.exit("API: unable to retrieve book chapters.")

        response = response.json()

        if not isinstance(response, dict) or len(response.keys()) == 1:
            self.display.exit(self.display.api_error(response))

        if "results" not in response or not len(response["results"]):
            self.display.exit("API: unable to retrieve book chapters.")

        if response["count"] > sys.getrecursionlimit():
            sys.setrecursionlimit(response["count"])

        if APIVER == 1:
            urntype = "filename"
        elif APIVER == 2:
            urntype = "ourn"

        result = []
        result.extend([c for c in response["results"] if "cover" in self.get_filename(c)])
        for c in result:
            # the point here is to move the "cover" chapter to the front of the chapter list,
            # though this current code will only be successful if the "cover" chapter is
            # on the first page of chapter info results
            self.display.log(f'Moving chapter {response["results"].index(c)} with URN {c[urntype]} to the front of the current list')
            del response["results"][response["results"].index(c)]

        result += response["results"]
        result += (self.get_book_chapters(response["next"]) if response["next"] else [])

        # The point of this next section is to move any "table of contents" chapter to be right after
        # the "cover", unless the chapter info has "indexed_position" values in it, in which case those
        # should be used to set the position of each chapter. Note: currently the code does not check
        # whether the chapter order matches the "indexed_position" values
        toc_index = -1
        for ci,c in enumerate(result):
            if "toc" in self.get_filename(c) or c["title"] == "nav":
                if c.get("indexed_position",None) is None : toc_index = ci
                break
        if toc_index >= 0:
            self.display.log(f'Moving chapter {toc_index} with URN {c[urntype]}  to the second place of the current list')
            result.insert(1, result.pop(toc_index))

        return result

    def get_default_cover(self):
        response = self.requests_provider(self.book_info["cover"], stream=True)
        if response == 0:
            self.display.error("Error trying to retrieve the cover: %s" % self.book_info["cover"])
            return False

        file_ext = response.headers["Content-Type"].split("/")[-1]
        with open(os.path.join(self.images_path, "default_cover." + file_ext), 'wb') as i:
            for chunk in response.iter_content(1024):
                i.write(chunk)

        return "default_cover." + file_ext

    def get_html(self, url):
        response = self.requests_provider(url)
        if response == 0 or response.status_code != 200:
            self.display.exit(
                "Crawler: error trying to retrieve this page: %s (%s)\n    From: %s" %
                (self.filename, self.chapter_title, url)
            )

        root = None
        try:
            root = html.fromstring(response.text, base_url=SAFARI_BASE_URL)

        except (html.etree.ParseError, html.etree.ParserError) as parsing_error:
            self.display.error(parsing_error)
            self.display.exit(
                "Crawler: error trying to parse this page: %s (%s)\n    From: %s" %
                (self.filename, self.chapter_title, url)
            )

        return root

    @staticmethod
    def url_is_absolute(url):
        return bool(urlparse(url).netloc)

    @staticmethod
    def is_doc_link(url: str):
        return any(x in url for x in [".html", ".xhtml", ".pdf"])

    @staticmethod
    def is_image_link(url: str):
        return any(x in url for x in ["cover", "images", "graphics"]) or (pathlib.Path(url).suffix[1:].lower() in ["jpg", "jpeg", "png", "gif"])

    @staticmethod
    def str_overlap(a, b):
        # returns the index in 'b' of the first character that doesn't overlap
        # with the end of 'a'
        return max(i for i in range(len(b)+1) if a.endswith(b[:i]))

    def link_replace(self, link):
        if link and not link.startswith("mailto"):
            if not self.url_is_absolute(link):
                if not self.is_doc_link(link) and self.is_image_link(link):
                    image_name, image_path = self.local_image_path(link)
                    new_link = self.IMAGES_BASE
                    if image_path : new_link += image_path + "/"
                    new_link += image_name
                    full_link = functools.reduce(lambda a, b: a + b[self.str_overlap(a,b):], [self.book_info["url"], "/files/", link])
                    self.images2.append(full_link)
                    # self.display.info(f'[Image] Output link: {new_link}, input link: {link}, full link: {full_link}')
                    return new_link

                new_link = link.rsplit("/",1)[-1].replace(".html", ".xhtml")
                # self.display.info(f'[Non-image, relative] Output link: {new_link}, input link: {link}')
                return new_link

            else:  # URL is absolute
                if self.book_info["url"] in link:
                    # return self.link_replace(link.split(self.book_id)[-1])
                    new_link = self.link_replace(link.replace(self.book_info["url"],"").lstrip("/"))
                    # self.display.info(f'[Non-image, absolute] Output link: {new_link}, input link: {link}')
                    return new_link

        return link

    @staticmethod
    def get_cover(html_root):
        lowercase_ns = etree.FunctionNamespace(None)
        lowercase_ns["lower-case"] = lambda _, n: n[0].lower() if n and len(n) else ""

        images = html_root.xpath("//img[contains(lower-case(@id), 'cover') or contains(lower-case(@class), 'cover') or"
                                 "contains(lower-case(@name), 'cover') or contains(lower-case(@src), 'cover') or"
                                 "contains(lower-case(@alt), 'cover')]")
        if len(images):
            return images[0]

        divs = html_root.xpath("//div[contains(lower-case(@id), 'cover') or contains(lower-case(@class), 'cover') or"
                               "contains(lower-case(@name), 'cover') or contains(lower-case(@src), 'cover')]//img")
        if len(divs):
            return divs[0]

        a = html_root.xpath("//a[contains(lower-case(@id), 'cover') or contains(lower-case(@class), 'cover') or"
                            "contains(lower-case(@name), 'cover') or contains(lower-case(@src), 'cover')]//img")
        if len(a):
            return a[0]

        images = html_root.xpath("//img")
        if len(images) == 1:
            return images[0]

        return None

    def parse_html(self, root, first_page=False):
        if random() > 0.8:
            if len(root.xpath("//div[@class='controls']/a/text()")):
                self.display.exit(self.display.api_error(" "))

        book_content = root.xpath("//div[@id='sbo-rt-content']")
        if not len(book_content):
            self.display.exit(
                "Parser: book content's corrupted or not present: %s (%s)" %
                (self.filename, self.chapter_title)
            )

        page_css = ""
        if self.args.theme != 'none':
            page_css += f"<link href=\"Styles/{SB_THEME_FILE}\" rel=\"stylesheet\" type=\"text/css\" />"
            src_sb_css = pathlib.Path(PATH) / pathlib.Path(SB_THEME_FILE)
            sb_css_file = pathlib.Path(self.css_path) / pathlib.Path(SB_THEME_FILE)
            sb_css_file.write_bytes(src_sb_css.read_bytes())
        if len(self.chapter_stylesheets):
            for chapter_css_url in self.chapter_stylesheets:
                if chapter_css_url not in self.css:
                    self.css.append(chapter_css_url)
                    self.display.log("Crawler: found a new CSS at %s" % chapter_css_url)

                page_css += "<link href=\"Styles/Style{0:0>2}.css\" " \
                            "rel=\"stylesheet\" type=\"text/css\" />\n".format(self.css.index(chapter_css_url))

        stylesheet_links = root.xpath("//link[@rel='stylesheet']")
        if len(stylesheet_links):
            for s in stylesheet_links:
                css_url = urljoin("https:", s.attrib["href"]) if s.attrib["href"][:2] == "//" \
                    else urljoin(self.base_url, s.attrib["href"])

                if css_url not in self.css:
                    self.css.append(css_url)
                    self.display.log("Crawler: found a new CSS at %s" % css_url)

                page_css += "<link href=\"Styles/Style{0:0>2}.css\" " \
                            "rel=\"stylesheet\" type=\"text/css\" />\n".format(self.css.index(css_url))

        stylesheets = root.xpath("//style")
        if len(stylesheets):
            for css in stylesheets:
                if "data-template" in css.attrib and len(css.attrib["data-template"]):
                    css.text = css.attrib["data-template"]
                    del css.attrib["data-template"]

                try:
                    page_css += html.tostring(css, method="xml", encoding='unicode') + "\n"

                except (html.etree.ParseError, html.etree.ParserError) as parsing_error:
                    self.display.error(parsing_error)
                    self.display.exit(
                        "Parser: error trying to parse one CSS found in this page: %s (%s)" %
                        (self.filename, self.chapter_title)
                    )

        # TODO: add all not covered tag for `link_replace` function
        svg_image_tags = root.xpath("//image")
        if len(svg_image_tags):
            for img in svg_image_tags:
                image_attr_href = [x for x in img.attrib.keys() if "href" in x]
                if len(image_attr_href):
                    svg_url = img.attrib.get(image_attr_href[0])
                    svg_root = img.getparent().getparent()
                    new_img = svg_root.makeelement("img")
                    new_img.attrib.update({"src": svg_url})
                    svg_root.remove(img.getparent())
                    svg_root.append(new_img)

        book_content = book_content[0]
        book_content.rewrite_links(self.link_replace)

        xhtml = None
        try:
            if first_page:
                is_cover = self.get_cover(book_content)
                if is_cover is not None:
                    page_css = "<style>" \
                               "body{display:table;position:absolute;margin:0!important;height:100%;width:100%;}" \
                               "#Cover{display:table-cell;vertical-align:middle;text-align:center;}" \
                               "img{height:90vh;margin-left:auto;margin-right:auto;}" \
                               "</style>"
                    cover_html = html.fromstring("<div id=\"Cover\"></div>")
                    cover_div = cover_html.xpath("//div")[0]
                    cover_img = cover_div.makeelement("img")
                    cover_img.attrib.update({"src": is_cover.attrib["src"]})
                    cover_div.append(cover_img)
                    book_content = cover_html

                    self.cover = is_cover.attrib["src"]

            xhtml = html.tostring(book_content, method="xml", encoding='unicode')

        except (html.etree.ParseError, html.etree.ParserError) as parsing_error:
            self.display.error(parsing_error)
            self.display.exit(
                "Parser: error trying to parse HTML of this page: %s (%s)" %
                (self.filename, self.chapter_title)
            )

        return page_css, xhtml

    @staticmethod
    def escape_dirname(dirname, clean_space=False):
        if ":" in dirname:
            if dirname.index(":") > 15:
                dirname = dirname.split(":")[0]

            elif "win" in sys.platform:
                dirname = dirname.replace(":", ",")

        for ch in ['~', '#', '%', '&', '*', '{', '}', '\\', '<', '>', '?', '/', '`', '\'', '"', '|', '+', ':']:
            if ch in dirname:
                dirname = dirname.replace(ch, "_")

        return dirname if not clean_space else dirname.replace(" ", "")

    def create_dirs(self):
        if os.path.isdir(self.BOOK_PATH):
            self.display.log("Book directory already exists: %s" % self.BOOK_PATH)

        else:
            os.makedirs(self.BOOK_PATH)

        oebps = os.path.join(self.BOOK_PATH, "OEBPS")
        if not os.path.isdir(oebps):
            self.display.book_ad_info = True
            os.makedirs(oebps)
            self.display.log(f"Created OEBPS directory {oebps}")

        self.css_path = os.path.join(oebps, "Styles")
        if os.path.isdir(self.css_path):
            self.display.log("CSSs directory already exists: %s" % self.css_path)

        else:
            os.makedirs(self.css_path)
            self.display.css_ad_info.value = 1

        self.images_path = os.path.join(oebps, "Images")
        if os.path.isdir(self.images_path):
            self.display.log("Images directory already exists: %s" % self.images_path)

        else:
            os.makedirs(self.images_path)
            self.display.images_ad_info.value = 1


    def fix_overconstrained_images(self, txt):
        # Remove inline 'width' and 'height' attributes from img tags that also have a style='height:XXem'
        # type of attribute
        fixed_n = 0
        tsoup = bs(txt, 'html.parser')
        for img in tsoup.find_all('img'):
            img_style = img.get('style') 
            if img_style and ('width' in img_style or 'height' in img_style):
                img_width  = img.get('width')
                img_height = img.get('height')
                if img_width  : del img['width']
                if img_height : del img['height']
                if img_width or img_height : fixed_n += 1
        if fixed_n > 0 : self.display.log(f"[fix_overconstrained_images] img tags changed: {fixed_n}\n")
        return str(tsoup)

    def save_page_html(self, contents):
        theme_mode = 'white'
        if self.args.theme == 'sepia':
            theme_mode = 'sepia'
        elif self.args.theme == 'black':
            theme_mode = 'black'

        self.filename = self.filename.replace(".html", ".xhtml")
        html_text = self.BASE_HTML.format(contents[0], contents[1], theme_mode).encode("utf-8", 'xmlcharrefreplace')
        with open(os.path.join(self.BOOK_PATH, "OEBPS", self.filename), "w") as html_file:
            html_file.write(self.fix_overconstrained_images(html_text))
        self.display.log("Created: %s" % self.filename)


    def get(self):
        len_books = len(self.book_chapters)

        for _ in range(len_books):
            if not len(self.chapters_queue):
                return

            first_page = len_books == len(self.chapters_queue)

            next_chapter = self.chapters_queue.pop(0)
            self.chapter_title = next_chapter["title"]
            self.filename = self.get_filename(next_chapter)
            if APIVER == 1:
                assets_root = next_chapter
                get_image = lambda x : urljoin(next_chapter['asset_base_url'], x)
                stylesheet_url = lambda x : x["url"]
                contentkey = "content"
            elif APIVER == 2:
                assets_root = next_chapter.get("related_assets",{})
                get_image = lambda x : x
                stylesheet_url = lambda x : x
                contentkey = "content_url"

            # asset_base_url = next_chapter['asset_base_url']
            # api_v2_detected = False
            # if 'v2' in next_chapter['content']:
            #     asset_base_url = SAFARI_BASE_URL + "/api/v2/epubs/urn:orm:book:{}/files".format(self.book_id)
            #     api_v2_detected = True

            # if "images" in next_chapter and len(next_chapter["images"]):
            #     for img_url in next_chapter['images']:
            #         if api_v2_detected:
            #             self.images.append(asset_base_url + '/' + img_url)
            #         else:
            #             self.images.append(urljoin(next_chapter['asset_base_url'], img_url))

            # Images
            if "images" in assets_root and len(assets_root["images"]):
                self.images.extend(get_image(img_url) for img_url in assets_root['images'])

            # Stylesheets
            self.chapter_stylesheets = []
            if "stylesheets" in assets_root and len(assets_root["stylesheets"]):
                self.chapter_stylesheets.extend(stylesheet_url(x) for x in assets_root["stylesheets"])

            if "site_styles" in assets_root and len(assets_root["site_styles"]):
                self.chapter_stylesheets.extend(assets_root["site_styles"])

            if os.path.isfile(os.path.join(self.BOOK_PATH, "OEBPS", self.filename.replace(".html", ".xhtml"))):
                if not self.display.book_ad_info and \
                        next_chapter not in self.book_chapters[:self.book_chapters.index(next_chapter)]:
                    self.display.info(
                        ("File `%s` already exists.\n"
                         "    If you want to download again all the book,\n"
                         "    please delete the output directory '" + self.BOOK_PATH + "' and restart the program.")
                         % self.filename.replace(".html", ".xhtml")
                    )
                    self.display.book_ad_info = 2

            else:
                get_url = next_chapter[contentkey]
                self.save_page_html(self.parse_html(self.get_html(get_url), first_page))
                if MODERATE : time.sleep(MODERATE_LEN)

            self.display.state(len_books, len_books - len(self.chapters_queue))


    def _thread_download_css(self, url):
        status = 'ok'
        css_file = os.path.join(self.css_path, "Style{0:0>2}.css".format(self.css.index(url)))
        if os.path.isfile(css_file):
            if not self.display.css_ad_info.value and url not in self.css[:self.css.index(url)]:
                self.display.info(("File `%s` already exists.\n"
                                   "    If you want to download again all the CSSs,\n"
                                   "    please delete the output directory '" + self.BOOK_PATH + "'"
                                   " and restart the program.") %
                                  css_file)
                self.display.css_ad_info.value = 1
            status = 'already exists'

        else:
            response = self.requests_provider(url)
            if response == 0:
                self.display.error("Error trying to retrieve this CSS: %s\n    From: %s" % (css_file, url))

            with open(css_file, 'wb') as s:
                s.write(response.content)

            # Save any font URLs found in the stylesheet for later downloading
            # Format is: @font-face{font-family:ff1;src:url(f1.otf) format("opentype")}
            srules = tc.parse_stylesheet(response.text)
            urlparts = urlparse(url)
            baseurl = urlparts._replace(path=urlparts.path.rsplit('/',1)[0]).geturl()
            for rule in srules:
                if rule.type == 'at-rule' and rule.lower_at_keyword == 'font-face':
                    fdec = tc.parse_declaration_list(rule.content)
                    for fd in fdec:
                        if fd.name == 'src':
                            for ffield in fd.value:
                                if ffield.type == 'url':
                                    self.fonts.append((baseurl, ffield.value))

            # for ff in self.fonts:
            #     furl = ff[1] + '/' + ff[2]
            #     font_file = (pathlib.Path(ff[0]) / ff[2]).resolve()    # handle paths with '../' in them
            #     font_file.parent.mkdir(parents=True, exist_ok=True)    # create directory if needed
            #     fresponse = self.requests_provider(furl)
            #     if fresponse == 0:
            #         self.display.error("Error trying to retrieve this font: %s\n    From: %s" % (font_file, furl))
            #     with open(font_file, 'wb') as s:
            #         s.write(fresponse.content)

        self.css_done_queue.put(1)
        self.display.state(len(self.css), self.css_done_queue.qsize())
        return status


    def _thread_download_font(self, font_info):
        status = 'ok'
        url = font_info[0] + '/' + font_info[1]
        font_file = (pathlib.Path(self.css_path) / font_info[1]).resolve()    # handle paths with '../' in them
        font_file.parent.mkdir(parents=True, exist_ok=True)                  # create directory if needed
        if os.path.isfile(font_file):
            if not self.display.fonts_ad_info.value and url not in self.fonts[:self.fonts.index(url)]:
                self.display.info(("File `%s` already exists.\n"
                                   "    If you want to download again all the fonts,\n"
                                   "    please delete the output directory '" + self.BOOK_PATH + "'"
                                   " and restart the program.") %
                                  font_file)
                self.display.fonts_ad_info.value = 1
            status = 'already exists'

        else:
            response = self.requests_provider(url)
            if response == 0:
                self.display.error("Error trying to retrieve this font: %s\n    From: %s" % (font_file, url))

            with open(font_file, 'wb') as s:
                s.write(response.content)

        self.fonts_done_queue.put(1)
        self.display.state(len(self.fonts), self.fonts_done_queue.qsize())
        return status


    def local_image_path(self, full_url):
        if APIVER == 1:
            return full_url.split("/")[-1], ""
        elif APIVER == 2:
            image_dirs = ["images/","graphics/","assets/"]
            baseurl = self.book_info["url"].rstrip("/").rsplit("/",1)[1] + "/files/"
            rel_url = full_url.split(baseurl)[-1].lstrip("/")     # gives something like XXXXX/image.jpeg, XXXXX/ch02/image.png, or files/image.jpeg
            local_path = rel_url
            for imd in image_dirs:
                if local_path[0:len(imd)] == imd:
                    local_path = local_path[len(imd):]            # image.jpeg or ch02/image.png
                    break
            path_parts = local_path.rsplit("/",1)                 # [image.jpeg] or [ch02,image.png]
            imname = path_parts[-1]
            impath = path_parts[0] if len(path_parts) > 1 else ""
            return imname, impath


    def _thread_download_images(self, url):
        status = 'ok'
        image_name, image_subfolder = self.local_image_path(url)
        image_path = os.path.join(self.images_path, image_subfolder, image_name)
        if os.path.isfile(image_path):
            if not self.display.images_ad_info.value and url not in self.images[:self.images.index(url)]:
                self.display.info(("File `%s` already exists.\n"
                                   "    If you want to download again all the images,\n"
                                   "    please delete the output directory '" + self.BOOK_PATH + "'"
                                   " and restart the program.") %
                                  image_name)
                self.display.images_ad_info.value = 1
            status = 'already exists'

        else:
            response = self.requests_provider(urljoin(SAFARI_BASE_URL, url), stream=True)
            if response == 0:
                self.display.error("Error trying to retrieve this image: %s\n    From: %s" % (image_name, url))
                return

            # create any necessary subfolders in self.images_path
            pathlib.Path(os.path.join(self.images_path, image_subfolder)).mkdir(parents=True, exist_ok=True)
            with open(image_path, 'wb') as img:
                for chunk in response.iter_content(1024):
                    img.write(chunk)

        self.images_done_queue.put(1)
        self.display.state(len(self.images), self.images_done_queue.qsize())
        return status


    def _start_multiprocessing(self, operation, full_queue):
        if len(full_queue) > 5:
            for i in range(0, len(full_queue), 5):
                self._start_multiprocessing(operation, full_queue[i:i + 5])

        else:
            process_queue = [Process(target=operation, args=(arg,)) for arg in full_queue]
            for proc in process_queue:
                proc.start()

            for proc in process_queue:
                proc.join()


    def collect_css(self):
        self.display.state_status.value = -1

        # "self._start_multiprocessing" seems to cause problem. Switching to mono-thread download.
        for css_url in self.css:
            status = self._thread_download_css(css_url)
            if status == 'ok' and MODERATE : time.sleep(MODERATE_LEN)


    def collect_fonts(self):
        self.display.state_status.value = -1

        # "self._start_multiprocessing" seems to cause problem. Switching to mono-thread download.
        for font_info in self.fonts:
            status = self._thread_download_font(font_info)
            if status == 'ok' and MODERATE : time.sleep(MODERATE_LEN)


    def collect_images(self):
        if self.display.book_ad_info == 2:
            self.display.info("Some of the book contents were already downloaded.\n"
                              "    If you want to be sure that all the images will be downloaded,\n"
                              "    please delete the output directory '" + self.BOOK_PATH +
                              "' and restart the program.")

        self.display.state_status.value = -1

        # "self._start_multiprocessing" seems to cause problem. Switching to mono-thread download.
        self.images += [x for x in self.images2 if x not in self.images]
        for image_url in self.images:
            status = self._thread_download_images(image_url)
            if status == 'ok' and MODERATE : time.sleep(MODERATE_LEN)


    @staticmethod
    def get_all_files_from(basedir):
        files = []
        dirlist = [basedir]
        while len(dirlist) > 0:
            for (dirpath, dirnames, filenames) in os.walk(dirlist.pop()):
                dirlist.extend(dirnames)
                files.extend(map(lambda n: os.path.join(*n), zip([dirpath] * len(filenames), filenames)))
        return [x.replace(basedir,"").lstrip(os.sep) for x in files]


    def create_content_opf(self):
        # self.css = next(os.walk(self.css_path))[2]
        # self.images = next(os.walk(self.images_path))[2]
        self.css = self.get_all_files_from(self.css_path)
        self.images = self.get_all_files_from(self.images_path)

        manifest = []
        spine = []
        for c in self.book_chapters:
            c["filename"] = self.get_filename(c).replace(".html", ".xhtml")
            item_id = escape("".join(c["filename"].split(".")[:-1]))
            manifest.append("<item id=\"{0}\" href=\"{1}\" media-type=\"application/xhtml+xml\" />".format(
                item_id, c["filename"]
            ))
            spine.append("<itemref idref=\"{0}\"/>".format(item_id))

        for i in set(self.images):
            dot_split = i.split(".")
            head = "img_" + escape("".join(dot_split[:-1]).replace(os.sep,"_"))
            extension = dot_split[-1]
            manifest.append("<item id=\"{0}\" href=\"Images/{1}\" media-type=\"image/{2}\" />".format(
                head, i, "jpeg" if "jp" in extension else extension
            ))

        for i in range(len(self.css)):
            manifest.append("<item id=\"style_{0:0>2}\" href=\"Styles/Style{0:0>2}.css\" "
                            "media-type=\"text/css\" />".format(i))

        authors = "\n".join("<dc:creator opf:file-as=\"{0}\" opf:role=\"aut\">{0}</dc:creator>".format(
            escape(aut.get("name", "n/d"))
        ) for aut in self.book_info.get("authors", []))

        subjects = "\n".join("<dc:subject>{0}</dc:subject>".format(escape(sub.get("name", "n/d")))
                             for sub in self.book_info.get("subjects", []))

        if APIVER == 1:
            description_root = self.book_info
            desckey = "description"
            pubkey = "issued"
        elif APIVER == 2:
            description_root = self.book_info.get("descriptions",[])
            desckey = "text/plain"
            pubkey = "publication_date"
        return self.CONTENT_OPF.format(
            (self.book_info.get("isbn", self.book_id)),
            escape(self.book_title),
            authors,
            escape(description_root.get(desckey, "")),
            subjects,
            ", ".join(escape(pub.get("name", "")) for pub in self.book_info.get("publishers", [])),
            escape(self.book_info.get("rights", "")),
            self.book_info.get(pubkey, ""),
            self.cover,
            "\n".join(manifest),
            "\n".join(spine),
            self.book_chapters[0]["filename"].replace(".html", ".xhtml")
        )


    @staticmethod
    def parse_toc(l, c=0, mx=0):
        if APIVER == 1:
            # idkey = "id"
            titlekey = "label"
            href = lambda cc : cc["href"].replace(".html", ".xhtml").split("/")[-1]
        elif APIVER == 2:
            # idkey = "ourn"
            titlekey = "title"
            href = lambda cc : SafariBooks.get_filename(cc).replace(".html", ".xhtml") + "#" + cc["fragment"]

        r = ""
        for cc in l:
            c += 1
            if int(cc["depth"]) > mx:
                mx = int(cc["depth"])

            r += "<navPoint id=\"{0}\" playOrder=\"{1}\">" \
                 "<navLabel><text>{2}</text></navLabel>" \
                 "<content src=\"{3}\"/>".format(
                    cc["fragment"], c,
                    escape(cc[titlekey]), href(cc)
                 )

            if cc["children"]:
                sr, c, mx = SafariBooks.parse_toc(cc["children"], c, mx)
                r += sr

            r += "</navPoint>\n"

        return r, c, mx

    def create_toc(self, toc_url):
        # response = self.requests_provider(urljoin(self.api_url, "toc/"))
        response = self.requests_provider(toc_url)
        if response == 0:
            self.display.exit("API: unable to retrieve book chapters. "
                            "Don't delete any files, just run again this program"
                            " in order to complete the `.epub` creation!")

        response = response.json()

        if not isinstance(response, list) and len(response.keys()) == 1:
            self.display.exit(
                self.display.api_error(response) +
                " Don't delete any files, just run again this program"
                " in order to complete the `.epub` creation!"
            )

        navmap, _, max_depth = self.parse_toc(response)
        return self.TOC_NCX.format(
            (self.book_info["isbn"] if self.book_info["isbn"] else self.book_id),
            max_depth,
            self.book_title,
            ", ".join(aut.get("name", "") for aut in self.book_info.get("authors", [])),
            navmap
        )

    def create_epub(self):
        if APIVER == 1:
            tockey = "toc"
        elif APIVER == 2:
            tockey = "table_of_contents"
        open(os.path.join(self.BOOK_PATH, "mimetype"), "w").write("application/epub+zip")
        meta_info = os.path.join(self.BOOK_PATH, "META-INF")
        if os.path.isdir(meta_info):
            self.display.log("META-INF directory already exists: %s" % meta_info)

        else:
            os.makedirs(meta_info)

        open(os.path.join(meta_info, "container.xml"), "wb").write(
            self.CONTAINER_XML.encode("utf-8", "xmlcharrefreplace")
        )
        open(os.path.join(self.BOOK_PATH, "OEBPS", "content.opf"), "wb").write(
            self.create_content_opf().encode("utf-8", "xmlcharrefreplace")
        )
        open(os.path.join(self.BOOK_PATH, "OEBPS", "toc.ncx"), "wb").write(
            self.create_toc(self.book_info[tockey]).encode("utf-8", "xmlcharrefreplace")
        )

        zip_file = os.path.join(PATH, "Books", self.book_id)
        if os.path.isfile(zip_file + ".zip"):
            os.remove(zip_file + ".zip")

        shutil.make_archive(zip_file, 'zip', self.BOOK_PATH)
        os.rename(zip_file + ".zip", os.path.join(self.BOOK_PATH, self.book_id) + ".epub")


# MAIN
if __name__ == "__main__":
    arguments = argparse.ArgumentParser(prog="safaribooks.py",
                                        description="Download and generate an EPUB of your favorite books"
                                                    " from Safari Books Online.",
                                        add_help=False,
                                        allow_abbrev=False)

    login_arg_group = arguments.add_mutually_exclusive_group()
    login_arg_group.add_argument(
        "--cred", metavar="<EMAIL:PASS>", default=False,
        help="Credentials used to perform the auth login on Safari Books Online."
             " Es. ` --cred \"account_mail@mail.com:password01\" `."
    )
    login_arg_group.add_argument(
        "--login", action='store_true',
        help="Prompt for credentials used to perform the auth login on Safari Books Online."
    )

    arguments.add_argument(
        "--no-cookies", dest="no_cookies", action='store_true',
        help="Prevent your session data to be saved into `cookies.json` file."
    )
    arguments.add_argument(
        "--kindle", dest="kindle", action='store_true',
        help="Add some CSS rules that block overflow on `table` and `pre` elements."
             " Use this option if you're going to export the EPUB to E-Readers like Amazon Kindle."
    )
    arguments.add_argument(
        "--preserve-log", dest="log", action='store_true', help="Leave the `info_XXXXXXXXXXXXX.log`"
                                                                " file even if there isn't any error."
    )
    arguments.add_argument(
        "--api", metavar="<API>", default=2,
        help="Choose the API version for interacting with SafariBooks (default is 2)"
    )
    arguments.add_argument(
        "--delay", metavar="<DELAY>", default=0.3,
        help="Amount of time to wait between file requests. Setting to 0 runs as quickly as possible"
             " but increases load on the server (which isn't always kind)"
    )
    arguments.add_argument(
        "--theme", metavar="<THEME>", default='none',
        help="Choose styling theme to use for the ePub. Themes 'black', 'white', and 'sepia' use the"
             " respective styles from the SafariBooks website, while 'none' uses the native ebook style"
    )
    arguments.add_argument("--help", action="help", default=argparse.SUPPRESS, help='Show this help message.')
    arguments.add_argument(
        "bookid", metavar='<BOOK ID>',
        help="Book digits ID that you want to download. You can find it in the URL (X-es):"
             " `" + SAFARI_BASE_URL + "/library/view/book-name/XXXXXXXXXXXXX/`"
    )

    args_parsed = arguments.parse_args()
    if args_parsed.cred or args_parsed.login:
        user_email = ""
        pre_cred = ""

        if args_parsed.cred:
            pre_cred = args_parsed.cred

        else:
            user_email = input("Email: ")
            passwd = getpass.getpass("Password: ")
            pre_cred = user_email + ":" + passwd

        parsed_cred = SafariBooks.parse_cred(pre_cred)

        if not parsed_cred:
            arguments.error("invalid credential: %s" % (
                args_parsed.cred if args_parsed.cred else (user_email + ":*******")
            ))

        args_parsed.cred = parsed_cred

    else:
        if args_parsed.no_cookies:
            arguments.error("invalid option: `--no-cookies` is valid only if you use the `--cred` option")

    SafariBooks(args_parsed)
    # Hint: do you want to download more then one book once, initialized more than one instance of `SafariBooks`...
    sys.exit(0)
