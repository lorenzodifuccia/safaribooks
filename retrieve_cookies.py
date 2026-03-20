import json
import argparse
import sys

# See: https://github.com/lorenzodifuccia/safaribooks/issues/358

try:
    from safaribooks import COOKIES_FILE
except ImportError:
    COOKIES_FILE = "cookies.json"

BROWSER_JS = """
// Run this in your browser console on https://learning.oreilly.com:
JSON.stringify(document.cookie.split(';').reduce((o,c) => { let [k,v] = c.trim().split('='); o[k] = v; return o; }, {}))
""".strip()

def from_browser(browser_name):
    try:
        import browser_cookie3
    except ImportError:
        print("browser_cookie3 not found. Run with: uv run --with browser_cookie3 python retrieve_cookies.py -b <browser>")
        sys.exit(1)

    browsers = {
        "chrome": browser_cookie3.chrome,
        "firefox": browser_cookie3.firefox,
        "edge": browser_cookie3.edge,
        "chromium": browser_cookie3.chromium,
    }
    cj = browsers[browser_name](domain_name=".oreilly.com")
    return {c.name: c.value for c in cj}

def from_paste():
    print("Paste the JSON output from your browser console, then press Enter:")
    print(f"  (Run this in console on learning.oreilly.com: {BROWSER_JS})\n")
    raw = input("> ").strip()
    if raw.startswith('"') and raw.endswith('"'):
        raw = json.loads(raw)  # unwrap if double-encoded
    return json.loads(raw)

def main():
    parser = argparse.ArgumentParser(
        description="Extract O'Reilly cookies for safaribooks",
        epilog="Examples:\n"
               "  python retrieve_cookies.py --paste\n"
               "  uv run --with browser_cookie3 python retrieve_cookies.py -b chrome\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--browser", "-b", choices=["chrome", "firefox", "edge", "chromium"],
                        help="Extract cookies automatically from this browser")
    parser.add_argument("--paste", "-p", action="store_true",
                        help="Paste cookies JSON from browser console")
    args = parser.parse_args()

    if not args.browser and not args.paste:
        # Default to paste mode (no extra dependencies needed)
        args.paste = True

    if args.paste:
        cookies = from_paste()
    else:
        cookies = from_browser(args.browser)

    if not cookies:
        print("No cookies found. Make sure you're logged in at https://learning.oreilly.com")
        sys.exit(1)

    with open(COOKIES_FILE, "w") as f:
        json.dump(cookies, f, indent=2)
    print(f"Saved {len(cookies)} cookies to {COOKIES_FILE}")

if __name__ == "__main__":
    main()
