"""
Script for SSO support, saves and converts the cookie string retrieved by the browser.
Please follow:
- https://github.com/lorenzodifuccia/safaribooks/issues/26
- https://github.com/lorenzodifuccia/safaribooks/issues/150#issuecomment-555423085
- https://github.com/lorenzodifuccia/safaribooks/issues/2#issuecomment-367726544


Thanks: @elrob, @noxymon
"""

import json
import safaribooks


def transform(cookies_string):
    cookies = {}
    for cookie in cookies_string.split(";"):
        cookie = cookie.strip()
        key, value = cookie.split("=", 1)
        cookies[key] = value

    print(cookies)
    json.dump(cookies, open(safaribooks.COOKIES_FILE, 'w'))
    print("\n\nDone! Cookie Jar saved into `cookies.json`. "
          "Now you can run `safaribooks.py` without the `--cred` argument...")


USAGE = "\n\n[*] Please use this command putting as argument the cookies retrieved by your browser.\n" + \
        "[+] In order to do so, please follow these steps: \n" + \
        "https://github.com/lorenzodifuccia/safaribooks/issues/150#issuecomment-555423085\n"

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("[!] Error: too few arguments." + USAGE)
        exit(1)

    elif len(sys.argv) > 2:
        print("[!] Error: too much arguments, try to enclose the string with quote '\"'." + USAGE)
        exit(1)

    transform(sys.argv[1])
