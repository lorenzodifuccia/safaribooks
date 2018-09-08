#!/usr/bin/env python3
# coding: utf-8
import sys
import json
from safaribooks import COOKIES_FILE


def die(message):
    print(message, file=sys.stderr)
    sys.exit(1)


def import_cookie(jar, header):
    header = header.strip()
    if len(header) == 0:
        return jar
    fields = header.split('=')
    if len(fields) != 2:
        die("Error importing: '{0}'. Expected 1 equal sign but found {1}."
            .format(header, len(fields) - 1))
        sys.exit(1)
    name = fields[0].strip()
    value = fields[1].strip()
    if value.endswith(';'):
        value = value[0:len(value)-1]
    jar[name] = value
    return jar


def import_cookies(jar, header):
    print("Importing values from '{0}'".format(header))
    values = header.split(' ')
    for value in values:
        import_cookie(jar, value)
    return jar


def save_cookies(jar):
    file = open(COOKIES_FILE, mode='w')
    file.write(json.dumps(jar))
    file.write("\n")
    file.close()
    print("Saved {0} cookies to {1}".format(len(jar), COOKIES_FILE))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        die("Please pass a cookie header")
    jar = {}
    for arg in sys.argv[1:]:
        import_cookies(jar, arg)
    save_cookies(jar)
