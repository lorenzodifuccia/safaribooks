import json
import safaribooks


def parse_cookies_file(file_path):
    with open(file_path) as f:
        data = json.load(f)
        convert_cookies(data)


def convert_cookies(cookies):
    converted_cookies = {}
    for c in cookies:
        name = c.get('name')
        value = c.get('value')
        converted_cookies[name] = value
    json.dump(converted_cookies, open(safaribooks.COOKIES_FILE, 'w'))


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print(f'Usage: {sys.argv[0]} <cookies_file.json>')
    parse_cookies_file(sys.argv[1])
