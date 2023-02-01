import re
import requests
import safaribooks

REGISTER_URL = safaribooks.SAFARI_BASE_URL + "/register/"
CHECK_EMAIL = safaribooks.SAFARI_BASE_URL + "/check-email-availability/"
CHECK_PWD = safaribooks.SAFARI_BASE_URL + "/check-password/"

# DEBUG
USE_PROXY = False
PROXIES = {"https": "https://127.0.0.1:8080"}

CSRF_TOKEN_RE = re.compile(r"(?<=name='csrfmiddlewaretoken' value=')([^']+)")


class Register:
    def __init__(self, email, password, first_name, second_name, country="US", referrer="podcast"):
        self.email = email
        self.password = password
        self.first_name = first_name
        self.second_name = second_name
        self.country = country
        self.referrer = referrer

        self.csrf = None

        self.session = requests.Session()
        if USE_PROXY:  # DEBUG
            self.session.proxies = PROXIES
            self.session.verify = False

        self.session.headers.update(safaribooks.SafariBooks.HEADERS)
        self.session.headers.update({
            "X-Requested-With": "XMLHttpRequest",
            "Referer": REGISTER_URL
        })

        self.register()

    def handle_cookie_update(self, set_cookie_headers):
        for morsel in set_cookie_headers:
            # Handle Float 'max-age' Cookie
            if safaribooks.SafariBooks.COOKIE_FLOAT_MAX_AGE_PATTERN.search(morsel):
                cookie_key, cookie_value = morsel.split(";")[0].split("=")
                self.session.cookies.set(cookie_key, cookie_value)

    def requests_provider(self, url, is_post=False, data=None, perform_redirect=True, check_200=True, **kwargs):
        try:
            response = getattr(self.session, "post" if is_post else "get")(
                url,
                data=data,
                allow_redirects=False,
                **kwargs
            )

            self.handle_cookie_update(response.raw.headers.getlist("Set-Cookie"))

        except (requests.ConnectionError, requests.ConnectTimeout, requests.RequestException) as request_exception:
            print("Error: ", str(request_exception))
            return 0

        if response.is_redirect and perform_redirect:
            return self.requests_provider(response.next.url, is_post, None, perform_redirect, check_200, **kwargs)

        if check_200 and response.status_code != 200:
            print("Invalid response code:\n", response.text)
            return 0

        return response

    def register(self):
        # Take first cookie + csrf
        response = self.requests_provider(REGISTER_URL)
        if response == 0:
            print("Error 0x1: unable to reach registration page!")
            exit(1)

        if "csrfmiddlewaretoken' value='" not in response.text:
            print("Error 0x2: CSRF token not present")
            exit(1)

        csrf_search = CSRF_TOKEN_RE.findall(response.text)
        if not len(csrf_search):
            print("Error 0x3: CSRF token RE error")
            exit(1)

        self.csrf = csrf_search[0]

        # Check user validity
        response = self.requests_provider(CHECK_EMAIL, params={"email": self.email})
        if response == 0:
            print("Error 0x4: unable to check email!")
            exit(1)

        response_dict = response.json()
        if not response_dict["success"]:
            print("Error 0x5:", response_dict["message"])
            exit(1)

        # Check password validity
        response = self.requests_provider(CHECK_PWD, is_post=True, data={
            "csrfmiddlewaretoken": self.csrf,
            "password1": self.password,
            "field_name": "password1"
        })
        if response == 0:
            print("Error 0x6: unable to check password!")
            exit(1)

        response_dict = response.json()
        if not response_dict["valid"]:
            print("Error 0x7:", response_dict["msg"])
            exit(1)

        # Register
        response = self.requests_provider(REGISTER_URL, is_post=True, data={
            "next": "",
            "trial_length": 10,
            "csrfmiddlewaretoken": self.csrf,
            "first_name": self.first_name,
            "last_name": self.second_name,
            "email": self.email,
            "password1": self.password,
            "country": self.country,
            "referrer": "podcast",
            "recently_viewed_bits": "[]"
        }, check_200=False)
        if response == 0:
            print("Error 0x8: unable to register!")
            exit(1)

        elif response.status_code != 201:
            print("Error: 0x9: invalid status code while registering!")
            exit(1)

        print("[*] Account registered: \nEMAIL: %s\nPASSWORD: %s" % (self.email, self.password))
        return


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("[!] Error: too few arguments.\nRun `register_user.py EMAIL PASSWORD`.")
        exit(1)

    elif len(sys.argv) > 3:
        print("[!] Error: too much arguments, try to enclose the string with quote '\"'.")
        exit(1)

    FIRST_NAME = "Safari"
    SECOND_NAME = "Download"

    Register(sys.argv[1], sys.argv[2], FIRST_NAME, SECOND_NAME)
