"""Pure HTML/response extractors.

No I/O, no database, no network — these take bytes and headers and return
structures. That makes the attack-surface inventory testable against fixtures
and identical whether the response came from a live crawl or a recorded one.
"""
from __future__ import annotations
import dataclasses as dc
import re
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

SECRETISH = re.compile(r"(token|secret|passwd|password|apikey|api_key|auth|session|jwt|csrf"
                       r"|signature|private)", re.I)
AUTH_HINTS = {
    "login": "login_form", "signin": "login_form", "sign-in": "login_form",
    "logout": "logout", "signout": "logout",
    "register": "register", "signup": "register",
    "reset-password": "password_reset", "forgot": "password_reset",
    "token": "token_endpoint", "oauth": "oauth", "authorize": "oauth",
}


def normalize_url(base: str, href: str) -> str | None:
    """Absolute URL with sorted query KEYS and no query VALUES.

    Values are dropped deliberately: the inventory is about surface identity,
    and keeping values would both leak data and explode the row count.
    """
    try:
        absolute = urljoin(base, href.strip())
    except ValueError:
        return None
    parts = urlsplit(absolute)
    if parts.scheme not in ("http", "https"):
        return None
    keys = sorted({k for k, _ in parse_qsl(parts.query, keep_blank_values=True)})
    query = "&".join(keys)
    path = parts.path or "/"
    return urlunsplit((parts.scheme, parts.netloc, path, query, ""))


def query_parameter_names(url: str) -> list[str]:
    return sorted({k for k, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)})


def classify_auth_entry(path: str) -> str:
    low = path.lower()
    for needle, kind in AUTH_HINTS.items():
        if needle in low:
            return kind
    return "none"


def looks_like_api(path: str, content_type: str | None) -> tuple[bool, str | None]:
    low = path.lower()
    if low.startswith("/graphql") or low.endswith("/graphql"):
        return True, "graphql"
    if low.startswith(("/api/", "/rest/", "/v1/", "/v2/")) or "/api/" in low or "/rest/" in low:
        return True, "rest"
    if content_type and "json" in content_type.lower():
        return True, "rest"
    return False, None


@dc.dataclass(slots=True)
class ParsedForm:
    action: str
    method: str
    enctype: str | None
    fields: list[dict[str, object]]

    @property
    def has_csrf_token_field(self) -> bool:
        return any(SECRETISH.search(str(f.get("name") or "")) and
                   str(f.get("input_type") or "").lower() == "hidden" for f in self.fields)

    @property
    def is_login_candidate(self) -> bool:
        has_pw = any(f.get("is_password") for f in self.fields)
        names = " ".join(str(f.get("name") or "") for f in self.fields).lower()
        return bool(has_pw and ("user" in names or "email" in names or "name" in names))


class _Parser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.forms: list[ParsedForm] = []
        self._current: ParsedForm | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag in ("script", "img", "link") and (a.get("src") or a.get("href")):
            self.scripts.append(a.get("src") or a.get("href", ""))
        elif tag == "form":
            self._current = ParsedForm(action=a.get("action", ""),
                                       method=(a.get("method") or "GET").upper(),
                                       enctype=a.get("enctype"), fields=[])
            self.forms.append(self._current)
        elif tag in ("input", "select", "textarea") and self._current is not None:
            itype = (a.get("type") or ("select" if tag == "select" else "text")).lower()
            self._current.fields.append({
                "name": a.get("name") or a.get("id") or "", "input_type": itype,
                "is_password": itype == "password", "required": "required" in a,
                "autocomplete": a.get("autocomplete")})

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._current = None


def parse_html(body: str) -> _Parser:
    p = _Parser()
    try:
        p.feed(body)
    except Exception:                                  # noqa: BLE001 - hostile input
        pass
    return p


# Headers whose ABSENCE is a security observation. Presence/absence is recorded;
# whether that constitutes a finding is decided later by the validation engine.
SECURITY_HEADERS = (
    "content-security-policy", "strict-transport-security", "x-content-type-options",
    "x-frame-options", "referrer-policy", "permissions-policy",
)

# Cookie attributes carry session-management meaning and are fully observable in
# a response that has already been collected, so they need no extra request.
COOKIE_ATTRIBUTES = ("HttpOnly", "Secure", "SameSite")


def cookie_attributes(set_cookie: str | None) -> tuple[str, ...]:
    """Attribute names PRESENT on a Set-Cookie header, in canonical spelling.

    The first `;`-separated segment is the cookie's NAME=VALUE and is discarded
    without being read: a cookie whose value happens to contain the text
    "HttpOnly" must not be reported as carrying the attribute.
    """
    if not set_cookie:
        return ()
    segments = [seg.strip() for seg in set_cookie.split(";")[1:]]
    names = {seg.split("=", 1)[0].strip().lower() for seg in segments if seg}
    return tuple(a for a in COOKIE_ATTRIBUTES if a.lower() in names)
