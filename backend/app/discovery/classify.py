"""Deterministic surface -> candidate-test matrix (L2 authority).

The agent may rank and explain these; it does not produce them. Selection is
reproducible without any LLM, which is the whole point (MVP_SCOPE.md §5).

Every concern is a TAXONOMY KEY (app/taxonomy.py), so discovery and findings
speak one vocabulary and coverage can be counted across both. A candidate is a
statement about SURFACE ("this endpoint takes a parameter that looks like a
URL"), never about a vulnerability. Confirmation is the validation engine's
job, and for `active` and `manual` categories it is a human's.
"""
from __future__ import annotations
import dataclasses as dc
import re

from .. import taxonomy as tax

MATRIX_VERSION = "2.0.0"

PASSIVE_PROFILE = "zap-passive"
ACTIVE_PROFILE = "zap-active-intrusive"

# Parameter-name heuristics. Deliberately conservative and NAME-based only:
# values are never inspected here, and a match is a reason to look, not a
# finding. Names are tokenised first (camelCase, snake_case, kebab-case and
# dotted paths all split the same way) so `imageUrl`, `image_url` and
# `image.url` are treated identically.
def tokens(name: str) -> set[str]:
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", name)
    return {t for t in re.split(r"[^A-Za-z0-9]+", spaced.lower()) if t}


URLISH = {"url", "uri", "link", "src", "source", "target", "dest", "destination",
          "redirect", "redir", "next", "return", "returnto", "callback", "cb",
          "webhook", "feed", "proxy", "fetch", "continue", "domain", "host", "site"}
IDISH = {"id", "uid", "userid", "user", "account", "customer", "order", "invoice",
         "doc", "ref", "pid", "sid", "guid", "uuid"}
VALUEISH = {"price", "amount", "total", "cost", "qty", "quantity", "count", "discount",
            "coupon", "voucher", "credit", "balance", "points", "rating", "stars",
            "fee", "shipping", "tax", "currency"}
ROLEISH = {"role", "roles", "admin", "isadmin", "privilege", "privileges", "perm",
           "perms", "permissions", "scope", "scopes", "group", "level", "verified",
           "enabled", "active", "deluxe", "premium"}
ADMINPATH = re.compile(r"/(admin|administrator|manage|management|internal|console|"
                       r"backoffice|ops|debug|actuator|metrics)(/|$)", re.I)


def _matches(name: str, vocabulary: set[str]) -> bool:
    return bool(tokens(name) & vocabulary)


@dc.dataclass(frozen=True, slots=True)
class Candidate:
    surface_kind: str
    concern: str                      # a taxonomy key
    suggested_profile_key: str | None
    requires_intrusive: bool
    rationale: str

    @property
    def category(self) -> tax.Category:
        return tax.BY_KEY[self.concern]


def _profile_for(concern: str) -> tuple[str | None, bool]:
    """Profile and intrusiveness follow the category's assertability, not the
    caller's preference: an `active` category can never be proposed passively."""
    cat = tax.BY_KEY[concern]
    if cat.assertability == tax.PASSIVE:
        return PASSIVE_PROFILE, False
    if cat.assertability == tax.ACTIVE:
        return ACTIVE_PROFILE, True
    return None, False                # manual: no profile confirms it


def _cand(concern: str, surface_kind: str, rationale: str) -> Candidate:
    profile, intrusive = _profile_for(concern)
    return Candidate(surface_kind, concern, profile, intrusive, rationale)


def candidates_for_endpoint(*, path: str, method: str, is_api: bool, api_style: str | None,
                            auth_entry_kind: str, parameter_names: tuple[str, ...],
                            has_login_form: bool, has_password_field: bool,
                            has_file_input: bool, missing_security_headers: tuple[str, ...],
                            set_cookie_attributes: tuple[str, ...] = (),
                            is_cleartext_transport: bool = False,
                            requires_auth_guess: bool = False,
                            ) -> list[Candidate]:
    """Total over the Tier-1 taxonomy: every emitted concern is a Tier-1 key, and
    a surface that warrants none of them emits nothing at all."""
    out: list[Candidate] = []
    params = tuple(parameter_names)

    # --- authentication -----------------------------------------------------
    if auth_entry_kind in ("login_form", "token_endpoint", "oauth", "register") or has_password_field:
        kind = {"register": "registration_form", "token_endpoint": "token_endpoint",
                "oauth": "oauth_endpoint"}.get(auth_entry_kind, "login_form")
        out.append(_cand("authentication", kind,
                         f"{path} is an authentication entry point ({auth_entry_kind}). "
                         "Credential handling, response differences between known and unknown "
                         "accounts, and recovery flows are assessable. Credential guessing and "
                         "brute force are OUT OF SCOPE by project constraint."))

    # --- session management -------------------------------------------------
    if set_cookie_attributes:
        missing = [a for a in ("HttpOnly", "Secure", "SameSite") if a not in set_cookie_attributes]
        if missing:
            out.append(_cand("session_management", "set_cookie",
                             f"{path} issues a cookie without {missing}. Cookie attributes are "
                             "observable in the stored response, so this is confirmable without "
                             "sending anything."))
    elif has_password_field or auth_entry_kind != "none":
        out.append(_cand("session_management", "auth_entry_point",
                         f"{path} participates in authentication, so session issuance, lifetime "
                         "and invalidation on logout are in scope. Logout itself is EXCLUDED "
                         "from automated testing (it destroys the session under test)."))

    # --- cryptographic failures ---------------------------------------------
    if is_cleartext_transport and (has_password_field or auth_entry_kind != "none"):
        out.append(_cand("cryptographic_failures", "cleartext_credentials",
                         f"{path} carries credentials over cleartext HTTP. Observable directly "
                         "from the request scheme."))
    elif is_cleartext_transport:
        out.append(_cand("cryptographic_failures", "cleartext_transport",
                         f"{path} is served over cleartext HTTP, so transport security and HSTS "
                         "enforcement are assessable."))

    # --- injection ----------------------------------------------------------
    if params:
        out.append(_cand("injection", "query_parameter",
                         f"{path} accepts user-controlled parameters {list(params)}. Reflection "
                         "is observable passively; confirming an interpreter reached it requires "
                         "crafted payloads, which are INTRUSIVE and need an approved profile and "
                         "genuine dual control."))

    # --- broken access control ----------------------------------------------
    id_params = sorted(p for p in params if _matches(p, IDISH))
    if id_params:
        out.append(_cand("broken_access_control", "object_reference",
                         f"{path} takes object references {id_params}. Whether another user's "
                         "object can be read or written is only answerable by requesting one, "
                         "which requires two accounts and an approved intrusive profile."))
    elif ADMINPATH.search(path):
        out.append(_cand("broken_access_control", "privileged_path",
                         f"{path} looks administrative. Whether it enforces the role it implies "
                         "is only answerable by requesting it without that role."))
    elif is_api and "/users" in path.lower():
        out.append(_cand("broken_access_control", "user_api",
                         f"{path} is a user-scoped API; authorisation behaviour and cross-user "
                         "data access are in scope."))

    # --- api security --------------------------------------------------------
    if is_api:
        role_params = sorted(p for p in params if _matches(p, ROLEISH))
        detail = (f" Parameters {role_params} look privilege-bearing, so mass assignment applies."
                  if role_params else "")
        out.append(_cand("api_security", "api_endpoint",
                         f"{path} is an API endpoint ({api_style or 'unknown style'}). Method "
                         f"handling, object-level authorisation and response verbosity are in "
                         f"scope.{detail}"))
        out.append(_cand("information_disclosure", "api_response",
                         f"{path} returns structured data; response content and headers are "
                         "assessable passively for fields the caller should not receive."))

    # --- ssrf ----------------------------------------------------------------
    url_params = sorted(p for p in params if _matches(p, URLISH))
    if url_params:
        out.append(_cand("ssrf", "url_parameter",
                         f"{path} accepts {url_params}, whose names suggest the server may fetch "
                         "a caller-controlled URL. Confirmation requires pointing it at a "
                         "controlled destination — INTRUSIVE, and inside the lab only."))

    # --- business logic -------------------------------------------------------
    value_params = sorted(p for p in params if _matches(p, VALUEISH))
    if value_params:
        out.append(_cand("business_logic", "value_parameter",
                         f"{path} accepts {value_params}, which carry commercial meaning. No "
                         "scanner confirms a logic flaw: this is flagged for MANUAL review, with "
                         "the surface named so a human knows where to look."))

    # --- file upload ----------------------------------------------------------
    if has_file_input:
        out.append(_cand("file_upload", "file_upload",
                         f"{path} exposes a file input. Type, size and storage enforcement, and "
                         "what happens when the file is served back, require uploading a file — "
                         "INTRUSIVE, and not enabled in this MVP."))

    # --- security misconfiguration / client-side ------------------------------
    if missing_security_headers:
        out.append(_cand("security_misconfiguration", "response_headers",
                         f"{path} responded without {list(missing_security_headers)}; passive "
                         "header assessment applies."))
        client_side_headers = [h for h in missing_security_headers
                               if h.lower() in ("content-security-policy", "x-frame-options",
                                                "permissions-policy")]
        if client_side_headers:
            out.append(_cand("client_side", "browser_policy",
                             f"{path} ships no {client_side_headers}, so nothing constrains what "
                             "executes or embeds in the browser. Observable in the response."))
    return out


def coverage_of(candidates: list[Candidate]) -> dict[str, int]:
    """Tier-1 key -> candidate count, including the zeroes."""
    counts = {k: 0 for k in tax.TIER1_KEYS}
    for c in candidates:
        counts[c.concern] = counts.get(c.concern, 0) + 1
    return counts
