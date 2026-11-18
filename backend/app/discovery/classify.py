"""Deterministic surface -> candidate-test matrix (L2 authority).

The agent may rank and explain these; it does not produce them. Selection is
reproducible without any LLM, which is the whole point (MVP_SCOPE.md §5).
"""
from __future__ import annotations
import dataclasses as dc

MATRIX_VERSION = "1.0.0"


@dc.dataclass(frozen=True, slots=True)
class Candidate:
    surface_kind: str
    concern: str
    suggested_profile_key: str | None
    requires_intrusive: bool
    rationale: str


def candidates_for_endpoint(*, path: str, method: str, is_api: bool, api_style: str | None,
                            auth_entry_kind: str, parameter_names: tuple[str, ...],
                            has_login_form: bool, has_password_field: bool,
                            has_file_input: bool, missing_security_headers: tuple[str, ...]
                            ) -> list[Candidate]:
    out: list[Candidate] = []

    if auth_entry_kind in ("login_form", "token_endpoint", "oauth") or has_password_field:
        kind = {"register": "registration_form", "token_endpoint": "token_endpoint",
                "oauth": "oauth_endpoint"}.get(auth_entry_kind, "login_form")
        out.append(Candidate(kind, "authentication_weaknesses", "zap-passive", False,
                             f"{path} is an authentication entry point ({auth_entry_kind}); "
                             "session handling, transport and credential exposure are assessable "
                             "passively. Credential guessing is NOT proposed."))
    if auth_entry_kind == "register":
        out.append(Candidate("registration_form", "input_validation", "zap-passive", False,
                             f"{path} accepts user-controlled registration input; validation and "
                             "error handling are assessable."))
    if parameter_names:
        out.append(Candidate("query_parameter", "injection", "zap-active-intrusive", True,
                             f"{path} accepts user-controlled parameters "
                             f"{list(parameter_names)}; injection testing is relevant but is "
                             "INTRUSIVE and requires an approved profile and genuine dual control."))
    if is_api and api_style == "rest" and "/users" in path.lower():
        out.append(Candidate("user_api", "broken_access_control", "zap-passive", False,
                             f"{path} is a user-scoped API; authorisation behaviour and data "
                             "exposure are assessable from responses."))
    elif is_api:
        out.append(Candidate("api_endpoint", "data_exposure", "zap-passive", False,
                             f"{path} is an API endpoint ({api_style}); response content and "
                             "headers are assessable passively."))
    if has_file_input:
        out.append(Candidate("file_upload", "file_handling", None, True,
                             f"{path} exposes a file input; file-handling tests are intrusive and "
                             "are not enabled in this MVP."))
    if missing_security_headers:
        out.append(Candidate("response_headers", "security_misconfiguration", "zap-passive", False,
                             f"{path} responded without {list(missing_security_headers)}; "
                             "passive header assessment applies."))
    return out
