"""Phase 3: extractors (pure), classification matrix, and discovery behaviour."""
from __future__ import annotations
import json, pathlib, sys
import pytest

REPO = pathlib.Path(__file__).parents[2]
sys.path.insert(0, str(REPO / "backend"))
from app.discovery import classify, extractors            # noqa: E402
from app.worker.http_client import Budget, BudgetExhausted, GuardedClient  # noqa: E402


# ------------------------------------------------------------ extractors -----
@pytest.mark.parametrize("base,href,expected", [
    ("http://shop.test:3000/", "/login", "http://shop.test:3000/login"),
    ("http://shop.test:3000/", "/s?q=apple&b=2", "http://shop.test:3000/s?b&q"),
    ("http://shop.test:3000/a/b", "../c", "http://shop.test:3000/c"),
    ("http://shop.test:3000/", "javascript:alert(1)", None),
    ("http://shop.test:3000/", "mailto:x@y.z", None),
    ("http://shop.test:3000/", "//evil.example/x", "http://evil.example/x"),
])
def test_normalize_url_drops_values_and_rejects_non_http(base, href, expected):
    assert extractors.normalize_url(base, href) == expected


def test_query_values_are_never_retained():
    url = extractors.normalize_url("http://s.test:3000/", "/x?token=SECRET123&id=7")
    assert "SECRET123" not in url and "7" not in url
    assert extractors.query_parameter_names(url) == ["id", "token"]


@pytest.mark.parametrize("path,kind", [
    ("/rest/user/login", "login_form"), ("/#/register", "register"),
    ("/rest/user/logout", "logout"), ("/rest/user/reset-password", "password_reset"),
    ("/oauth/authorize", "oauth"), ("/api/Products", "none"),
])
def test_auth_entry_classification(path, kind):
    assert extractors.classify_auth_entry(path) == kind


@pytest.mark.parametrize("path,ctype,is_api,style", [
    ("/api/Users", None, True, "rest"),
    ("/rest/products/search", None, True, "rest"),
    ("/graphql", None, True, "graphql"),
    ("/login", "text/html", False, None),
    ("/x", "application/json", True, "rest"),
])
def test_api_detection(path, ctype, is_api, style):
    assert extractors.looks_like_api(path, ctype) == (is_api, style)


def test_form_parsing_identifies_login_and_csrf():
    html = """<form action="/rest/user/login" method="POST">
      <input name="email" type="email" required>
      <input name="password" type="password" required>
      <input name="_csrf" type="hidden"></form>"""
    forms = extractors.parse_html(html).forms
    assert len(forms) == 1
    f = forms[0]
    assert f.method == "POST" and f.action == "/rest/user/login"
    assert f.is_login_candidate and f.has_csrf_token_field
    assert any(x["is_password"] for x in f.fields)


def test_malformed_html_does_not_raise():
    p = extractors.parse_html("<form><input name=a <<>> </form><a href=")
    assert isinstance(p.forms, list)


# ---------------------------------------------------------- classification ----
def test_injection_candidate_is_marked_intrusive():
    cands = classify.candidates_for_endpoint(
        path="/rest/products/search", method="GET", is_api=True, api_style="rest",
        auth_entry_kind="none", parameter_names=("q",), has_login_form=False,
        has_password_field=False, has_file_input=False, missing_security_headers=())
    inj = [c for c in cands if c.concern == "injection"]
    assert inj and inj[0].requires_intrusive is True
    assert inj[0].suggested_profile_key == "zap-active-intrusive"


def test_login_surface_produces_no_bruteforce_candidate():
    cands = classify.candidates_for_endpoint(
        path="/rest/user/login", method="POST", is_api=True, api_style="rest",
        auth_entry_kind="login_form", parameter_names=(), has_login_form=True,
        has_password_field=True, has_file_input=False, missing_security_headers=())
    text = " ".join(c.concern + c.rationale for c in cands).lower()
    # The matrix must name the exclusion rather than stay silent about it: a
    # reader of the candidate list should see that guessing was ruled OUT by
    # project constraint, not simply omitted.
    assert "brute force are out of scope" in text
    assert "credential guessing" in text
    auth = [c for c in cands if c.concern == "authentication"]
    assert auth, "a login form must produce an authentication candidate"
    # Nothing on a login surface may propose sending credentials.
    assert all("guess" not in c.rationale.lower().replace("credential guessing and brute "
                                                         "force are out of scope", "")
               for c in cands)


def test_matrix_is_deterministic_and_versioned():
    args = dict(path="/api/Users", method="GET", is_api=True, api_style="rest",
                auth_entry_kind="none", parameter_names=(), has_login_form=False,
                has_password_field=False, has_file_input=False,
                missing_security_headers=("content-security-policy",))
    a = classify.candidates_for_endpoint(**args)
    b = classify.candidates_for_endpoint(**args)
    assert a == b, "classification must be deterministic"
    assert classify.MATRIX_VERSION


# ------------------------------------------------------- guarded client -------
def _client(**kw):
    budget = Budget(max_requests_per_second=100, max_total_requests=5, max_duration_seconds=60)
    return GuardedClient(pinned_ip="172.30.10.20", host="shop.brakes-vapt.test", port=3000,
                         scheme="http", budget=budget, **kw)


def test_out_of_scope_redirect_targets_are_rejected():
    c = _client(allowed_path_prefixes=("/",), excluded_path_prefixes=("/ftp",))
    try:
        assert c.target_in_scope("http://shop.brakes-vapt.test:3000/next") is True
        assert c.target_in_scope("http://evil.example/next") is False
        assert c.target_in_scope("http://shop.brakes-vapt.test:9999/next") is False
        assert c.target_in_scope("https://shop.brakes-vapt.test:3000/ftp/x") is False
        assert c.target_in_scope("ftp://shop.brakes-vapt.test:3000/x") is False
    finally:
        c.close()


def test_excluded_paths_are_never_requested():
    c = _client(allowed_path_prefixes=("/",), excluded_path_prefixes=("/ftp", "/rest/user/logout"))
    try:
        assert c.path_in_scope("/login") is True
        assert c.path_in_scope("/ftp") is False
        assert c.path_in_scope("/ftp/secret.md") is False
        assert c.path_in_scope("/rest/user/logout") is False
        # a request to an excluded path returns None without touching the network
        assert c.get("/ftp") is None
        assert c.budget.requests_made == 0
    finally:
        c.close()


def test_request_cap_is_enforced():
    budget = Budget(max_requests_per_second=100, max_total_requests=0, max_duration_seconds=60)
    c = GuardedClient(pinned_ip="172.30.10.20", host="shop.brakes-vapt.test", port=3000,
                      scheme="http", budget=budget)
    try:
        with pytest.raises(BudgetExhausted):
            c.get("/")
    finally:
        c.close()


def test_client_never_follows_redirects_or_trusts_proxy_env():
    c = _client()
    try:
        assert c._client.follow_redirects is False
        assert c._client.trust_env is False
        assert c._client.headers["Host"] == "shop.brakes-vapt.test"
        assert str(c._client.base_url).startswith("http://172.30.10.20:3000")
    finally:
        c.close()


# ------------------------------------------------------------- fixtures -------
def test_fixtures_are_hand_authored_not_recorded():
    folder = REPO / "backend" / "fixtures" / "mock-web-001"
    assert (folder / "README.md").exists()
    readme = (folder / "README.md").read_text()
    assert "not recorded from the live target" in readme
    docs = [json.loads(f.read_text()) for f in folder.glob("*.json")]
    assert docs and all({"path", "status", "headers", "body"} <= set(d) for d in docs)
