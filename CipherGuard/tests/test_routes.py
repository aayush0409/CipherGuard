"""Route and response tests for the CipherGuard application shell."""
import pytest
from cipherguard import create_app


@pytest.fixture()
def client():
    app = create_app({"TESTING": True})
    with app.test_client() as test_client:
        yield test_client


@pytest.mark.parametrize(("path", "heading"), [
    ("/", "Clarity for your"),
    ("/generate", "Generate"),
    ("/analyze", "Analyze"),
    ("/crack-time", "Crack-time"),
    ("/security", "Security, made"),
    ("/privacy", "Privacy is a"),
])
def test_pages_render_successfully(client, path, heading):
    response = client.get(path)
    assert response.status_code == 200
    assert heading.encode() in response.data
    assert b"CipherGuard" in response.data


def test_navigation_links_are_present(client):
    response = client.get("/")
    assert response.status_code == 200
    for path in (b"/generate", b"/analyze", b"/crack-time", b"/security", b"/privacy"):
        assert path in response.data


def test_analyzer_and_crack_time_tools_are_active(client):
    analyzer = client.get("/analyze")
    assert analyzer.status_code == 200
    assert b"LOCAL STRENGTH ANALYSIS" in analyzer.data
    assert b"analysis-password" in analyzer.data
    assert b"Not active yet" not in analyzer.data
    crack_time = client.get("/crack-time")
    assert crack_time.status_code == 200
    assert b"Not active yet" not in crack_time.data
    assert b"crack-time-password" in crack_time.data
    assert b"Rate-limited online" in crack_time.data
    assert b"Offline, fast hash" in crack_time.data
    generator = client.get("/generate")
    assert generator.status_code == 200
    assert b"Generate password" in generator.data


def test_privacy_page_describes_current_generator_scope(client):
    response = client.get("/privacy")
    assert response.status_code == 200
    assert b"Generation inputs are request-scoped" in response.data
    assert b"No database or credential storage" in response.data
    assert b"Browser-local password analysis and crack-time estimates" in response.data


def test_missing_route_returns_404(client):
    response = client.get("/this-route-does-not-exist")
    assert response.status_code == 404


def test_static_stylesheet_is_served(client):
    response = client.get("/static/css/tokens.css")
    assert response.status_code == 200
    assert b"#080D16" in response.data


def test_debug_mode_is_disabled_by_default():
    app = create_app()
    assert app.debug is False


def test_generator_post_returns_password_without_persisting_it(client):
    response = client.post("/generate", data={
        "length": "24", "uppercase": "on", "lowercase": "on",
        "numbers": "on", "symbols": "on",
    })
    assert response.status_code == 200
    assert b"NEW PASSWORD" in response.data
    assert b"No database or credential storage" not in response.data


def test_generator_rejects_out_of_range_length(client):
    response = client.post("/generate", data={"length": "500", "lowercase": "on"})
    assert response.status_code == 200
    assert b"between 8 and 128" in response.data


def test_generator_rejects_empty_character_selection(client):
    response = client.post("/generate", data={"length": "20"})
    assert response.status_code == 200
    assert b"Select at least one character type" in response.data


def test_generator_static_assets_use_project_root(client):
    response = client.get("/static/css/app.css")
    assert response.status_code == 200


def test_generated_password_response_is_not_cacheable(client):
    response = client.post("/generate", data={"length": "20", "lowercase": "on"})
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store, max-age=0"
    assert response.headers["Pragma"] == "no-cache"
    assert response.headers["Referrer-Policy"] == "no-referrer"


def test_generated_password_is_masked_and_has_reveal_and_copy_controls(client):
    response = client.post("/generate", data={"length": "20", "lowercase": "on"})
    assert response.status_code == 200
    assert b'data-revealed="false"' in response.data
    assert b'aria-label="Reveal password"' in response.data
    assert b'aria-pressed="false"' in response.data
    assert b">Reveal</button>" in response.data
    assert b'data-copy-target="generated-password"' in response.data
    assert b"data-password=" in response.data


def test_generator_javascript_copies_actual_value_and_reports_copy_failures(client):
    response = client.get("/static/js/app.js")
    assert response.status_code == 200
    assert b'target.dataset.password ?? target.textContent' in response.data
    assert b'await navigator.clipboard.writeText(value)' in response.data
    assert b'Could not copy automatically.' in response.data
    assert b'Copied to clipboard.' in response.data


def test_generator_form_exposes_optional_exclusion_field(client):
    response = client.get("/generate")
    assert response.status_code == 200
    assert b'name="exclusion_terms"' in response.data
    assert b"OPTIONAL" in response.data
    assert b"punctuation/separators" in response.data
    assert b'name="inclusion_terms"' in response.data
    assert b"Required characters or terms to include" in response.data


def test_generator_post_applies_exclusion_terms(client):
    response = client.post("/generate", data={
        "length": "32", "uppercase": "on", "lowercase": "on",
        "numbers": "on", "symbols": "on", "exclusion_terms": "AayushPrasadUniqueTerm",
    })
    assert response.status_code == 200
    assert b'value="AayushPrasadUniqueTerm"' in response.data  # preserved for the current workflow
    assert b"Could not find a password" not in response.data
    assert response.headers["Cache-Control"] == "no-store, max-age=0"


def test_invalid_exclusion_term_is_escaped_and_preserved_in_response(client):
    secret_term = "PrivateUniqueTerm9981"
    response = client.post("/generate", data={
        "length": "32", "uppercase": "on", "lowercase": "on",
        "numbers": "on", "symbols": "on", "exclusion_terms": "x\n" + secret_term,
    })
    assert response.status_code == 200
    assert b"at least two" in response.data
    assert secret_term.encode() in response.data
    assert response.headers["Cache-Control"] == "no-store, max-age=0"


def test_empty_exclusions_generate_normally(client):
    response = client.post("/generate", data={
        "length": "24", "uppercase": "on", "lowercase": "on",
        "numbers": "on", "symbols": "on", "exclusion_terms": "\n  ",
    })
    assert response.status_code == 200
    assert b"NEW PASSWORD" in response.data
    assert b"Could not find a password" not in response.data


def test_both_constraint_fields_persist_after_success_and_error(client):
    success = client.post("/generate", data={
        "length": "32", "uppercase": "on", "lowercase": "on", "numbers": "on", "symbols": "on",
        "exclusion_terms": "Aayush, delhi", "inclusion_terms": "CG, @, 7",
    })
    assert success.status_code == 200
    assert b'value="Aayush, delhi"' in success.data
    assert b'value="CG, @, 7"' in success.data
    assert success.headers["Cache-Control"] == "no-store, max-age=0"

    failure = client.post("/generate", data={
        "length": "8", "uppercase": "on", "lowercase": "on", "numbers": "on", "symbols": "on",
        "exclusion_terms": "Keep Me", "inclusion_terms": "ThisTermIsTooLong",
    })
    assert failure.status_code == 200
    assert b'value="Keep Me"' in failure.data
    assert b'value="ThisTermIsTooLong"' in failure.data
    assert failure.headers["Cache-Control"] == "no-store, max-age=0"


def test_constraint_values_are_html_escaped(client):
    response = client.post("/generate", data={
        "length": "8", "lowercase": "on", "exclusion_terms": '<img src=x onerror="alert(1)">',
        "inclusion_terms": "abc",
    })
    assert response.status_code == 200
    assert b"<img src=x" not in response.data
    assert b"&lt;img" in response.data


def test_inclusion_outside_selected_categories_shows_error_and_preserves_inputs(client):
    response = client.post("/generate", data={
        "length": "20", "lowercase": "on", "inclusion_terms": "A", "exclusion_terms": "Keep This",
    })
    assert b"outside the enabled character types" in response.data
    assert b'value="A"' in response.data
    assert b'value="Keep This"' in response.data


def test_analyzer_page_does_not_submit_password_or_load_external_scripts(client):
    response = client.get("/analyze")
    assert response.status_code == 200
    assert b'method="post"' not in response.data.lower()
    assert b'localStorage' not in response.data
    assert b'sessionStorage' not in response.data
    assert b'<script src="http' not in response.data.lower()
    assert b'id="analysis-password"' in response.data
    js = client.get("/static/js/app.js")
    assert js.status_code == 200
    assert b"analyzer-form" in js.data
    assert b"fetch(" not in js.data


def test_crack_time_page_does_not_submit_password_or_load_external_scripts(client):
    response = client.get("/crack-time")
    assert response.status_code == 200
    assert b'method="post"' not in response.data.lower()
    assert b'id="crack-time-password"' in response.data
    assert b'id="crack-time-clear"' in response.data
    assert b'aria-live="polite"' in response.data
    assert b'<script src="http' not in response.data.lower()
    assert b'localStorage' not in response.data
    assert b'sessionStorage' not in response.data
    js = client.get("/static/js/app.js")
    assert js.status_code == 200
    assert b"crack-time-form" in js.data
    assert b"fetch(" not in js.data
    assert b"XMLHttpRequest" not in js.data
    assert b"const orderedScenarios = [...scenarios].sort((a, b) => b.rate - a.rate)" in js.data
    assert b"orderedScenarios.forEach((scenario) =>" in js.data
    html_names = [b"Offline, fast hash", b"Offline, slow password hash", b"Permissive online", b"Rate-limited online"]
    positions = [response.data.index(name) for name in html_names]
    assert positions == sorted(positions)
    assert all(response.data.count(name) >= 1 for name in html_names)


APPLICATION_PAGES = ("/", "/generate", "/analyze", "/crack-time", "/security", "/privacy")


def test_shared_creator_footer_appears_on_every_application_page(client):
    for path in APPLICATION_PAGES:
        response = client.get(path)
        assert response.status_code == 200
        assert b'aria-label="Creator and social links"' in response.data
        assert b"Crafted with" in response.data
        assert b"by Aayush" in response.data
        assert b"Find a bug or want to contact me?" in response.data
        assert b'aria-label="Contact and social profiles"' in response.data


def test_footer_email_links_use_the_supplied_recipient(client):
    response = client.get("/")
    assert response.status_code == 200
    assert response.data.count(b'href="mailto:aayush0409@gmail.com"') == 2
    assert b'aria-label="Email Aayush"' in response.data
    assert b'title="Email"' in response.data


def test_footer_social_links_have_exact_urls_safe_targets_and_accessible_names(client):
    response = client.get("/")
    assert response.status_code == 200
    html = response.data.decode("utf-8")
    links = {
        "https://github.com/aayush0409": ("Aayush on GitHub", "GitHub"),
        "https://www.linkedin.com/in/aayush-prasad-70a87726a/": ("Aayush on LinkedIn", "LinkedIn"),
        "https://www.instagram.com/laazy.potatoo/": ("Aayush on Instagram", "Instagram"),
    }
    for url, (accessible_name, tooltip) in links.items():
        assert f'href="{url}" target="_blank" rel="noopener noreferrer"' in html
        assert f'aria-label="{accessible_name}"' in html
        assert f'title="{tooltip}"' in html
    assert html.count('class="footer-social-link"') == 4
    assert "<svg" in html
    assert 'src="https://' not in html


def test_dashboard_describes_working_tools_without_development_badges(client):
    response = client.get("/")
    assert response.status_code == 200
    html = response.data.decode("utf-8").lower()
    for stale_label in ("in development", "coming soon", "not active yet", "planned for a later phase"):
        assert stale_label not in html
    expected_descriptions = (
        "optional personal-information exclusions",
        "character variety, recognizable patterns, repetition",
        "hypothetical online and offline attack speeds",
        "password managers, mfa, passkeys",
    )
    for description in expected_descriptions:
        assert description in html
    for path in ("/generate", "/analyze", "/crack-time", "/security"):
        assert f'href="{path}"' in html


def test_crack_time_scenario_order_and_existing_local_privacy_checks_remain(client):
    response = client.get("/crack-time")
    assert response.status_code == 200
    html = response.data
    labels = [b"Offline, fast hash", b"Offline, slow password hash", b"Permissive online", b"Rate-limited online"]
    positions = [html.index(label) for label in labels]
    assert positions == sorted(positions)
    assert all(html.count(label) == 1 for label in labels)
    assert b'id="crack-time-clear"' in html
    assert b'id="crack-time-visibility"' in html
    assert b'method="post"' not in html.lower()
    assert b"localStorage" not in html
    assert b"sessionStorage" not in html
