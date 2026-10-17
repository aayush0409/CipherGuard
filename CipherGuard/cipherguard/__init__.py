"""Application factory for CipherGuard."""
from pathlib import Path

from flask import Flask, render_template, request

from .generator import PasswordGenerationError, generate_password


def create_app(test_config=None):
    project_root = Path(__file__).resolve().parent.parent
    app = Flask(
        __name__,
        template_folder=str(project_root / "templates"),
        static_folder=str(project_root / "static"),
        static_url_path="/static",
    )
    app.config.from_mapping(
        SECRET_KEY=None,
        TESTING=False,
    )
    if test_config:
        app.config.update(test_config)

    @app.get("/")
    def dashboard():
        return render_template("index.html", page_title="Dashboard", active_page="dashboard")

    @app.route("/generate", methods=["GET", "POST"])
    def generate():
        generated_password = None
        error_message = None
        settings = {"length": 20, "uppercase": True, "lowercase": True, "numbers": True, "symbols": True}
        exclusion_terms_text = ""
        inclusion_terms_text = ""

        if request.method == "POST":
            try:
                raw_length = request.form.get("length", "20")
                if not raw_length.isdecimal():
                    raise PasswordGenerationError("Enter a whole-number password length.")
                exclusion_terms_text = request.form.get("exclusion_terms", "")
                inclusion_terms_text = request.form.get("inclusion_terms", "")
                settings = {
                    "length": int(raw_length),
                    "uppercase": request.form.get("uppercase") == "on",
                    "lowercase": request.form.get("lowercase") == "on",
                    "numbers": request.form.get("numbers") == "on",
                    "symbols": request.form.get("symbols") == "on",
                }
                generated_password = generate_password(
                    **settings, excluded_terms=exclusion_terms_text, included_terms=inclusion_terms_text
                )
            except PasswordGenerationError as exc:
                error_message = str(exc)

        response = app.make_response(render_template(
            "generator.html",
            page_title="Generate Password",
            active_page="generate",
            generated_password=generated_password,
            error_message=error_message,
            settings=settings,
            # Values are echoed only to preserve the current form workflow. Jinja's autoescaping is enabled; responses are no-store. This increases local DOM exposure.
            exclusion_terms_text=exclusion_terms_text,
            inclusion_terms_text=inclusion_terms_text,
        ))
        if request.method == "POST":
            # Prevent intermediaries and browsers from caching a secret-bearing response.
            response.headers["Cache-Control"] = "no-store, max-age=0"
            response.headers["Pragma"] = "no-cache"
            response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.get("/analyze")
    def analyze():
        return render_template("analyzer.html", page_title="Analyze Password", active_page="analyze")

    @app.get("/crack-time")
    def crack_time():
        return render_template("crack_time.html", page_title="Crack-Time Estimate", active_page="crack-time")

    @app.get("/security")
    def security():
        return render_template("security.html", page_title="Security Guidance", active_page="security")

    @app.get("/privacy")
    def privacy():
        return render_template("privacy.html", page_title="Settings & Privacy", active_page="privacy")

    return app
