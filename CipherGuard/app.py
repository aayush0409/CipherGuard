"""CipherGuard Flask application entry point."""
from cipherguard import create_app

app = create_app()

if __name__ == "__main__":
    # Keep the interactive debugger disabled by default; never expose it in production.
    app.run(debug=False)
