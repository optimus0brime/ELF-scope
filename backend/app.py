"""
Flask application factory.

We use the application factory pattern (create_app()) rather than a
module-level app object so that tests can spin up isolated instances
without side effects between test runs.
"""

import os
from flask import Flask, send_from_directory
from flask_cors import CORS


def create_app(config: dict = None) -> Flask:
    # Serve static files (the frontend) from the ../frontend directory
    frontend_dir = os.path.join(os.path.dirname(__file__), '..', 'frontend')
    app = Flask(__name__, static_folder=frontend_dir, static_url_path='')

    # Allow cross-origin requests — needed during development when the
    # frontend might be served on a different port from the API.
    CORS(app)

    # Default config
    app.config.update({
        'DEBUG':       True,
        'UPLOAD_DIR':  '/tmp/emulator_uploads',
        'MAX_CONTENT_LENGTH': 16 * 1024 * 1024,  # 16 MB max upload
    })
    if config:
        app.config.update(config)

    # Register the API blueprint (all routes under /api/...)
    from backend.api.routes import api
    app.register_blueprint(api)

    # Serve the frontend's index.html at the root URL
    @app.route('/')
    def index():
        return send_from_directory(frontend_dir, 'index.html')

    # Health check — useful for smoke-testing the server is up
    @app.route('/health')
    def health():
        return {'status': 'ok'}, 200

    return app
