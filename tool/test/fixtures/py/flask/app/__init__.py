from flask import Flask
from flask_cors import CORS


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "s3cr3t-in-code"
    CORS(app, supports_credentials=True)
    from app.views import api
    app.register_blueprint(api, url_prefix="/api")
    return app
