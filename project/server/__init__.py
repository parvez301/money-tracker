# project/server/__init__.py

import os

from flask import Flask,request
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS

app = Flask(__name__)
CORS(app,resources={r"/auth/*": {"origins": "*"}})

app_settings = os.getenv(
    'APP_SETTINGS',
    'project.server.config.DevelopmentConfig'
)
app.config.from_object(app_settings)
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    if request.method == 'OPTIONS':
        response.headers['Access-Control-Allow-Methods'] = 'DELETE, GET, POST, PUT'
        headers = request.headers.get('Access-Control-Request-Headers')
        if headers:
            response.headers['Access-Control-Allow-Headers'] = headers
            print(response)
    return response
app.after_request(add_cors_headers)
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)
from project.server.auth.views import auth_blueprint
app.register_blueprint(auth_blueprint)
