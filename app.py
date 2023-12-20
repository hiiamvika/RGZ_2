from flask_sqlalchemy import SQLAlchemy
from Db import db
from Db.models import users
from flask_login import LoginManager
from flask import Flask, session
from rgz import rgz

app = Flask(__name__)

app.register_blueprint(rgz)