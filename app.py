from flask_sqlalchemy import SQLAlchemy
from Db import db
from Db.models import User, Initiative, Vote
from flask_login import LoginManager
from flask import Flask, session
from rgz import rgz

app = Flask(__name__)
app.secret_key = "123"
user_db = "admin_rgz_base"
host_ip = "127.0.0.1"
host_port = "5432"
database_name = "rgz_base"
password = "123"

app.config ['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{user_db}:{password}@{host_ip}:{host_port}/{database_name}'
app.config ['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

login_manager = LoginManager()

login_manager.login_view = "rgz.login"
login_manager.init_app(app)

@login_manager.user_loader
def load_users(user_id):
    return User.query.get(int(user_id))


# def create_sample_initiatives():
#     with app.app_context():  # Гарантирует, что вы находитесь в контексте приложения Flask
#         existing_count = Initiative.query.count()
#         if existing_count < 100:
#             for i in range(existing_count + 1, 101):  # Creates up to 100 initiatives
#                 initiative = Initiative(
#                     title=f"Initiative {i}",
#                     description=f"Description for Initiative {i}",
#                     user_id=2  # Предполагается, что 2 — это идентификатор существующего пользователя.
#                 )
#                 db.session.add(initiative)
#             db.session.commit()
#             #print(f"Added {100 - existing_count} new initiatives.")

# create_sample_initiatives()
app.register_blueprint(rgz)