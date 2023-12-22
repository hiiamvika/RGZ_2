from . import db
from flask_login import UserMixin


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), nullable=False, unique=True)
    password = db.Column(db.String(360), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<User {self.username}>'

class Initiative(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    date_created = db.Column(db.DateTime, default=db.func.current_timestamp())
    score = db.Column(db.Integer, default=0)

    def __repr__(self):
        return f'<Initiative {self.title}>'

class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    initiative_id = db.Column(db.Integer, db.ForeignKey('initiative.id', ondelete='CASCADE'))#ondelete='CASCADE' будет удалять каскадно все, что стоит после 
    vote_type = db.Column(db.Boolean)  

    def __repr__(self):
        return f'<Vote {self.vote_type}>'
