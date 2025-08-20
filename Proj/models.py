from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    reward_points = db.Column(db.Integer, nullable=True, default=None)

    # Relationship to certificates
    certificates = db.relationship('Certificate', backref='user', lazy=True)

    def __repr__(self):
        return f'<User {self.username}>'

class Certificate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cid = db.Column(db.String(255), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    reward_points = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Linking Certificate to User

    def __repr__(self):
        return f'<Certificate {self.name} (CID: {self.cid})>'
