from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from pyzbar.pyzbar import decode
from PIL import Image
import os
import requests

# Create the Flask app
app = Flask(__name__)

# App configuration
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['UPLOAD_FOLDER'] = './uploads/'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app_database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db = SQLAlchemy(app)

# Pinata API credentials
api_key = "54e8978af30661887cf9"
api_secret = "9f062785828ab44b5a4d86155257ddea5c8ccad1dee910e60184687895ebe4b6"
pinata_endpoint = "https://api.pinata.cloud/pinning/pinFileToIPFS"

# Define the User and Certificate models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    reward_points = db.Column(db.Integer, nullable=True, default=None)
    certificates = db.relationship('Certificate', backref='user', lazy=True)

    def __repr__(self):
        return f'<User {self.username}>'

class Certificate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cid = db.Column(db.String(255), unique=True, nullable=False)
    certificate_name = db.Column(db.String(150), nullable=False)
    points = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f'<Certificate {self.certificate_name} (CID: {self.cid})>'

# Create database tables
with app.app_context():
    db.create_all()

# Utility functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def contains_valid_qr_with_link(filepath):
    image = Image.open(filepath)
    decoded_objects = decode(image)
    
    for obj in decoded_objects:
        data = obj.data.decode("utf-8")
        if data.startswith('http://') or data.startswith('https://'):
            return True
    flash('No valid QR code with a link detected in the image.')
    return False

def upload_to_pinata(filepath):
    with open(filepath, 'rb') as file:
        files = {'file': (os.path.basename(filepath), file)}
        headers = {
            'pinata_api_key': api_key,
            'pinata_secret_api_key': api_secret
        }
        response = requests.post(pinata_endpoint, headers=headers, files=files)
        if response.status_code == 200:
            return response.json().get('IpfsHash')
        else:
            flash(f"Failed to upload file to IPFS. Status code: {response.status_code}")
            return None

# Routes
@app.route('/')
def home():
    if 'username' in session:
        # Fetch the user from the database
        user = User.query.filter_by(username=session['username']).first()

        # Check if user exists before accessing attributes
        if user:
            return render_template('home.html', username=user.username)
        else:
            # Handle the case where the user is not found in the database
            flash('User not found in the database. Please log in again.', 'danger')
            return redirect(url_for('logout'))

    # If no user is logged in, redirect to login page
    return redirect(url_for('login'))



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['username'] = user.username
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid credentials.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful!', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if 'username' not in session:
        flash('Please log in to upload files.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Capture file details and form inputs
        file = request.files.get('file')
        name = request.form.get('name')
        category = request.form.get('category')

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            if contains_valid_qr_with_link(filepath):
                try:
                    # Upload the file to Pinata IPFS
                    cid = upload_to_pinata(filepath)
                    if cid:
                        # Fetch the logged-in user
                        user = User.query.filter_by(username=session['username']).first()

                        # Assign reward points based on the category
                        if category == "NPTEL":
                            reward_points = 5
                        elif category == "Data Science":
                            reward_points = 10
                        elif category == "Web Development":
                            reward_points = 20
                        elif category == "Cybersecurity":
                            reward_points = 10
                        else:
                            reward_points = 0  # Default for undefined categories

                        # Save certificate details to the database
                        new_certificate = Certificate(
                            cid=cid,
                            certificate_name=name,
                            points=reward_points,
                            user_id=user.id  # Associate with the logged-in user
                        )
                        db.session.add(new_certificate)

                        # Update user's reward points in the User profile
                        if user.reward_points is None:
                            user.reward_points = 0  # Initialize if it's None
                        user.reward_points += reward_points
                        db.session.commit()

                        flash(f'File uploaded to IPFS with CID: {cid}. {reward_points} points awarded, and added to your profile.', 'success')

                    os.remove(filepath)
                except Exception as e:
                    flash(f'Error uploading to IPFS: {str(e)}', 'danger')
                    os.remove(filepath)
            else:
                os.remove(filepath)
                flash('File does not contain a valid QR code with a link.', 'danger')

            return redirect(url_for('upload_file'))

    return render_template('upload.html')


@app.route('/profile/<username>')
def profile(username):
    user = User.query.filter_by(username=username).first()

    if user:
        return render_template('profile.html', user=user)
    else:
        flash('User not found.', 'danger')
        return redirect(url_for('home'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))

# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)
