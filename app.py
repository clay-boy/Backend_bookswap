from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import check_password_hash, generate_password_hash
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database and login manager
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Redirect unauthorized users to the login page

# -----------------------
# Database Models
# -----------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    # Relationship: one user may have many books
    books = db.relationship('Book', backref='owner', lazy=True)

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    author = db.Column(db.String(150), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# -----------------------
# Routes
# -----------------------

# Home page
@app.route('/')
def home():
    return render_template('index.html', user=current_user)

# Sign up route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        confirm = request.form.get('confirm_password')

        # Check if user already exists
        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'error')
            return redirect(url_for('signup'))
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('signup'))
        if password != confirm:
            flash('Passwords do not match', 'error')
            return redirect(url_for('signup'))

        # Create new user with hashed password
        try:
            new_user = User(
                email=email,
                username=username,
                password=generate_password_hash(password, method='pbkdf2:sha256')
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            flash('Account created successfully!', 'success')
            return redirect(url_for('home'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred. Please try again.', 'error')
            return redirect(url_for('signup'))

    return render_template('signup.html', user=current_user)

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if not user or not check_password_hash(user.password, password):
            flash('Please check your login details and try again.', 'error')
            return redirect(url_for('login'))

        login_user(user)
        flash('Logged in successfully!', 'success')
        return redirect(url_for('home'))

    return render_template('login.html', user=current_user)

# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('home'))

# View the logged-in user’s books
@app.route('/mybooks')
@login_required
def mybooks():
    books = Book.query.filter_by(owner_id=current_user.id).all()
    return render_template('mybooks.html', books=books, user=current_user)

# Add a new book (to swap)
@app.route('/addbook', methods=['GET', 'POST'])
@login_required
def addbook():
    if request.method == 'POST':
        title = request.form.get('title')
        author = request.form.get('author')
        
        # Debug: Print the current user's ID
        print(f"Current User ID: {current_user.id}")
        
        if not title or not author:
            flash('Title and author are required.', 'error')
            return redirect(url_for('addbook'))
        
        try:
            new_book = Book(title=title, author=author, owner_id=current_user.id)
            db.session.add(new_book)
            db.session.commit()
            flash('Book added successfully!', 'success')
            return redirect(url_for('mybooks'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred. Please try again.', 'error')
            return redirect(url_for('addbook'))
    
    return render_template('addbook.html', user=current_user)

# -----------------------
# Run the App
# -----------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create database tables if they don't exist
    app.run(debug=True)