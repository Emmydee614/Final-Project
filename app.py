from flask import Flask, render_template, request, redirect, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)

# defense mechanism
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

limiter = Limiter(key_func=get_remote_address,
default_limits=["5 per day", "5 per hour"])
limiter.init_app(app)
    

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

class LoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), nullable=False)
    ip_address = db.Column(db.String(64), nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())
    successful = db.Column(db.Boolean, default=False)

with app.app_context():
    db.create_all()


# Connect to SQLite database
def get_db_connection():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

# Create tables if they don't exist
def create_tables():
    conn = get_db_connection()
    conn.execute('''CREATE TABLE IF NOT EXISTS users
                 (username text PRIMARY KEY, password text)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS login_attempts
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, username text, ip_address text, timestamp text, successful integer)''')
    conn.commit()
    conn.close()

create_tables()

# Register a new user (for demonstration purposes)
def register_user(username, password):
    hashed_password = generate_password_hash(password)
    conn = get_db_connection()
    try:
        conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
        conn.commit()
        conn.close()
    except sqlite3.IntegrityError:
        print('Username already exists')

# Register the admin user
register_user('admin', 'password')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        ip_address = request.remote_addr
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if user and check_password_hash(user['password'], password):
            conn.execute('INSERT INTO login_attempts (username, ip_address, timestamp, successful) VALUES (?, ?, ?, ?)',

 (username, ip_address, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 1))
            conn.commit()
            conn.close()
            return redirect(url_for('dashboard'))
        else:
            conn.execute('INSERT INTO login_attempts (username, ip_address, timestamp, successful) VALUES (?, ?, ?, ?)',
                         (username, ip_address, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 0))
            conn.commit()
            conn.close()
            return 'Invalid credentials'
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    return 'Welcome to the dashboard!'

if __name__ == '__main__':
    app.run(debug=True)


