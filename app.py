from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to your own secret key

# Function to create a connection to the SQLite database
def get_db_connection():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

# Creating users table if it doesn't exist
def create_users_table():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.close()

# Route for the signup page
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
        conn.commit()
        conn.close()

        return redirect(url_for('login'))
    return render_template('signup.html')

# Route for the login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('home'))
        else:
            return 'Invalid username or password'

    return render_template('login.html')

# Route for the home page (after login)
@app.route('/home')
def home():
    if 'logged_in' in session:
        return f'Welcome, {session["username"]}! You are logged in.'
    else:
        return redirect(url_for('login'))

# Route for logging out
@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    create_users_table()  # Create the users table if it doesn't exist
    app.run(debug=True)
