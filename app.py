from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3
from sqlite3 import Error

app = Flask(__name__)
app.secret_key = 'my_secret_key'
DICTIONARY_DB = 'dictionary.sqlite'  # Set up secret key and database connection

def connect_to_database(db_file):  # Connect to database function
    try:
        connection = sqlite3.connect(db_file)
        return connection
    except Error as e:  # Check if an error occurs
        print("Something went wrong while connecting")
        print(e)
    return None

@app.route('/')
def render_homepage():
    return render_template('home.html')

@app.route('/login', methods=['POST', 'GET'])
def render_login():
    if 'email' in session:
        user_name = session.get('name')
        if user_name:  # Check if user_name is not None
            error_message = f"You are already logged in as {user_name}."
            return render_template('login.html', error=error_message)

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('user_password')

        conn = sqlite3.connect(DICTIONARY_DB)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM user_info WHERE email=? AND password=?", (email, password))
        user = cursor.fetchone()
        conn.close()

        if user:
            session['email'] = email
            session['name'] = user[3]  # Assuming the name is in the 4th column (fname)
            session['teacher'] = bool(user[5])  # Assuming the Teacher column is the 6th column
            return redirect(url_for('render_homepage'))  # Redirect to homepage after login
        else:
            error_message = "Invalid email or password. Please try again."
            return render_template('login.html', error=error_message)

    return render_template('login.html')

@app.route('/logout')
def render_logout():
    session.clear()
    return redirect(url_for('render_login'))  # Redirect to login page after logout

@app.route('/signup', methods=['POST', 'GET'])
def render_signup_page():  # Signup page
    if request.method == 'POST':  # Will be posting information to the table
        email = request.form.get('email')
        password = request.form.get('user_password')
        verify_password = request.form.get('user_password_verify')
        firstname = request.form.get('firstname')
        lastname = request.form.get('lastname')  # Add to the table

        if password != verify_password:  # Verify passwords
            error_message = "Passwords do not match. Please try again."
            return render_template('signup.html', error=error_message)

        con = connect_to_database(DICTIONARY_DB)  # Connect to database
        cur = con.cursor()
        cur.execute("INSERT INTO user_info (email, password, fname, lname) VALUES (?, ?, ?, ?)",
                    (email, password, firstname, lastname))  # Insert info into table
        con.commit()
        con.close()

        return redirect('/')

    return render_template('signup.html')

@app.route('/dictionary', methods=['GET'])
def render_dictionary():
    if 'email' not in session:
        return redirect('/login')  # Redirect to login if user is not logged in

    category = request.args.get('category', '').lower()
    level_from = request.args.get('level_from')
    level_to = request.args.get('level_to')

    conn = sqlite3.connect(DICTIONARY_DB)
    cursor = conn.cursor()

    # Make the SQL query based on the selected filters
    query = "SELECT * FROM me_dictionary WHERE 1=1"
    params = []

    if category:
        query += " AND LOWER(Category) = ?"
        params.append(category)

    if level_from and level_to:
        query += " AND Level BETWEEN ? AND ?"
        params.extend([level_from, level_to])

    cursor.execute(query, params)
    dictionary_data = cursor.fetchall()
    conn.close()

    return render_template('dictionary.html', dictionary_data=dictionary_data)

@app.route('/add_word', methods=['GET', 'POST'])
def render_add_word_form():
    if 'email' not in session:
        return redirect('/login')

    if not session.get('teacher'):
        return redirect(url_for('permission_denied'))

    if request.method == 'POST':
        m_word = request.form.get('m_word')
        e_word = request.form.get('e_word')
        category = request.form.get('category')
        definition = request.form.get('definition')
        level = request.form.get('level')

        conn = sqlite3.connect(DICTIONARY_DB)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO me_dictionary (M_word, E_word, Category, Definition, Level) VALUES (?, ?, ?, ?, ?)",
                       (m_word, e_word, category, definition, level))
        conn.commit()
        conn.close()

        return redirect(url_for('render_dictionary'))

    return render_template('add_word_form.html')

@app.route('/permission_denied')
def permission_denied():
    return render_template('permission_denied.html')

if __name__ == '__main__':
    app.run()
