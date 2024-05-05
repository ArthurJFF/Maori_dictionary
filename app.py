from flask import Flask, render_template, request, redirect, session
import sqlite3
from sqlite3 import Error
app = Flask(__name__)
app.secret_key = 'my_secret_key'
DICTIONARY_DB = 'dictionary.sqlite'  # did importing, set up secret key and database connection


def connect_to_database(db_file):  # connect to database function
    try:
        connection = sqlite3.connect(db_file)
        return connection
    except Error as e:  # check if error occurs
        print("something went wrong while connecting")
        print(e)
    return None


@app.route('/')
def render_homepage():
    return render_template('home.html')


from flask import redirect, url_for

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
        cursor.execute("SELECT * FROM User_info WHERE email=? AND password=?", (email, password))
        user = cursor.fetchone()
        conn.close()

        if user:
            session['email'] = email
            session['name'] = user[1]
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
def render_signup_page():  # signup page
    if request.method == 'POST':  # will be posting information to the table
        email = request.form.get('email')
        password = request.form.get('user_password')
        verify_password = request.form.get('user_password_verify')
        firstname = request.form.get('firstname')
        lastname = request.form.get('lastname')  # add to the table

        if password != verify_password:  # verify passwords
            error_message = "Passwords do not match. Please try again."
            return render_template('signup.html', error=error_message)

        con = connect_to_database(DICTIONARY_DB)  # connect to database
        cur = con.cursor()
        cur.execute("INSERT INTO user_info (email, password, fname, lname) VALUES (?, ?, ?, ?)",
                    (email, password, firstname, lastname))   # insert info into table
        con.commit()
        con.close()

        return redirect('/')

    return render_template('signup.html')

@app.route('/dictionary')
def render_dictionary():
    if 'email' not in session:
        return redirect('/login')  # Redirect to login if user is not logged in

    conn = sqlite3.connect(DICTIONARY_DB)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM me_dictionary")
    dictionary_data = cursor.fetchall()
    conn.close()


    print(dictionary_data)

    return render_template('dictionary.html', dictionary_data=dictionary_data)



if __name__ == '__main__':
    app.run()
