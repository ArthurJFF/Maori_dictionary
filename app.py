from flask import Flask, render_template, request, redirect, session, url_for, jsonify, flash
import sqlite3
import bcrypt
from datetime import datetime

from sqlite3 import Error
from bcrypt import hashpw, gensalt, checkpw
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
def render_login_page():  # Login page
    if request.method == 'POST':  # If the user submits the login form
        email = request.form.get('email')  # Get the email entered by the user
        password = request.form.get('user_password')  # Get the password entered by the user

        con = connect_to_database(DICTIONARY_DB)  # Connect to the database
        cur = con.cursor()
        cur.execute("SELECT user_id, password, fname, lname, teacher FROM user_info WHERE email = ?", (email,))  # Retrieve user data
        result = cur.fetchone()  # Fetch the first result
        con.close()

        if result:
            stored_hashed_password = result[1].encode('utf-8')  # Convert the stored hashed password back to bytes
            if bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password):  # Verify the password
                session['email'] = email
                session['firstname'] = result[2]
                session['lastname'] = result[3]
                session['user_id'] = result[0]  # Set the user_id in the session
                session['teacher'] = result[4]  # Set the teacher status in the session

                return redirect(url_for('render_homepage'))  # Redirect to home if login is successful
            else:
                error_message = "Incorrect password. Please try again."
        else:
            error_message = "Email not found. Please try again."

        return render_template('login.html', error=error_message)  # Render the login page with error message

    return render_template('login.html')  # Render the login page



@app.route('/logout')
def render_logout():
    session.clear()
    return redirect(url_for('render_login_page'))  # Redirect to login page after logout


@app.route('/signup', methods=['POST', 'GET'])
def render_signup_page():  # Signup page
    if request.method == 'POST':  # Will be posting information to the table
        email = request.form.get('email')  # variables = whatever is entered into the table
        password = request.form.get('user_password')
        verify_password = request.form.get('user_password_verify')
        firstname = request.form.get('firstname')
        lastname = request.form.get('lastname')

        if password != verify_password:  # Verify passwords
            error_message = "Passwords do not match. Please try again."
            return render_template('signup.html', error=error_message)

        # Hash the password before storing it
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        con = connect_to_database(DICTIONARY_DB)  # Connect to database
        cur = con.cursor()
        cur.execute("INSERT INTO user_info (email, password, fname, lname, teacher) VALUES (?, ?, ?, ?, ?)",
                    (email, hashed_password, firstname, lastname, False))  # Insert info into table
        con.commit()
        con.close()

        return redirect('/')

    return render_template('signup.html')

@app.route('/teacher_signup', methods=['POST', 'GET'])
def render_teacher_signup_page():  # Teacher signup page
    # Check if the user is a teacher
    if 'email' in session and session.get('teacher'):
        if request.method == 'POST':
            # Handle form submission for teacher signup
            email = request.form.get('email')
            password = request.form.get('user_password')
            verify_password = request.form.get('user_password_verify')
            firstname = request.form.get('firstname')
            lastname = request.form.get('lastname')
            is_teacher = True  # Set the user as a teacher

            if password != verify_password:
                error_message = "Passwords do not match. Please try again."
                return render_template('teacher_signup.html', error=error_message)

            # Hash the password before storing it
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

            con = connect_to_database(DICTIONARY_DB)
            cur = con.cursor()
            cur.execute("INSERT INTO user_info (email, password, fname, lname, teacher) VALUES (?, ?, ?, ?, ?)",
                        (email, hashed_password, firstname, lastname, is_teacher))
            con.commit()
            con.close()

            return redirect('/')  # Redirect to homepage after signup

        return render_template('teacher_signup.html')  # Render the teacher signup page

    else:
        return redirect(url_for('permission_denied'))  # Redirect unauthorized users

# Check if the user is a teacher to render the teacher dashboard
@app.route('/teacher_dashboard')
def render_teacher_dashboard():
    if 'email' in session and session.get('teacher'):
        return render_template('teacher_dashboard.html')
    else:
        return redirect(url_for('permission_denied'))  # Redirect unauthorized users


@app.route('/dictionary', methods=['GET'])
def render_dictionary():
    if 'email' not in session:
        return redirect('/login')  # Redirect to login if user is not logged in

    user_id = session['user_id']  # Get the logged in user's ID
    category = request.args.get('category', '').lower()  # gets the filters the user puts in
    level_from = request.args.get('level_from')
    level_to = request.args.get('level_to')
    learned_filter = request.args.get('learned_filter')

    conn = connect_to_database(DICTIONARY_DB)
    cursor = conn.cursor()

    # Make the SQL query based on the selected filters
    query = """
    SELECT me_dictionary.id, me_dictionary.M_word, me_dictionary.E_word, me_dictionary.Category, 
            me_dictionary.Definition,
           me_dictionary.Level, CASE WHEN learned_words.word_id IS NOT NULL THEN 1 ELSE 0 END as learned
    FROM me_dictionary
    LEFT JOIN learned_words ON me_dictionary.id = learned_words.word_id AND learned_words.user_id = ?  
    WHERE 1=1
    """  # checks if each word has been learnt by the current user.
    # Left join means all words included even if not in "learned words" then filters by user
    params = [user_id]

    if category:  # this section checks for filters and then makes conditional SQL queries to be displayed on the table
        query += " AND LOWER(Category) = ?"
        params.append(category)

    if level_from and level_to:
        query += " AND Level BETWEEN ? AND ?"
        params.extend([level_from, level_to])

    if learned_filter:
        if learned_filter == 'learned':
            query += " AND learned_words.word_id IS NOT NULL"
        elif learned_filter == 'unlearned':
            query += " AND learned_words.word_id IS NULL"

    cursor.execute(query, params)
    dictionary_data = cursor.fetchall()
    conn.close()

    return render_template('dictionary.html', dictionary_data=dictionary_data)


@app.route('/view_word/<int:word_id>', methods=['GET'])
def view_word(word_id):
    if 'email' not in session:
        return redirect('/login')  # Redirect to login if user is not logged in

    conn = connect_to_database(DICTIONARY_DB)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM me_dictionary WHERE id = ?", (word_id,))
    word = cursor.fetchone()

    teacher_name = None

    # Fetch teacher name from user_info table using teacher_id
    if word[9]:
        cursor.execute("SELECT fname, lname FROM user_info WHERE user_id = ?", (word[9],))
        teacher_data = cursor.fetchone()

        if teacher_data:
            teacher_name = f"{teacher_data[0]} {teacher_data[1]}"

    conn.close()

    date_added = None
    date_modified = None

    # Parse date added
    if word[7]:
        try:
            date_added = datetime.strptime(word[7][:10], "%Y-%m-%d").strftime("%Y-%m-%d")
        except ValueError:
            flash('Error parsing date added.')

    # Parse date modified
    if word[8]:
        try:
            date_modified = datetime.strptime(word[8][:10], "%Y-%m-%d").strftime("%Y-%m-%d")
        except ValueError:
            flash('Error parsing date modified.')

    return render_template('view_word.html', word=word, teacher_name=teacher_name, date_added=date_added, date_modified=date_modified)


@app.route('/edit_word/<int:word_id>', methods=['GET', 'POST'])
def edit_word(word_id):
    if 'email' not in session:
        return redirect('/login')  # Redirect to login if user is not logged in

    if not session.get('teacher'):  # if user isn't a teacher permission denied
        return redirect(url_for('permission_denied'))

    conn = connect_to_database(DICTIONARY_DB)
    cursor = conn.cursor()

    if request.method == 'POST':  # retrieves values inputted into the fields
        m_word = request.form.get('m_word')
        e_word = request.form.get('e_word')
        category = request.form.get('category')
        definition = request.form.get('definition')
        level = request.form.get('level')
        image_url = request.form.get('image_url')
        teacher_id = session.get('user_id')  # Get the logged-in teacher's ID

        # Validate level input is in the correct bounds
        try:
            level = int(level)
            if level < 1 or level > 10:
                flash('Invalid level. Please enter a number between 1 and 10.')
                return redirect(url_for('edit_word', word_id=word_id))
        except ValueError:
            flash('Invalid level. Please enter a valid number.')
            return redirect(url_for('edit_word', word_id=word_id))

        cursor.execute("""
            UPDATE me_dictionary
            SET M_word = ?, E_word = ?, Category = ?, Definition = ?, Level = ?, image_url = ?, date_modified = ?, teacher_id = ?
            WHERE id = ?
        """, (m_word, e_word, category, definition, level, image_url, datetime.now(), teacher_id, word_id))
        # updates the corresponding columns for the selected word id

        conn.commit()
        conn.close()

        return redirect(url_for('render_dictionary'))

    cursor.execute("SELECT * FROM me_dictionary WHERE id = ?", (word_id,))  # SQL query for row with same word id
    word = cursor.fetchone()
    conn.close()

    return render_template('edit_word_form.html', word=word)




@app.route('/delete_word/<int:word_id>', methods=['GET', 'POST'])
def delete_word(word_id):
    if 'email' not in session:
        return redirect('/login')  # Redirect to login if user is not logged in

    if not session.get('teacher'):
        return redirect(url_for('permission_denied'))

    conn = connect_to_database(DICTIONARY_DB)
    cursor = conn.cursor()

    if request.method == 'POST':  # delete from dictionary row with corresponding word id
        cursor.execute("DELETE FROM me_dictionary WHERE id = ?", (word_id,))
        conn.commit()
        conn.close()

        return redirect(url_for('render_dictionary'))

    cursor.execute("SELECT * FROM me_dictionary WHERE id = ?", (word_id,))
    word = cursor.fetchone()
    conn.close()

    return render_template('confirm_delete.html', word=word)


@app.route('/add_word', methods=['GET', 'POST'])
def add_word():
    if 'email' not in session:
        return redirect('/login')  # Redirect to login if user is not logged in

    if not session.get('teacher'):
        return redirect(url_for('permission_denied'))

    if request.method == 'POST':
        m_word = request.form.get('m_word')
        e_word = request.form.get('e_word')
        category = request.form.get('category')
        definition = request.form.get('definition')
        level = request.form.get('level')
        image_url = request.form.get('image_url')
        teacher_id = session.get('user_id')  # Get the logged-in teacher's ID

        # Validate level input is in the right bounds
        try:
            level = int(level)
            if level < 1 or level > 10:
                flash('Invalid level. Please enter a number between 1 and 10.')
                return redirect(url_for('add_word'))
        except ValueError:
            flash('Invalid level. Please enter a valid number.')
            return redirect(url_for('add_word'))

        conn = connect_to_database(DICTIONARY_DB)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO me_dictionary (M_word, E_word, Category, Definition, Level, image_url, date_added, teacher_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (m_word, e_word, category, definition, level, image_url, datetime.now(), teacher_id))
        conn.commit()
        conn.close()

        return redirect(url_for('render_dictionary'))

    return render_template('add_word_form.html')


@app.route('/permission_denied')  # when not teacher tries to access teacher webpages
def permission_denied():
    return render_template('permission_denied.html')


@app.route('/learn_word', methods=['POST'])  # identify word as learned and change table
def learn_word():
    if 'email' not in session:
        return jsonify({'status': 'fail'})
        # prevents unauthorised users from marking as learnt in case they somehow got to the dictionary

    user_id = session['user_id']
    word_id = request.form.get('word_id')  # gets the user id and id of word they want to mark as learned

    conn = connect_to_database(DICTIONARY_DB)
    cursor = conn.cursor()

    cursor.execute("INSERT INTO learned_words (user_id, word_id) VALUES (?, ?)", (user_id, word_id))
    # insert the the inputted data into the table. So the user id and the word id into it
    conn.commit()
    conn.close()

    return jsonify({'status': 'success'})  # json used because of javascript usage in this section


@app.route('/unlearn_word', methods=['POST'])  # opposite of above route
def unlearn_word():
    if 'email' not in session:
        return jsonify({'status': 'fail'})

    user_id = session['user_id']
    word_id = request.form.get('word_id')

    conn = connect_to_database(DICTIONARY_DB)
    cursor = conn.cursor()

    cursor.execute("DELETE FROM learned_words WHERE user_id = ? AND word_id = ?", (user_id, word_id))
    conn.commit()
    conn.close()

    return jsonify({'status': 'success'})


if __name__ == '__main__':
    app.run()
