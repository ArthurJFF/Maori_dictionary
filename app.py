from flask import Flask, render_template, request, redirect, session, url_for, jsonify
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

    if request.method == 'POST':  # gets email and password from table
        email = request.form.get('email')
        password = request.form.get('user_password')

        conn = connect_to_database(DICTIONARY_DB)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM user_info WHERE email=? AND password=?", (email, password))
        # check user with required credentials exists
        user = cursor.fetchone()
        conn.close()

        if user:
            session['email'] = email  # set variables for session that are used to personalise the user experience
            session['user_id'] = user[0]
            session['name'] = user[3]
            session['teacher'] = bool(user[5])
            return redirect(url_for('render_homepage'))
        else:
            error_message = "Invalid email or password. Please try again."  # error message if login fails
            return render_template('login.html', error=error_message)

    return render_template('login.html')


@app.route('/logout')
def render_logout():
    session.clear()
    return redirect(url_for('render_login'))  # Redirect to login page after logout


@app.route('/signup', methods=['POST', 'GET'])
def render_signup_page():  # Signup page
    if request.method == 'POST':  # Will be posting information to the table
        email = request.form.get('email')  # variables = whatever is entered into the table
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


@app.route('/view_word/<int:word_id>', methods=['GET'])  # route for viewing details of individual word once clicked
def view_word(word_id):
    if 'email' not in session:
        return redirect('/login')  # Redirect to login if user is not logged in

    conn = connect_to_database(DICTIONARY_DB)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM me_dictionary WHERE id = ?", (word_id,))
    # query to get data from row with the corresponding word id
    word = cursor.fetchone()
    conn.close()

    return render_template('view_word.html', word=word)


@app.route('/edit_word/<int:word_id>', methods=['GET', 'POST'])
# this allows the teacher to edit existing words in the dictionary
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

        cursor.execute("""
            UPDATE me_dictionary
            SET M_word = ?, E_word = ?, Category = ?, Definition = ?, Level = ?, image_url = ?
            WHERE id = ?
        """, (m_word, e_word, category, definition, level, image_url, word_id))
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

        conn = connect_to_database(DICTIONARY_DB)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO me_dictionary (M_word, E_word, Category, Definition, Level, image_url) "
                       "VALUES (?, ?, ?, ?, ?, ?)",
                       (m_word, e_word, category, definition, level, image_url))
        # get the data from the form then insert them into the right row of me_dictionary
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
