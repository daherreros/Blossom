from flask import Flask, render_template, flash, redirect, url_for, session, request, logging
from data import Articles
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt

app = Flask(__name__)

# Config MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'root'
app.config['MYSQL_DB'] = 'blossom'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
# init MySQL
mysql = MySQL(app)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        name = request.form['name']
        password_candidate = request.form['password']

        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM patients WHERE name = %s", [name])

        if result > 0:
            data = cur.fetchone()
            password = data['password']

            if sha256_crypt.verify(password_candidate, password):
                session['logged-in'] = True
                session['name'] = name

                flash('You are now logged in.', 'success')
                return redirect(url_for('dashboard'))
            else:
                return redirect(url_for('login'))
        else:
            return redirect(url_for('login'))
        cur.close()
    return render_template('home.html')

@app.route('/about')
def about():
    return render_template("about.html")

@app.route('/quiz')
def quiz():
    return render_template("quiz.html")

@app.route('/faq')
def faq():
    return render_template("faq.html")

@app.route('/forgot')
def forgot():
    return render_template("forgot.html")

class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min = 1, max = 50)])
    age = StringField('Age', [validators.Length(min = 1, max = 100)])
    address = StringField('Address', [validators.Length(min = 1, max = 50)])
    caregiverName = StringField('Caregiver', [validators.Length(min = 1, max = 50)])
    avgQuizScore = StringField('AvgQuizScore', [validators.Length(min = 1, max = 5)])
    avgMatchingScore = StringField('AvgMatchingScore', [validators.Length(min = 1, max = 5)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        age = form.age.data
        address = form.address.data
        careGiver = form.caregiverName.data
        avgQuiz = form.avgQuizScore.data
        avgMatch = form.avgMatchingScore.data
        password = sha256_crypt.encrypt(str(form.password.data))

        # Create cursor
        cur = mysql.connection.cursor()

        # Execute query
        cur.execute("INSERT INTO patients(name, age, address, careGiver, avgQuiz, avgMatch, password) VALUES(%s, %s, %s, %s, %s, %s, %s)", (name, age, address, careGiver, avgQuiz, avgMatch, password))

        # Commit to DB
        mysql.connection.commit()

        # Close connection
        cur.close()
        flash("You are now registered and can log in.", "success")

        redirect(url_for('index'))
    return render_template('register.html', form = form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        name = request.form['name']
        password_candidate = request.form['password']
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM patients WHERE name = %s", [name])

        if result > 0:
            data = cur.fetchone()
            password = data['password']
            if sha256_crypt.verify(password_candidate, password):
                session['logged-in'] = True
                session['name'] = name

                flash('You are now logged in.', 'success')
                return redirect(url_for('dashboard'))
            else:
                error = "Invalid Login"
                return render_template('login.html', error = error)
        else:
            error = "Name Not Found"
            return render_template('login.html', error = error)
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/aboutLogged')
def aboutLogged():
    return render_template('aboutLogged.html')

@app.route('/faqLogged')
def faqLogged():
    return render_template('faqLogged.html')

if __name__ == "__main__":
    app.secret_key='secret123'
    app.run(debug=True)
