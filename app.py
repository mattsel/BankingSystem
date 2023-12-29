from flask import Flask, render_template, request, redirect, url_for, session
import mysql.connector
import hashlib
import re
import random
import logging
from dotenv import load_dotenv
import os

app = Flask(__name__, static_url_path='/static')
app.secret_key = 'your_secret_key'

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

# Initialize Database Connection
mydb = mysql.connector.connect(
    host=os.environ.get('DB_HOST'),
    user=os.environ.get('DB_USER'),
    passwd=os.environ.get('DB_PASSWORD'),
    database=os.environ.get('DB_NAME')
)
mycursor = mydb.cursor()

# SQL formula to insert new user information
sqlFormula = "INSERT INTO information (username, email, password, salt, balance) VALUES (%s, %s, %s, %s, %s)"

def get_balance(email):
    mycursor.execute("SELECT balance FROM information WHERE email = %s", (email,))
    return mycursor.fetchone()[0]

def get_username(email):
    mycursor.execute("SELECT username FROM information WHERE email = %s", (email,))
    return mycursor.fetchone()[0]

def check_user_exists(email):
    mycursor.execute("SELECT COUNT(*) FROM information WHERE email = %s", (email,))
    count = mycursor.fetchone()[0]
    return count > 0

def pass_check(request):
    password = request.form.get('password')
    conf_password = request.form.get('confirm_password')
    if password != conf_password:
        return "Please confirm your passwords match"
    else:
        return password

def pass_length(password):
    return len(password) > 12

def pass_capital(password):
    return any(char.isupper() for char in password)

def pass_special(password):
    special = "!@#$%^&*()-+?_=,<>/."
    return any(char in special for char in password)

def pass_numerical(password):
    numerical = "0123456789"
    return any(char in numerical for char in password)

def generate_salt():
    return str(random.randint(100000, 999999))

def hash_password(password, salt):
    hashed_password = hashlib.sha256((password + str(salt)).encode()).hexdigest()
    return hashed_password

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error_message = None
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        mycursor.execute("SELECT salt FROM information WHERE email = %s", (email,))
        salt_data = mycursor.fetchone()

        if salt_data:
            salt_value = salt_data[0]
            hashed_password_input = hash_password(password, salt_value)

            mycursor.execute("SELECT * FROM information WHERE email = %s AND password = %s", (email, hashed_password_input))
            user_data = mycursor.fetchone()

            if user_data:
                session['email'] = email
                return redirect(url_for('dashboard'))
            else:
                error_message = "Incorrect password. Please try again."

    return render_template('login.html', error_message=error_message)

@app.route('/new_acc', methods=['GET', 'POST'])
def new_acc():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = pass_check(request)  # Pass the request to the function

        mycursor.execute("SELECT * FROM information WHERE email = %s", (email,))
        existing_user = mycursor.fetchone()

        if existing_user:
            return "An account with this email already exists. Please use a different email."

        if pass_length(password) and pass_capital(password) and pass_special(password) and pass_numerical(password):
            salt = generate_salt()
            hashed_password = hash_password(password, salt)
            mycursor.execute(sqlFormula, (username, email, hashed_password, salt, 0))
            mydb.commit()
            session['email'] = email
            return redirect(url_for('dashboard'))  # Redirect to the dashboard page
        else:
            return "Please enter a valid password that includes the following:\n- Capital letter\n- Special Character\n- 12 Characters\n- Numerical Value"

    return render_template('new_acc.html')

@app.route('/check_balance', methods=['GET'])
def check_balance():
    if 'email' in session:
        email = session['email']
        current_balance = get_balance(email)
        return f"Current balance: ${current_balance}"

    return redirect(url_for('login'))

@app.route('/withdraw', methods=['GET', 'POST'])
def withdraw():
    if 'email' in session:
        email = session['email']

        if request.method == 'POST':
            withdraw_amount = int(request.form.get('amount'))

            if withdraw_amount <= 0:
                return "Invalid withdrawal amount. Please enter a positive value."

            current_balance = get_balance(email)

            if withdraw_amount > current_balance:
                return "Insufficient funds. Withdrawal canceled."

            mycursor.execute("UPDATE information SET balance = balance - %s WHERE email = %s", (withdraw_amount, email))
            mydb.commit()

            return "Withdrawal successful!"

        return render_template('withdraw.html')
    else:
        return redirect(url_for('login'))

@app.route('/deposit', methods=['GET', 'POST'])
def deposit():
    if 'email' in session:
        email = session['email']

        if request.method == 'POST':
            deposit_amount = int(request.form.get('amount'))

            if deposit_amount <= 0:
                return "Invalid deposit amount. Please enter a positive value."

            mycursor.execute("UPDATE information SET balance = balance + %s WHERE email = %s", (deposit_amount, email))
            mydb.commit()

            return f"Deposit successful! Remaining balance: ${get_balance(email)}"

        return render_template('deposit.html')
    else:
        return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'email' in session:
        email = session['email']

        if request.method == 'POST':
            action = request.form.get('action')

            if action == "deposit":
                deposit_amount = int(request.form.get('amount'))
                mycursor.execute("UPDATE information SET balance = balance + %s WHERE email = %s", (deposit_amount, email))
                mydb.commit()
                return f"Deposit successful! Remaining balance: ${get_balance(email)}"

            elif action == "withdraw":
                withdraw_amount = int(request.form.get('amount'))
                current_balance = get_balance(email)

                if withdraw_amount > current_balance:
                    return "Insufficient funds. Withdrawal canceled."
                else:
                    mycursor.execute("UPDATE information SET balance = balance - %s WHERE email = %s", (withdraw_amount, email))
                    mydb.commit()
                    return "Withdrawal successful!"

            elif action == "check_balance":
                return f"Current balance: ${get_balance(email)}"

            elif action == "wire_transfer":
                return redirect(url_for('wire_transfer'))

            else:
                return "Invalid action. Please choose a valid operation."

        return render_template('dashboard.html', username=get_username(email))
    else:
        return redirect(url_for('login'))

@app.route('/wire_transfer', methods=['GET', 'POST'])
def wire_transfer():
    if request.method == 'POST':
        recipient = request.form.get('recipient')
        wire_amount = int(request.form.get('amount'))

        recipient_exists = check_user_exists(recipient)

        if not recipient_exists:
            return "Recipient not found. Wire transfer canceled."

        current_balance = get_balance(session['email'])

        if wire_amount > current_balance:
            return "Insufficient funds. Wire transfer canceled."

        mycursor.execute("UPDATE information SET balance = balance - %s WHERE email = %s", (wire_amount, session['email']))
        mycursor.execute("UPDATE information SET balance = balance + %s WHERE email = %s", (wire_amount, recipient))
        mydb.commit()

        return "Wire transfer successful!"

    return render_template('wire_transfer.html')

if __name__ == "__main__":
    app.run(debug=True)

# Close database connection on application exit
@app.teardown_appcontext
def close_db_connection(exception=None):
    mycursor.close()
    mydb.close()
