import mysql.connector
import hashlib
import re
import random
from dotenv import load_dotenv
import os

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

# Ensures a valid email is entered
def email_check():
    while True:
        try:
            email = input("Email: ").strip()
            if not re.search(r".+@.+", email):
                raise ValueError("Please enter a valid email address")
            else:
                break
        except ValueError as e:
            print(e)
    return email

# Function to ensure password and confirmation match
def pass_check():
    while True:
        password = input("Password: ")
        conf_password = input("Confirm Password: ")
        if password != conf_password:
            print("Please confirm your passwords match")
        else:
            return password

# Function to check password length
def pass_length(password):
    return len(password) > 12

# Function to check for uppercase letter in password
def pass_capital(password):
    return any(char.isupper() for char in password)

# Function to check for special character in password
def pass_special(password):
    special = "!@#$%^&*()-+?_=,<>/."
    return any(char in special for char in password)

# Function to check for numerical value in password
def pass_numerical(password):
    numerical = "0123456789"
    return any(char in numerical for char in password)

# Generate unique random salt for user
def generate_salt():
    return str(random.randint(100000, 999999))

# Hash the user password with salt to ensure security
def hash_password(password, salt):
    hashed_password = hashlib.sha256((password + str(salt)).encode()).hexdigest()
    return hashed_password

# Function to handle wire transfer
def wire_transfer(email):
    while True:
        recipient = input("Please enter the recipient's email: ")
        wire_amount = int(input("How much would you like to send: $"))

        # Check if the recipient exists
        recipient_exists = check_user_exists(recipient)

        if not recipient_exists:
            print("Recipient not found. Wire transfer canceled.")
            return

        # Check if the user has sufficient funds
        mycursor.execute("SELECT balance FROM information WHERE email = %s", (email,))
        current_balance = mycursor.fetchone()[0]

        if wire_amount > current_balance:
            print("Insufficient funds. Wire transfer canceled.")
        else:
            # Update sender's balance
            mycursor.execute("UPDATE information SET balance = balance - %s WHERE email = %s", (wire_amount, email))
            
            # Update recipient's balance
            mycursor.execute("UPDATE information SET balance = balance + %s WHERE email = %s", (wire_amount, recipient))
            
            mydb.commit()
            print("Wire transfer successful!")

        another_transfer = input("Do you want to make another wire transfer? (yes/no): ").strip().lower()
        if another_transfer != 'yes':
            break
        
# Function to check if a user with given email exists
def check_user_exists(email):
    mycursor.execute("SELECT COUNT(*) FROM information WHERE email = %s", (email,))
    count = mycursor.fetchone()[0]
    return count > 0

# Proceed with following steps for user after a successful login or account was created
def dashboard_steps(email):
     while True:
        action = input("Would you like to make a deposit, withdraw, check balance, or wire transfer? ").strip().lower()
        try:
            if action == "deposit":
                deposit_amount = int(input("How much would you like to deposit? $"))
                mycursor.execute("UPDATE information SET balance = balance + %s WHERE email = %s", (deposit_amount, email))
                mydb.commit()

                mycursor.execute("SELECT balance FROM information WHERE email = %s", (email,))
                current_balance = mycursor.fetchone()[0]
                print(f"Deposit successful! Remaining balance: ${current_balance}")
                break

            elif action == "withdraw":
                withdraw_amount = int(input("How much would you like to withdraw? $"))
                mycursor.execute("SELECT balance FROM information WHERE email = %s", (email,))
                current_balance = mycursor.fetchone()[0]

                if withdraw_amount > current_balance:
                    print("Insufficient funds. Withdrawal canceled.")
                else:
                    mycursor.execute("UPDATE information SET balance = balance - %s WHERE email = %s", (withdraw_amount, email))
                    mydb.commit()
                    print("Withdrawal successful!")
                break

            elif action == "check balance" or action == "balance":
                mycursor.execute("SELECT balance FROM information where email = %s", (email,))
                current_balance = mycursor.fetchone()[0]
                print(current_balance)
                break

            elif action == "wire transfer" or action == "wire":
                wire_transfer(email)
            else:
                print("Please make sure that you select either 'deposit', 'withdraw', 'balance', or 'wire transfer'")

        except ValueError:
            print("Please make sure you are entering a valid numerical value.")

# Following steps for a user logging in to ensure they have an account
def login():
    while True:
        email = input("Please enter email: ").lower()
        password = input("Please enter your password: ")

        mycursor.execute("SELECT salt FROM information WHERE email = %s", (email,))
        salt_data = mycursor.fetchone()

        if salt_data:
            salt_value = salt_data[0]  # Use the correct field name to retrieve the salt
            hashed_password_input = hash_password(password, salt_value)

            mycursor.execute("SELECT * FROM information WHERE email = %s AND password = %s", (email, hashed_password_input))
            user_data = mycursor.fetchone()

            if user_data:
                print("Login successful!")
                dashboard_steps(email)
                break
            else:
                print("Incorrect password. Please try again.")
        else:
            print("Email not found. Please make sure you entered the correct email or create a new account.")
            break
# Steps for a new account to store their information
def new_acc():
    username = input("Please enter your username: ")
    email = email_check()

    # Check if the email already exists in the database
    mycursor.execute("SELECT * FROM information WHERE email = %s", (email,))
    existing_user = mycursor.fetchone()

    if existing_user:
        print("An account with this email already exists. Please use a different email.")
        return

    password = pass_check()

    if pass_length(password) and pass_capital(password) and pass_special(password) and pass_numerical(password):
        salt = generate_salt()
        hashed_password = hash_password(password, salt)
        mycursor.execute(sqlFormula, (username, email, hashed_password, salt, 0))
        mydb.commit()
        print("New account created successfully!")
        dashboard_steps(email)
    else:
        print("Please enter a valid password that includes the following:")
        print("- Capital letter")
        print("- Special Character")
        print("- 12 Characters")
        print("- Numerical Value")

# Initial function that will ask the user if they want to login or create an account
def main():
    new_user_questions = input("Would you like to login or create a new account? 'L' for login and 'N' for new account: ").strip().lower()
    while True:
        if new_user_questions == "l":
            login()
            break
        elif new_user_questions == "n":
            new_acc()
            break
        else:
            print("Please enter valid input 'L' or 'N'")

if __name__ == "__main__":
    main()
