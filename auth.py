from flask import Blueprint, request, flash, redirect, url_for, session, jsonify, render_template
from authlib.integrations.flask_client import OAuth
import pyodbc
import hashlib 
import os 
import ssl 
import binascii
import random
import smtplib
from extensions import oauth  # Import OAuth from extensions.py

auth_bp = Blueprint('auth', __name__)

# SQL Server connection string
DB_CONNECTION = "DRIVER={SQL Server};SERVER=BhuwanPC;DATABASE=HandwritingRecognitionDB;Trusted_Connection=yes;" 

#Database Connection Function
def get_db_connection(): 
    #Establish a connection with the SQL Server
    try: 
        conn = pyodbc.connect(DB_CONNECTION)
        return conn 
    except Exception as e: 
        print(f"Database Connection Error: {e}")
        return None

#Password Hash using SHA 256
def hash_password(password):
    hashed = hashlib.sha256(password.encode()).hexdigest()  # Convert to hex string
    return hashed

# Handling Google Callback
def create_or_update_google_user(user_info):
    conn = get_db_connection()
    if conn is None:
        raise Exception("Database connection failed")

    cursor = conn.cursor()
    try:
        # 1) Check if user record exists (by google_id or by email).
        select_query = """
            SELECT id, google_id, email, is_google_user
            FROM Users
            WHERE google_id = ? OR email = ?
        """
        
        print("user_info from Google:", user_info)

        cursor.execute(select_query, (user_info["sub"], user_info["email"]))
        row = cursor.fetchone()
        if row:
            # 2) If the user exists, mark them as google-only if not already
            update_query = """
                UPDATE Users
                SET google_id = ?, 
                    is_google_user = 1  -- Force Google-only
                WHERE id = ?
            """
            print("User row from DB:", row)  # Debugging
            cursor.execute(update_query, (user_info["sub"], row[0])) 
            conn.commit()
            return row[0] # or return any relevant user dict
        else:
            # 3) Insert a new user with google-only
            insert_query = """
                INSERT INTO Users (google_id, email, username, is_google_user)
                OUTPUT INSERTED.id
                VALUES (?, ?, ?, 1)
            """
            cursor.execute(insert_query, (user_info["sub"], user_info["email"], user_info["name"]))  # Use Google name as username
            new_user_id = cursor.fetchone()[0]
            conn.commit()
            return new_user_id

    finally:
        cursor.close()
        conn.close()



@auth_bp.route('/login', methods=['POST'])
def login():
    email = request.form.get('email')
    password = request.form.get('password')

    if not email or not password:
        flash("Email and password are required", "error")
        return redirect(url_for('home'))

    conn = get_db_connection()
    if conn is None:
        flash("Database connection failed", "error")
        return redirect(url_for('home'))

    cursor = conn.cursor()
    try:
        # Get user with matching email
        query = """
            SELECT id, password_hash, is_google_user
            FROM Users
            WHERE email = ?
        """
        cursor.execute(query, (email,))
        user_row = cursor.fetchone()

        if not user_row:
            # No user found at all
            flash("Invalid email or password", "error")
            return redirect(url_for('home'))

        is_google_only = user_row.is_google_user
        if is_google_only:
            # If this account is marked for Google-only, show a message
            flash("This account was created via Google OAuth. Please log in with Google.", "error")
            return redirect(url_for('home'))

        # If is_google_only == 0, we proceed with normal password check
        stored_hash = user_row.password_hash
        # Compare `stored_hash` with the hash of `password`
        # e.g.:
        import hashlib
        hashed_password = hash_password(password)
        
        print(f"Entered Hash: {hashed_password}")
        print(f"Stored Hash: {stored_hash}")

        if stored_hash == hashed_password:
            # Logged in successfully
            session['user'] = email
            flash("Login successful!", "success")
            return redirect(url_for('home'))
        else:
            flash("Invalid email or password", "error")
            return redirect(url_for('home'))

    except Exception as e:
        flash("An error occurred during login", "error")
        print(f"Login Error: {e}")
        return redirect(url_for('home'))
    finally:
        cursor.close()
        conn.close()


'''==========================Sign Up Route======================================'''
@auth_bp.route('/signup_page', methods=['GET'])
def signup_page():
    return render_template('signup.html')

@auth_bp.route('/signup', methods=['POST'])
def signup():
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')

    # Basic validations
    if not username or not email or not password:
        flash("All fields are required.", "error")
        return redirect(url_for('auth.signup_page'))

    conn = get_db_connection()
    if conn is None:
        flash("Database connection failed", "error")
        return redirect(url_for('auth.signup_page'))

    cursor = conn.cursor()
    try:
        # 1. Check if user email already exists
        cursor.execute("SELECT id FROM Users WHERE email = ?", (email,))
        existing_user = cursor.fetchone()
        if existing_user:
            flash("An account with this email already exists.", "error")
            return redirect(url_for('auth.signup_page'))

        # 2. Generate a verification code (6 digits, for example)
        verification_code = str(random.randint(100000, 999999))

        # 3. Hash the password
        password_hash = hash_password(password)

        # 4. Temporarily store the user in a table or store code in session
        #    For simplicity, let's store them in session so we can insert only after verification
        #    Alternatively, you can store them in a "UsersTemp" table or something similar
        session['signup_data'] = {
            'username': username,
            'email': email,
            'password_hash': password_hash,
            'verification_code': verification_code
        }

        # 5. Send verification code via email
        #    You need a working email server or provider's SMTP settings
        #    This is a simple example using Gmail's SMTP:
        try:
            sender_email = "ayanshrestha187@gmail.com"
            sender_password = "szrx ltkh ksgx ynri"  # Use an App Password if 2FA is on
            receiver_email = email

            message = f"""\
Subject: Your Verification Code

Hello {username},

Your verification code is: {verification_code}

Please enter this code on the verification page to complete your sign-up.
"""

            context = ssl.create_default_context()
            with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
                server.login(sender_email, sender_password)
                server.sendmail(sender_email, receiver_email, message)

        except Exception as e:
            print(f"Error sending verification email: {e}")
            flash("Failed to send verification code to your email.", "error")
            return redirect(url_for('auth.signup_page'))

        # 6. Redirect to verification page
        return redirect(url_for('auth.verify_page'))

    except Exception as e:
        flash("An error occurred during sign up", "error")
        print(f"Sign Up Error: {e}")
        return redirect(url_for('auth.signup_page'))
    finally:
        cursor.close()
        conn.close()

'''=================Verify Route for Sign In========================='''
@auth_bp.route('/verify_page', methods=['GET'])
def verify_page():
    # Just render the page that asks for the code
    return render_template('verify.html')


@auth_bp.route('/verify', methods=['POST'])
def verify():
    input_code = request.form.get('code')
    signup_data = session.get('signup_data')  # The data we stored after sign-up

    if not signup_data:
        flash("No signup data found. Please sign up again.", "error")
        return redirect(url_for('auth.signup_page'))

    stored_code = signup_data.get('verification_code')
    if input_code != stored_code:
        flash("Invalid verification code. Please try again.", "error")
        return redirect(url_for('auth.verify_page'))

    # If code matches, proceed to insert user into DB
    conn = get_db_connection()
    if conn is None:
        flash("Database connection failed", "error")
        return redirect(url_for('auth.signup_page'))

    cursor = conn.cursor()
    try:
        # Insert final user record
        insert_query = """
            INSERT INTO Users (username, email, password_hash, is_google_user)
            VALUES (?, ?, CONVERT(VARBINARY(MAX), ?), 0)
        """
        cursor.execute(insert_query, (
            signup_data['username'],
            signup_data['email'],
            signup_data['password_hash']
        ))
        conn.commit()

        # Clear session data
        session.pop('signup_data', None)

        flash("Your account has been created successfully!", "success")
        return redirect(url_for('home'))  # or wherever you want to send them
    except Exception as e:
        flash("An error occurred while creating your account.", "error")
        print(f"Verification Insert Error: {e}")
        return redirect(url_for('auth.signup_page'))
    finally:
        cursor.close()
        conn.close()


        
'''
======================== Google OAuth Initailization ============================
'''       
@auth_bp.route("/login/google")
def google_login():
    """Redirect to Google OAuth"""
    google = oauth.create_client("google")  # Create OAuth client dynamically
    return google.authorize_redirect(url_for("auth.google_callback", _external=True))
@auth_bp.route("/callback")
def google_callback():
    try:
        google = oauth.create_client("google")
        token = google.authorize_access_token()
        user_info = google.get("userinfo").json()
        
        # 1) Save or update user in DB
        local_user_id = create_or_update_google_user(user_info)  # Returns user_id (int)

        # 2) Store user info in session
        session["user"] = user_info["email"]  # Store user email as 'user' session key
        session["user_id"] = local_user_id  # Store user ID
        session["is_google_user"] = True  # Add flag for Google users
        
        flash("Google login successful!", "success")
        return redirect(url_for("home"))  # Redirect to home after login
    except Exception as e:
        flash("Google login failed. Please try again.", "error")
        print(f"Google Login Error: {e}")
        return redirect(url_for("home"))


        
'''
======================== Google OAuth Finished here ============================
'''    

@auth_bp.route('/logout')
def logout():
    """ Logs out the user and redirects to login page """
    session.pop('user', None)
    flash("You have been logged out.", "info")
    return redirect(url_for('home'))