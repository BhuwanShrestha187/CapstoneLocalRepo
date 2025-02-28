from flask import Blueprint, request, flash, redirect, url_for, session, jsonify, render_template
from authlib.integrations.flask_client import OAuth
import pyodbc
import bcrypt  # Import bcrypt instead of hashlib
import os
import ssl
import random
import smtplib
from extensions import oauth

auth_bp = Blueprint('auth', __name__)

# SQL Server connection string
DB_CONNECTION = "DRIVER={SQL Server};SERVER=BhuwanPC;DATABASE=HandwritingRecognitionDB;Trusted_Connection=yes;"

# Database Connection Function
def get_db_connection():
    try:
        conn = pyodbc.connect(DB_CONNECTION)
        return conn
    except Exception as e:
        print(f"Database Connection Error: {e}")
        return None

# Password Hashing with bcrypt
def hash_password(password):
    # Generate a salt and hash the password
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed

# Verify Password with bcrypt
def check_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed)

# Handling Google Callback (unchanged)
def create_or_update_google_user(user_info):
    conn = get_db_connection()
    if conn is None:
        raise Exception("Database connection failed")
    cursor = conn.cursor()
    try:
        select_query = """
            SELECT id, google_id, email, is_google_user
            FROM Users
            WHERE google_id = ? OR email = ?
        """
        cursor.execute(select_query, (user_info["sub"], user_info["email"]))
        row = cursor.fetchone()
        if row:
            update_query = """
                UPDATE Users
                SET google_id = ?, 
                    is_google_user = 1
                WHERE id = ?
            """
            cursor.execute(update_query, (user_info["sub"], row[0]))
            conn.commit()
            return row[0]
        else:
            insert_query = """
                INSERT INTO Users (google_id, email, username, is_google_user)
                OUTPUT INSERTED.id
                VALUES (?, ?, ?, 1)
            """
            cursor.execute(insert_query, (user_info["sub"], user_info["email"], user_info["name"]))
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
        return render_template('login.html', email=email)  # Pass email back

    conn = get_db_connection()
    if conn is None:
        flash("Database connection failed", "error")
        return render_template('login.html', email=email)  # Pass email back

    cursor = conn.cursor()
    try:
        query = """
            SELECT id, password_hash, is_google_user
            FROM Users
            WHERE email = ?
        """
        cursor.execute(query, (email,))
        user_row = cursor.fetchone()

        if not user_row:
            flash("Invalid email or password", "error")
            return render_template('login.html', email=email)  # Pass email back

        is_google_only = user_row.is_google_user
        if is_google_only:
            flash("This account was created via Google OAuth. Please log in with Google.", "error")
            return render_template('login.html', email=email)  # Pass email back

        stored_hash = user_row.password_hash  # This is now a binary bcrypt hash
        if check_password(password, stored_hash):
            session['user'] = email
            return redirect(url_for('home'))
        else:
            flash("Invalid email or password", "error")
            return render_template('login.html', email=email)  # Pass email back

    except Exception as e:
        flash("An error occurred during login", "error")
        print(f"Login Error: {e}")
        return render_template('login.html', email=email)  # Pass email back
    finally:
        cursor.close()
        conn.close()

@auth_bp.route('/signup_page', methods=['GET'])
def signup_page():
    return render_template('signup.html')

@auth_bp.route('/signup', methods=['POST'])
def signup():
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')

    if not username or not email or not password:
        flash("All fields are required.", "error")
        return redirect(url_for('auth.signup_page'))

    conn = get_db_connection()
    if conn is None:
        flash("Database connection failed", "error")
        return redirect(url_for('auth.signup_page'))

    cursor = conn.cursor()
    try:
        cursor.execute("SELECT id FROM Users WHERE email = ?", (email,))
        existing_user = cursor.fetchone()
        if existing_user:
            flash("An account with this email already exists.", "error")
            return redirect(url_for('auth.signup_page'))

        verification_code = str(random.randint(100000, 999999))
        password_hash = hash_password(password)

        session['signup_data'] = {
            'username': username,
            'email': email,
            'password_hash': password_hash,
            'verification_code': verification_code
        }

        try:
            sender_email = "ayanshrestha187@gmail.com"
            sender_password = "szrx ltkh ksgx ynri"
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

        return redirect(url_for('auth.verify_page'))

    except Exception as e:
        flash("An error occurred during sign up", "error")
        print(f"Sign Up Error: {e}")
        return redirect(url_for('auth.signup_page'))
    finally:
        cursor.close()
        conn.close()

@auth_bp.route('/verify_page', methods=['GET'])
def verify_page():
    return render_template('verify.html')

@auth_bp.route('/verify', methods=['POST'])
def verify():
    input_code = request.form.get('code')
    signup_data = session.get('signup_data')

    if not signup_data:
        flash("No signup data found. Please sign up again.", "error")
        return redirect(url_for('auth.signup_page'))

    stored_code = signup_data.get('verification_code')
    if input_code != stored_code:
        flash("Invalid verification code. Please try again.", "error")
        return redirect(url_for('auth.verify_page'))

    conn = get_db_connection()
    if conn is None:
        flash("Database connection failed", "error")
        return redirect(url_for('auth.signup_page'))

    cursor = conn.cursor()
    try:
        insert_query = """
            INSERT INTO Users (username, email, password_hash, is_google_user)
            VALUES (?, ?, ?, 0)
        """
        cursor.execute(insert_query, (
            signup_data['username'],
            signup_data['email'],
            signup_data['password_hash']  # Already hashed with bcrypt
        ))
        conn.commit()

        session.pop('signup_data', None)
        flash("Your account has been created successfully!", "success")
        return redirect(url_for('home'))
    except Exception as e:
        flash("An error occurred while creating your account.", "error")
        print(f"Verification Insert Error: {e}")
        return redirect(url_for('auth.signup_page'))
    finally:
        cursor.close()
        conn.close()

@auth_bp.route('/forgot_password_page', methods=['GET'])
def forgot_password_page():
    return render_template('forgot_password.html')

@auth_bp.route('/forgot_password', methods=['POST'])
def forgot_password():
    email = request.form.get('email')
    if not email:
        flash("Email is required.", "error")
        return redirect(url_for('auth.forgot_password_page'))

    conn = get_db_connection()
    if conn is None:
        flash("Database connection failed", "error")
        return redirect(url_for('auth.forgot_password_page'))

    cursor = conn.cursor()
    try:
        # Check if email exists and its Google-only status
        cursor.execute("SELECT id, is_google_user FROM Users WHERE email = ?", (email,))
        user_row = cursor.fetchone()

        if not user_row:
            flash("Account associated with this email is not found in our records!!", "danger")
            return redirect(url_for('auth.forgot_password_page'))

        is_google_only = user_row.is_google_user
        if is_google_only:
            flash("Error sending the verification link. This account is created using Google login.", "danger")
            return redirect(url_for('auth.forgot_password_page'))

        # If not Google-only, proceed with sending verification code
        verification_code = str(random.randint(100000, 999999))
        session['forgot_password_data'] = {
            'email': email,
            'verification_code': verification_code
        }

        try:
            sender_email = "ayanshrestha187@gmail.com"
            sender_password = "szrx ltkh ksgx ynri"
            receiver_email = email

            message = f"""\
Subject: Password Reset Verification Code

Hello,

Your verification code is: {verification_code}

Please enter this code on the verification page to reset your password.
"""

            context = ssl.create_default_context()
            with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
                server.login(sender_email, sender_password)
                server.sendmail(sender_email, receiver_email, message)

            flash("Verification code has been sent to your email.", "success")
            return redirect(url_for('auth.forgot_password_verify_page'))

        except Exception as e:
            print(f"Error sending verification email: {e}")
            flash("Failed to send verification code. Please try again.", "error")
            return redirect(url_for('auth.forgot_password_page'))

    except Exception as e:
        flash("An error occurred. Please try again.", "error")
        print(f"Forgot Password Error: {e}")
        return redirect(url_for('auth.forgot_password_page'))
    finally:
        cursor.close()
        conn.close()

@auth_bp.route('/forgot_password_verify_page', methods=['GET'])
def forgot_password_verify_page():
    return render_template('forgot_password_verify.html')

@auth_bp.route('/forgot_password_verify', methods=['POST'])
def forgot_password_verify():
    input_code = request.form.get('code')
    forgot_data = session.get('forgot_password_data')

    if not forgot_data:
        flash("Session expired or invalid. Please try again.", "error")
        return redirect(url_for('auth.forgot_password_page'))

    if input_code != forgot_data.get('verification_code'):
        flash("Invalid verification code. Please try again.", "error")
        return redirect(url_for('auth.forgot_password_verify_page'))

    flash("Verification successful! Please set a new password.", "success")
    return redirect(url_for('auth.reset_password_page'))

@auth_bp.route('/reset_password_page', methods=['GET'])
def reset_password_page():
    return render_template('reset_password.html')

@auth_bp.route('/reset_password', methods=['POST'])
def reset_password():
    forgot_data = session.get('forgot_password_data')
    if not forgot_data:
        flash("Session expired or invalid. Please try again.", "error")
        return redirect(url_for('auth.forgot_password_page'))

    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    if not new_password or not confirm_password:
        flash("Please fill all password fields.", "error")
        return redirect(url_for('auth.reset_password_page'))

    if new_password != confirm_password:
        flash("Passwords do not match. Please try again.", "error")
        return redirect(url_for('auth.reset_password_page'))

    new_password_hash = hash_password(new_password)

    conn = get_db_connection()
    if conn is None:
        flash("Database connection failed", "error")
        return redirect(url_for('auth.reset_password_page'))

    cursor = conn.cursor()
    try:
        email = forgot_data.get('email')
        update_query = """
            UPDATE Users
            SET password_hash = ?
            WHERE email = ?
        """
        cursor.execute(update_query, (new_password_hash, email))
        conn.commit()

        session.pop('forgot_password_data', None)
        flash("Your password has been reset successfully!", "success")
        return redirect(url_for('home'))

    except Exception as e:
        flash("An error occurred while updating the password.", "error")
        print(f"Reset Password Error: {e}")
        return redirect(url_for('auth.reset_password_page'))
    finally:
        cursor.close()
        conn.close()

@auth_bp.route("/login/google")
def google_login():
    google = oauth.create_client("google")
    return google.authorize_redirect(url_for("auth.google_callback", _external=True))

@auth_bp.route("/callback")
def google_callback():
    try:
        google = oauth.create_client("google")
        token = google.authorize_access_token()
        user_info = google.get("userinfo").json()
        
        local_user_id = create_or_update_google_user(user_info)
        session["user"] = user_info["email"]
        session["user_id"] = local_user_id
        session["is_google_user"] = True
        
        return redirect(url_for("home"))
    except Exception as e:
        flash("Google login failed. Please try again.", "error")
        print(f"Google Login Error: {e}")
        return redirect(url_for("home"))

@auth_bp.route('/logout')
def logout():
    session.pop('user', None)
    flash("You have been logged out.", "info")
    return redirect(url_for('home'))