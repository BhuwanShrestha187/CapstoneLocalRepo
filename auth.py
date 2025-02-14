from flask import Blueprint, request, flash, redirect, url_for, session, jsonify
from authlib.integrations.flask_client import OAuth
import pyodbc
import hashlib 
import os 
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
    return hashlib.sha256(password.encode()).hexdigest()

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
        hashed_password = hashlib.sha256(password.encode()).digest()

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