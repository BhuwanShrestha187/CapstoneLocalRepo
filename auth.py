from flask import Blueprint, request, flash, redirect, url_for, session, jsonify
import pyodbc
import hashlib 
import os 

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

@auth_bp.route('/login', methods=['POST'])
def login():
    """ Handles user login authentication """
    email = request.form.get('email')
    password = request.form.get('password')

    if not email or not password:
        flash("Email and Password are required", "error")
        return redirect(url_for('home'))

    conn = get_db_connection()
    if conn is None:
        flash("Database connection failed", "error")
        return redirect(url_for('home'))

    cursor = conn.cursor()
    
    try:
        hashed_password = hashlib.sha256(password.encode()).digest()  # Use digest() for binary format
        query = "SELECT email FROM Users WHERE email = ? AND password_hash = ?"
        cursor.execute(query, (email, hashed_password))

        user = cursor.fetchone()
        
        if user:
            session['user'] = email  # Store user session
            flash("Login successful!", "success")
            return redirect(url_for('home'))  # Redirect to base.html
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
        

@auth_bp.route('/logout')
def logout():
    """ Logs out the user and redirects to login page """
    session.pop('user', None)
    flash("You have been logged out.", "info")
    return redirect(url_for('home'))