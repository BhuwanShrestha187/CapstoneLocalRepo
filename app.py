from flask import Flask, render_template, request, flash, redirect, url_for, send_file, session
import os
import numpy as np
import cv2
from io import BytesIO
from PIL import Image
from auth import auth_bp
from authlib.integrations.flask_client import OAuth
from extensions import oauth  # Import OAuth from extensions.py

#local imports
from laplacian_edge_detector import conv2d  # Import the conv2d function
from greyscale import apply_greyscale

app = Flask(__name__)


'''
======================== Google OAuth Setups ============================
'''

oauth.init_app(app)



# Configure Google OAuth
google = oauth.register(
    name='google',
    client_id='334543306177-3go89o6a71iedphhdahab1mhd86spc1p.apps.googleusercontent.com',
    client_secret='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',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    access_token_url='https://oauth2.googleapis.com/token',
    api_base_url='https://www.googleapis.com/oauth2/v3/',
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs',
    client_kwargs={'scope': 'openid email profile'},
    redirect_uri='http://127.0.0.1:5000/auth/callback'  # Ensure this matches Google Cloud Console
)


'''
======================== Google OAuth Setups until here ============================
'''



@app.route('/')
def home():
    if 'user' in session:
        return render_template("base.html")  # Redirect logged-in users to base.html
    return render_template("login.html")  # Show login page for guests


# Filters for calculating Laplacian
conv_kernel = np.array([[-1, -1, -1, -1, -1], 
                        [-1, -1, -1, -1, -1], 
                        [-1, -1, 24, -1, -1],
                        [-1, -1, -1, -1, -1],
                        [-1, -1, -1, -1, -1]])

# Secret key for flash messages
app.secret_key = os.urandom(24)  # Secret key for session management

# Register authentication routes
app.register_blueprint(auth_bp, url_prefix="/auth")

# Configure upload folder and allowed file extensions
UPLOAD_FOLDER = 'uploads'
PROCESSED_FOLDER = 'processed'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['PROCESSED_FOLDER'] = PROCESSED_FOLDER

# Helper function to check file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS



@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(url_for('home'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('home'))
    
    if file and allowed_file(file.filename):
        # Save the uploaded file
        filename = file.filename
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # Process the uploaded image
        image = cv2.imread(file_path, cv2.IMREAD_GRAYSCALE)
        if image is None:
            flash('Invalid image format')
            return redirect(url_for('home'))

        processed_image = conv2d(image, conv_kernel)

        # Normalize and save the processed image
        processed_image = (processed_image - np.min(processed_image)) / (np.max(processed_image) - np.min(processed_image)) * 255
        processed_image = processed_image.astype(np.uint8)
        processed_pil = Image.fromarray(processed_image)

        processed_filename = f"processed_{filename}"
        processed_path = os.path.join(app.config['PROCESSED_FOLDER'], processed_filename)
        processed_pil.save(processed_path)

        greyscale_filename = f"greyscale_{filename}"
        greyscale_path = os.path.join(app.config['PROCESSED_FOLDER'], greyscale_filename)
        greyscale_pil = Image.fromarray(image)
        greyscale_pil.save(greyscale_path)

        # Display success message and provide download link
        #flash('File successfully uploaded and processed!')

        
        return redirect(url_for('compare_images', filename=filename))
    
    flash('Allowed file types are: png, jpg, jpeg')
    return redirect(url_for('home'))

@app.route('/original/<filename>')
def original_file(filename):
    upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    return send_file(upload_path, mimetype='image/jpeg', as_attachment=False)

@app.route('/processed/<filename>')
def processed_file(filename):
    processed_path = os.path.join(app.config['PROCESSED_FOLDER'], filename)
    return send_file(processed_path, mimetype='image/jpeg', as_attachment=False)

@app.route('/compare/<filename>')
def compare_images(filename):
    original_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    processed_filename = f"processed_{filename}"
    processed_path = os.path.join(app.config['PROCESSED_FOLDER'], processed_filename)
    greyscale_filename=f"greyscale_{filename}"
    greyscale_path = os.path.join(app.config['PROCESSED_FOLDER'], greyscale_filename)
    
    # Verify files exist before rendering
    if not os.path.exists(original_path):
        print(f"Original file not found: {original_path}")
        flash('Original image not found')
        return redirect(url_for('home'))
    
    if not os.path.exists(processed_path):
        print(f"Processed file not found: {processed_path}")
        flash('Processed image not found')
        return redirect(url_for('home'))
    
    return render_template('comparison.html', 
                           original_filename=filename, 
                           processed_filename=processed_filename,
                           greyscale_filename=greyscale_filename)
    
    




app.jinja_env.auto_reload = True
app.config["TEMPLATES_AUTO_RELOAD"] = True


if __name__ == '__main__':
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    os.makedirs(PROCESSED_FOLDER, exist_ok=True)
    app.run(debug=True)
