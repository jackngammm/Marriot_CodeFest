from flask import Flask, render_template, request, session, redirect, url_for
import pandas as pd
from datetime import timedelta
import logging
from logging.handlers import RotatingFileHandler
import re
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
app.secret_key = '1percent'
stored_hashed_password = generate_password_hash("pass", method='pbkdf2:sha256')


# 1. Add Session Management Configuration
app.config['SESSION_COOKIE_SECURE'] = True  # Use HTTPS for cookie transmission (in production)
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to cookies
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Limit cross-site cookie transmission
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)  # Set session timeout to 15 minutes

def sanitize_input(user_input):
    # Allow only alphanumeric characters and spaces
    return re.sub(r'[^\w\s]', '', user_input)


@app.before_request
def make_session_permanent():
    
    session.permanent = True  # Ensure sessions are refreshed on each request

# Placeholder CSRF logging function
@app.before_request
def log_csrf_token():
    csrf_token = session.get('csrf_token')
    if csrf_token:
        app.logger.info(f"CSRF Token (Placeholder): {csrf_token}")
    else:
        app.logger.info("No CSRF Token found (Placeholder).")

# 2. Add Security Headers Implementation
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "img-src 'self' data: https:; "
        "style-src 'self' 'unsafe-inline' https:; "
        "script-src 'self' 'unsafe-inline' https:; "
        "font-src 'self' https: data:;"  # Allow fonts from HTTPS and data URIs
    )
    return response


# Placeholder CSRF logging function
@app.before_request
def log_csrf_token():
    csrf_token = session.get('csrf_token')
    if csrf_token:
        app.logger.info(f"CSRF Token (Placeholder): {csrf_token}")
    else:
        app.logger.info("No CSRF Token found (Placeholder).")

# Set up rotating log files
log_file = 'app.log'
handler = RotatingFileHandler(log_file, maxBytes=10000, backupCount=5)
handler.setLevel(logging.INFO)
app.logger.addHandler(handler)

# Load the dataset
hotel_data = pd.read_csv('marriott_hotels_dataset.csv')

# Home Page
@app.route('/')
def home():
    return render_template('index.html')

# Log in Page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'attempts' not in session:
        session['attempts'] = 0

    if request.method == 'POST':
        login_type = request.form.get('login-type')  # Determine login type

        if session['attempts'] >= 5:
            error = "Too many login attempts. Try again later."
            return render_template('login.html', error=error)

        # Email-based login with hashed password verification
        if login_type == 'email':
            email = sanitize_input(request.form.get('email'))
            password = sanitize_input(request.form.get('password'))

            # Check email and hashed password
            if email == "user@user" and check_password_hash(stored_hashed_password, password):
                session['attempts'] = 0  # Reset attempts on successful login
                app.logger.info(f"Successful login for user: {email}")
                return redirect(url_for('preferences'))
            else:
                session['attempts'] += 1
                error = "Invalid credentials. Please try again."
                return render_template('login.html', error=error)

        # Phone-based login (no hashing needed)
        elif login_type == 'phone':
            phone = sanitize_input(request.form.get('phone'))
            otp = sanitize_input(request.form.get('otp'))

            # Check phone and OTP
            if phone == "123456789" and otp == "123456":
                session['attempts'] = 0  # Reset attempts on successful login
                app.logger.info(f"Successful login for phone: {phone}")
                return redirect(url_for('preferences'))
            else:
                session['attempts'] += 1
                error = "Invalid phone or OTP. Please try again."
                return render_template('login.html', error=error)

    return render_template('login.html')


# Register Page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        registration_type = request.form.get('registration-type')

        if registration_type == 'email':
            username = sanitize_input(request.form.get('username'))
            email = sanitize_input(request.form.get('email'))
            password = sanitize_input(request.form.get('password'))
            app.logger.info(f"New user registration: {email}")

            # Add logic to handle email registration here

        elif registration_type == 'phone':
            phone = sanitize_input(request.form.get('phone'))
            otp = sanitize_input(request.form.get('otp'))
            app.logger.info(f"New user registration: {phone}")

            # Add logic to handle phone registration here

        return redirect(url_for('login'))

    return render_template('register.html')

# Preferences Page
@app.route('/preferences', methods=['GET', 'POST'])
def preferences():
    if request.method == 'POST':
        try:
            location = sanitize_input(request.form['location'])
            min_price = float(request.form['min_price'])
            max_price = float(request.form['max_price'])

            session['preferences'] = {
                'location': location,
                'min_price': min_price,
                'max_price': max_price
            }

            return redirect(url_for('hotels'))
        except Exception as e:
            app.logger.error(f"Error setting preferences: {e}")
            return render_template('preferences.html', error="An error occurred while setting preferences. Please try again.")

    return render_template('preferences.html')

# Hotels Page (Display hotels based on preferences)
@app.route('/hotels')
def hotels():
    preferences = session.get('preferences', {})
    location = preferences.get('location', '')
    min_price = preferences.get('min_price', 0)
    max_price = preferences.get('max_price', float('inf'))

    # Filter hotels based on location and price range
    filtered_hotels = hotel_data[
        (hotel_data['Location'].str.contains(location, case=False, na=False)) &
        (hotel_data['Price_Per_Night'] >= min_price) &
        (hotel_data['Price_Per_Night'] <= max_price)
    ]
    
    hotels_list = filtered_hotels.to_dict(orient='records')
    return render_template('hotels.html', hotels=hotels_list)

# Save Liked Hotels
@app.route('/save_liked_hotels', methods=['POST'])
def save_liked_hotels():
    liked_hotels = request.json.get('liked_hotels', [])
    session['liked_hotels'] = liked_hotels
    return 'Liked hotels saved successfully!'

# Liked Hotels Page
@app.route('/liked_hotels')
def liked_hotels():
    liked_hotel_list = session.get('liked_hotels', [])
    return render_template('liked_hotels.html', liked_hotels=liked_hotel_list)

# Chat Page
@app.route('/chat/<hotel_name>', methods=['GET', 'POST'])
def chat(hotel_name):
    user_message = None
    bot_response = None

    if request.method == 'POST':
        user_message = request.form.get('message')
        bot_response = f"Chatbot response to: {user_message}"

    return render_template('chat.html', hotel_name=hotel_name, user_message=user_message, bot_response=bot_response)

# Logout Route
@app.route('/logout')
def logout():
    user = session.get('user', 'Unknown user')
    session.clear()  # Clears all session data
    app.logger.info(f"User {user} logged out")
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
