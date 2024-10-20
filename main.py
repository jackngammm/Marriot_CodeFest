from flask import Flask, render_template, request, session, redirect, url_for
import pandas as pd
import re
from flask import Flask, session, redirect, url_for, make_response
from datetime import timedelta
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, request, session, redirect, url_for


app = Flask(__name__)
app.secret_key = '1percent'

# 1. Add Session Management Configuration
app.config['SESSION_COOKIE_SECURE'] = True  # Use HTTPS for cookie transmission (in production)
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to cookies
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Limit cross-site cookie transmission
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)  # Set session timeout to 15 minutes

@app.before_request
def make_session_permanent():
    session.permanent = True  # Ensure sessions are refreshed on each request

# Your existing routes and logic here...

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


#Log in Page

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Check if both username and password are in the form data
        email = request.form.get('email')  # Use .get() to avoid KeyError
        password = request.form.get('password')
        
        # Basic authentication check (replace this with your own logic)
        if email == "user@user" and password == "pass":
            #session['user'] = email  # Store user email in session
            app.logger.info(f"Successful login for user: {email}")

            return redirect(url_for('preferences'))
        else:
            app.logger.warning(f"Failed login attempt for email: {email}")

            return render_template('login.html', error="Invalid credentials. Please try again.")
    
    # For GET requests, simply render the login page
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if request.form.get('registration-type') == 'email':
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')    
            app.logger.info(f"New user registration: {email}")

            # Add your logic to handle email registration here
        elif request.form.get('registration-type') == 'phone':
            phone = request.form.get('phone')
            otp = request.form.get('otp')
            app.logger.info(f"New user registration: {phone}")

            # Add your logic to handle phone registration here

        # Redirect or render appropriate response based on registration logic
        return redirect(url_for('login'))  # Change this based on your logic

    return render_template('register.html')

@app.route('/registration_success')
def registration_success():
    return "Registration successful! You can now log in."  # Placeholder message

# Preferences Page
@app.route('/preferences', methods=['GET', 'POST'])

@app.route('/preferences', methods=['GET', 'POST'])
def preferences():
    if request.method == 'POST':
        try:
            location = request.form['location']
            min_price = float(request.form['min_price'])
            max_price = float(request.form['max_price'])

            # Store preferences in session for access across routes
            session['preferences'] = {
                'location': location,
                'min_price': min_price,
                'max_price': max_price
            }

            # Log successful preference setting
            app.logger.info(f"Preferences set: Location - {location}, "
                            f"Min Price - {min_price}, Max Price - {max_price}, "
                            f"User IP - {request.remote_addr}")

            return redirect(url_for('hotels'))

        except Exception as e:
            # Log any errors during setting preferences
            app.logger.error(f"Error setting preferences: {e}, User IP - {request.remote_addr}")
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

#This is the saved page

@app.route('/save_liked_hotels', methods=['POST'])
def save_liked_hotels():
    liked_hotels = request.json.get('liked_hotels', [])
    session['liked_hotels'] = liked_hotels
    return 'Liked hotels saved successfully!'




@app.route('/liked_hotels')
def liked_hotels():
    liked_hotel_list = session.get('liked_hotels', [])
    return render_template('liked_hotels.html', liked_hotels=liked_hotel_list)




@app.route('/chat/<hotel_name>', methods=['GET', 'POST'])
def chat(hotel_name):
    user_message = None
    bot_response = None

    if request.method == 'POST':
        user_message = request.form.get('message')
        bot_response = f"Chatbot response to: {user_message}"  # Placeholder response logic

    return render_template('chat.html', hotel_name=hotel_name, user_message=user_message, bot_response=bot_response)


@app.route('/logout')
def logout():
    user = session.get('user', 'Unknown user')
    session.clear()  # Clears all session data
    app.logger.info(f"User {user} logged out")
    return redirect(url_for('home'))  # Replace 'home' with your homepage route


if __name__ == '__main__':
    app.run(debug=True)