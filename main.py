from flask import Flask, render_template, request, session, redirect, url_for
import pandas as pd

app = Flask(__name__)
app.secret_key = '1percent'

# Load the dataset
hotel_data = pd.read_csv('marriott_hotels_dataset.csv')

# Home Page
@app.route('/')
def home():
    return render_template('index.html')


#Log in Page

# Preferences Page
@app.route('/preferences', methods=['GET', 'POST'])
def preferences():
    if request.method == 'POST':
        location = request.form['location']
        min_price = float(request.form['min_price'])
        max_price = float(request.form['max_price'])
        
        # Store preferences in session for access across routes
        session['preferences'] = {
            'location': location,
            'min_price': min_price,
            'max_price': max_price
        }
        return redirect(url_for('hotels'))
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



if __name__ == '__main__':
    app.run(debug=True)
