import os
import base64
import requests
import sqlite3
import uuid
import hashlib
from datetime import datetime
from dotenv import load_dotenv
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
import io
from PIL import Image
import stripe

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "your-secret-key")  # Change in production

# Get API keys from environment variables
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")
STRIPE_PUBLISHABLE_KEY = os.getenv("STRIPE_PUBLISHABLE_KEY")

# Configure Stripe
stripe.api_key = STRIPE_SECRET_KEY

# Database setup
def get_db_connection():
    conn = sqlite3.connect('ghibli_app.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        image_count INTEGER DEFAULT 0,
        paid BOOLEAN DEFAULT FALSE,
        stripe_customer_id TEXT
    )
    ''')
    
    # Create transformations table to track image transformations
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS transformations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    # Create payments table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS payments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        amount REAL NOT NULL,
        payment_id TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    conn.commit()
    conn.close()

# Initialize the database
init_db()

# Authentication functions
def hash_password(password):
    # Simple password hashing - in production, use a proper password hashing library
    return hashlib.sha256(password.encode()).hexdigest()

def check_auth():
    if 'user_id' not in session:
        return False
    return True

# App routes
@app.route('/')
def index():
    if check_auth():
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not email or not password:
            flash('Email and password are required')
            return render_template('signup.html')
            
        if password != confirm_password:
            flash('Passwords do not match')
            return render_template('signup.html')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if user already exists
        cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
        if cursor.fetchone():
            conn.close()
            flash('Email already registered')
            return render_template('signup.html')
        
        # Create Stripe customer
        try:
            customer = stripe.Customer.create(email=email)
            stripe_customer_id = customer.id
        except Exception as e:
            stripe_customer_id = None
            print(f"Error creating Stripe customer: {str(e)}")
        
        # Create user
        hashed_password = hash_password(password)
        cursor.execute(
            'INSERT INTO users (email, password, stripe_customer_id) VALUES (?, ?, ?)',
            (email, hashed_password, stripe_customer_id)
        )
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        # Log user in
        session['user_id'] = user_id
        session['email'] = email
        
        return redirect(url_for('dashboard'))
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not email or not password:
            flash('Email and password are required')
            return render_template('login.html')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT id, password FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        conn.close()
        
        if user and user['password'] == hash_password(password):
            session['user_id'] = user['id']
            session['email'] = email
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password')
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if not check_auth():
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT image_count, paid FROM users WHERE id = ?', (session['user_id'],))
    user = cursor.fetchone()
    conn.close()
    
    free_images_left = max(0, 5 - user['image_count'] % 5) if not user['paid'] else "Unlimited"
    need_payment = user['image_count'] >= 5 and not user['paid'] and user['image_count'] % 5 == 0
    
    return render_template(
        'dashboard.html', 
        email=session['email'], 
        image_count=user['image_count'],
        free_images_left=free_images_left,
        need_payment=need_payment,
        stripe_key=STRIPE_PUBLISHABLE_KEY
    )

@app.route('/transform', methods=['POST'])
def transform_image():
    if not check_auth():
        return jsonify({'error': 'Authentication required'}), 401
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get user data
    cursor.execute('SELECT image_count, paid FROM users WHERE id = ?', (session['user_id'],))
    user = cursor.fetchone()
    
    # Check if payment is required
    if user['image_count'] >= 5 and not user['paid'] and user['image_count'] % 5 == 0:
        conn.close()
        return jsonify({'error': 'Payment required', 'need_payment': True}), 402
    
    if 'image' not in request.files:
        conn.close()
        return jsonify({'error': 'No image uploaded'}), 400
    
    file = request.files['image']
    
    # Read and encode the image to base64
    image_data = file.read()
    
    # Optional: resize image if it's too large
    try:
        img = Image.open(io.BytesIO(image_data))
        if max(img.size) > 1024:
            img.thumbnail((1024, 1024), Image.Resampling.LANCZOS)
            buffer = io.BytesIO()
            img.save(buffer, format="JPEG")
            image_data = buffer.getvalue()
    except Exception as e:
        conn.close()
        return jsonify({'error': f'Error processing image: {str(e)}'}), 400
    
    # Encode the image to base64
    base64_image = base64.b64encode(image_data).decode('utf-8')
    
    # Call OpenAI API to transform the image
    try:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {OPENAI_API_KEY}"
        }
        
        payload = {
            "model": "dall-e-3",
            "prompt": "Transform this photograph into a Studio Ghibli animation style. Maintain the subject and composition but apply the iconic Ghibli aesthetic with soft colors, painterly details, and whimsical atmosphere.",
            "n": 1,
            "size": "1024x1024",
            "image": base64_image
        }
        
        response = requests.post(
            "https://api.openai.com/v1/images/generations",
            headers=headers,
            json=payload
        )
        
        if response.status_code == 200:
            result = response.json()
            transformed_image_url = result["data"][0]["url"]
            
            # Update user's image count
            cursor.execute('UPDATE users SET image_count = image_count + 1 WHERE id = ?', (session['user_id'],))
            
            # Log the transformation
            cursor.execute('INSERT INTO transformations (user_id) VALUES (?)', (session['user_id'],))
            
            conn.commit()
            conn.close()
            
            return jsonify({'transformed_image': transformed_image_url})
        else:
            conn.close()
            return jsonify({'error': f'API Error: {response.text}'}), 500
    
    except Exception as e:
        conn.close()
        return jsonify({'error': f'Error calling OpenAI API: {str(e)}'}), 500

@app.route('/create-payment-intent', methods=['POST'])
def create_payment():
    if not check_auth():
        return jsonify({'error': 'Authentication required'}), 401
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get user's Stripe customer ID
        cursor.execute('SELECT stripe_customer_id FROM users WHERE id = ?', (session['user_id'],))
        user = cursor.fetchone()
        
        # Create a PaymentIntent with the order amount and currency
        intent = stripe.PaymentIntent.create(
            amount=100,  # $1.00 in cents
            currency='usd',
            customer=user['stripe_customer_id'] if user['stripe_customer_id'] else None,
            metadata={
                'user_id': session['user_id']
            }
        )
        
        conn.close()
        
        return jsonify({
            'clientSecret': intent.client_secret
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/payment-success', methods=['POST'])
def payment_success():
    if not check_auth():
        return jsonify({'error': 'Authentication required'}), 401
    
    data = request.json
    payment_intent_id = data.get('paymentIntentId')
    
    if not payment_intent_id:
        return jsonify({'error': 'Payment intent ID is required'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Verify the payment with Stripe
        payment_intent = stripe.PaymentIntent.retrieve(payment_intent_id)
        
        if payment_intent.status == 'succeeded':
            # Record the payment
            cursor.execute(
                'INSERT INTO payments (user_id, amount, payment_id) VALUES (?, ?, ?)',
                (session['user_id'], payment_intent.amount / 100, payment_intent_id)
            )
            
            # Update the user's paid status
            cursor.execute('UPDATE users SET paid = TRUE WHERE id = ?', (session['user_id'],))
            
            conn.commit()
            conn.close()
            
            return jsonify({'success': True})
        else:
            conn.close()
            return jsonify({'error': 'Payment has not succeeded'}), 400
    
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 500

@app.route('/history')
def history():
    if not check_auth():
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT t.created_at 
        FROM transformations t 
        WHERE t.user_id = ? 
        ORDER BY t.created_at DESC
    ''', (session['user_id'],))
    
    transformations = cursor.fetchall()
    
    cursor.execute('''
        SELECT p.amount, p.created_at 
        FROM payments p 
        WHERE p.user_id = ? 
        ORDER BY p.created_at DESC
    ''', (session['user_id'],))
    
    payments = cursor.fetchall()
    
    conn.close()
    
    return render_template('history.html', transformations=transformations, payments=payments)

if __name__ == '__main__':
    # Check if API keys are available
    if not OPENAI_API_KEY:
        print("Warning: OPENAI_API_KEY not found in environment variables")
    if not STRIPE_SECRET_KEY:
        print("Warning: STRIPE_SECRET_KEY not found in environment variables")
    
    app.run(debug=True)