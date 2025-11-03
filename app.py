#!/usr/bin/env python3
"""
Food Carve - Consolidated Single File Application
All functionality combined into one file for simplicity
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash, after_this_request
from flask_cors import CORS
from functools import wraps
import os
import re
import random
import json
import hmac
import hashlib
from pymongo import MongoClient
from bson.objectid import ObjectId
from datetime import datetime
import bcrypt
from typing import List, Dict, Any, Callable

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your-secret-key-here')

# Security headers
@app.after_request
def after_request(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# Enable CORS for all routes
CORS(app)

# ==================== MODELS ====================
class User:
    """User model for the application"""
    
    def __init__(self, username: str, email: str, password: str, role: str = 'customer'):
        self.username = username
        self.email = email
        self.password = password
        self.role = role
        self.created_at = datetime.now()
        self.is_active = True
        self.last_login = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert user to dictionary"""
        return {
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'created_at': self.created_at.isoformat(),
            'is_active': self.is_active,
            'last_login': self.last_login.isoformat() if self.last_login else None
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'User':
        """Create user from dictionary"""
        user = cls(
            username=data['username'],
            email=data['email'],
            password=data['password'],
            role=data.get('role', 'customer')
        )
        user.created_at = datetime.fromisoformat(data['created_at'])
        user.is_active = data.get('is_active', True)
        if data.get('last_login'):
            user.last_login = datetime.fromisoformat(data['last_login'])
        return user

# ==================== UTILS ====================
def calculate_cart_total(cart_items: List[Dict[str, Any]]) -> Dict[str, float]:
    """
    Calculate cart totals including subtotal, tax, delivery fee, and total
    """
    subtotal = sum(item['price'] * item['quantity'] for item in cart_items)
    delivery_fee = subtotal * 0.1  # 10% delivery fee
    tax = subtotal * 0.08  # 8% tax
    total = subtotal + delivery_fee + tax
    
    return {
        'subtotal': round(subtotal, 2),
        'delivery_fee': round(delivery_fee, 2),
        'tax': round(tax, 2),
        'total': round(total, 2)
    }

def calculate_order_total(items: List[Dict[str, Any]], 
                         delivery_fee_rate: float = 0.1, 
                         tax_rate: float = 0.08) -> Dict[str, float]:
    """
    Calculate order total with customizable rates
    """
    subtotal = sum(item['price'] * item['quantity'] for item in items)
    delivery_fee = subtotal * delivery_fee_rate
    tax = subtotal * tax_rate
    total = subtotal + delivery_fee + tax
    
    return {
        'subtotal': round(subtotal, 2),
        'delivery_fee': round(delivery_fee, 2),
        'tax': round(tax, 2),
        'total': round(total, 2)
    }

def format_currency(amount: float, currency: str = "INR") -> str:
    """Format currency amount"""
    if currency == "INR":
        return f"₹{amount:,.2f}"
    elif currency == "USD":
        return f"${amount:,.2f}"
    else:
        return f"{amount:,.2f} {currency}"

def validate_password(password: str) -> tuple[bool, str]:
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r"\d", password):
        return False, "Password must contain at least one digit"
    
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character"
    
    return True, "Password is valid"

def validate_email(email: str) -> bool:
    """Validate email format"""
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, email) is not None

# ==================== SERVICES ====================
class PaymentService:
    """Payment service for handling transactions"""
    
    def __init__(self):
        self.key_id = os.getenv('RAZORPAY_KEY_ID', 'rzp_test_R8SjqiBx6bgTHd')
        self.key_secret = os.getenv('RAZORPAY_KEY_SECRET', 'yBxGwBq2QP4X6rMpXLwX3b6Y')
    
    def create_order(self, amount: float, currency: str = 'INR') -> dict:
        """Create a payment order"""
        # In a real implementation, this would integrate with Razorpay API
        return {
            'order_id': f"order_{random.randint(100000, 999999)}",
            'amount': int(amount * 100),  # Convert to paise
            'currency': currency
        }
    
    def verify_payment(self, payment_id: str, order_id: str, signature: str) -> bool:
        """Verify payment signature"""
        # In a real implementation, this would verify with Razorpay
        expected_signature = hmac.new(
            self.key_secret.encode(),
            f"{order_id}|{payment_id}".encode(),
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(signature, expected_signature)

class EmailService:
    """Email service for sending notifications"""
    
    def __init__(self):
        self.smtp_server = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
        self.smtp_port = int(os.getenv('SMTP_PORT', '587'))
        self.username = os.getenv('EMAIL_USERNAME', '')
        self.password = os.getenv('EMAIL_PASSWORD', '')
    
    def send_welcome_email(self, email: str, username: str):
        """Send welcome email to new user"""
        # In a real implementation, this would send an actual email
        print(f"Welcome email sent to {email} for user {username}")
    
    def send_order_confirmation(self, email: str, order_id: str):
        """Send order confirmation email"""
        # In a real implementation, this would send an actual email
        print(f"Order confirmation sent to {email} for order {order_id}")

# ==================== DATABASE ====================
# MongoDB Configuration
try:
    mongo_uri = os.getenv('MONGODB_URI', 'mongodb://localhost:27017/')
    mongo_client = MongoClient(
        mongo_uri,
        serverSelectionTimeoutMS=5000,
        connectTimeoutMS=5000,
        socketTimeoutMS=5000
    )
    db_name = os.getenv('MONGODB_DATABASE', 'cravebite')
    db = mongo_client[db_name]
    users_collection = db['users']
    orders_collection = db['orders']
    menu_collection = db['menu']
    
    # Test the connection
    mongo_client.admin.command('ping')
    print("MongoDB connected successfully")
except Exception as e:
    print(f"MongoDB connection failed: {e}")
    mongo_client = None

# ==================== DATA ====================
# Sample menu data
menu_data = [
    {
        'id': 1,
        'name': 'Margherita Pizza',
        'description': 'Classic pizza with tomato sauce, mozzarella, and fresh basil',
        'price': 1078.17,
        'category': 'Main Course',
        'image': 'pizza.jpg'
    },
    {
        'id': 2,
        'name': 'Caesar Salad',
        'description': 'Fresh romaine lettuce with Caesar dressing, croutons, and parmesan',
        'price': 746.17,
        'category': 'Appetizer',
        'image': 'salad.jpg'
    },
    {
        'id': 3,
        'name': 'Chocolate Cake',
        'description': 'Rich chocolate cake with ganache and fresh berries',
        'price': 580.17,
        'category': 'Dessert',
        'image': 'cake.jpg'
    },
    {
        'id': 4,
        'name': 'Grilled Salmon',
        'description': 'Fresh salmon fillet with lemon butter sauce and seasonal vegetables',
        'price': 1327.17,
        'category': 'Main Course',
        'image': 'salmon.jpg'
    },
    {
        'id': 5,
        'name': 'Garlic Bread',
        'description': 'Toasted bread with garlic butter and herbs',
        'price': 414.17,
        'category': 'Appetizer',
        'image': 'bread.jpg'
    },
    {
        'id': 6,
        'name': 'Tiramisu',
        'description': 'Classic Italian coffee-flavored dessert with mascarpone',
        'price': 663.17,
        'category': 'Dessert',
        'image': 'tiramisu.jpg'
    },
    {
        'id': 7,
        'name': 'Beef Burger',
        'description': 'Juicy beef patty with lettuce, tomato, onion, and special sauce',
        'price': 995.17,
        'category': 'Main Course',
        'image': 'burger.jpg'
    },
    {
        'id': 8,
        'name': 'Fruit Smoothie',
        'description': 'Refreshing blend of seasonal fruits and yogurt',
        'price': 497.17,
        'category': 'Beverage',
        'image': 'smoothie.jpg'
    }
]

# Sample restaurant data
sample_restaurants = [
    {
        'id': 1,
        'name': "Taste of India",
        'cuisine': "Indian",
        'rating': 4.7,
        'deliveryTime': "25-35 min",
        'image': "https://images.unsplash.com/photo-1585853340472-1bf780c78a2d?ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D&auto=format&fit=crop&w=800&q=80",
        'description': "Authentic Indian cuisine with traditional spices and flavors",
        'location': "Downtown",
        'coordinates': {'lat': 40.7128, 'lng': -74.0060}
    },
    {
        'id': 2,
        'name': "Mamma Mia Italian",
        'cuisine': "Italian",
        'rating': 4.5,
        'deliveryTime': "30-40 min",
        'image': "https://images.unsplash.com/photo-1574071318508-1cdbab80d002?ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D&auto=format&fit=crop&w=800&q=80",
        'description': "Handcrafted pasta and wood-fired pizzas",
        'location': "Midtown",
        'coordinates': {'lat': 40.7589, 'lng': -73.9851}
    }
]

# ==================== AUTHENTICATION ====================
def get_user(username: str):
    """Get user by username from MongoDB"""
    if mongo_client is None:
        # Fallback to in-memory storage with static password hashes
        users = {
            'admin': {
                'username': 'admin',
                'email': 'admin@foodcarve.com',
                'password': b'$2b$12$80f4Ju.z6wQibJvY0F755OeS8xX5ZjdGhTd7vd7OSZ4LTOB74nHoAm',  # Admin123!
                'role': 'admin'
            },
            'owner': {
                'username': 'owner',
                'email': 'owner@foodcarve.com',
                'password': b'$2b$12$pDkoQzTMvljhXJBjpzGVVPO7pmELvKt9nJwbadAnIiuvzXNTgV18cK',  # Owner123!
                'role': 'owner'
            },
            'delivery': {
                'username': 'delivery',
                'email': 'delivery@foodcarve.com',
                'password': b'$2b$12$NvI2BANTjk1lGD3IqqPFC8O6aopXULqMPc/t9KHTn1RDdMtUd2a3Ry',  # Delivery123!
                'role': 'delivery'
            }
        }
        return users.get(username)
    
    try:
        user = users_collection.find_one({'username': username})
        if user:
            user['_id'] = str(user['_id'])
        return user
    except Exception as e:
        print(f"Error fetching user: {e}")
        return None

def create_user(username: str, email: str, password: str, role: str = 'customer'):
    """Create a new user in MongoDB"""
    if mongo_client is None:
        print("MongoDB not available, cannot create user")
        return False
    
    # Input validation
    if not username or not email or not password:
        print("Missing required fields for user creation")
        return False
    
    if not validate_email(email):
        print("Invalid email format")
        return False
    
    try:
        print(f"Checking if user {username} already exists")
        # Check if user already exists
        existing_user = users_collection.find_one({'username': username}, {'_id': 1})
        if existing_user:
            print(f"User {username} already exists")
            return False
        
        print(f"Checking if email {email} already exists")
        # Check if email already exists
        existing_email = users_collection.find_one({'email': email}, {'_id': 1})
        if existing_email:
            print(f"Email {email} already exists")
            return False
        
        print(f"Hashing password for user {username}")
        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        user_data = {
            'username': username,
            'email': email,
            'password': hashed_password,
            'role': role,
            'created_at': datetime.now(),
            'updated_at': datetime.now()
        }
        
        print(f"Inserting user {username} into database")
        print(f"User data: {user_data}")
        result = users_collection.insert_one(user_data)
        print(f"Insert result: {result.inserted_id}")
        
        # Verify the user was inserted
        if result.inserted_id:
            print(f"User {username} created successfully with ID: {result.inserted_id}")
            # Try to find the user to confirm insertion
            inserted_user = users_collection.find_one({'_id': result.inserted_id})
            if inserted_user:
                print(f"Verified user insertion: {inserted_user['username']}")
            else:
                print("Failed to verify user insertion")
        else:
            print("Failed to insert user")
            
        return result.inserted_id is not None
    except Exception as e:
        print(f"Error creating user: {e}")
        import traceback
        traceback.print_exc()
        return False

# ==================== DECORATORS ====================
def require_role(role: str):
    """Decorator to require specific role"""
    def decorator(f: Callable):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'username' not in session:
                return redirect(url_for('login'))
            if session.get('role') != role:
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ==================== ROUTES ====================
@app.route('/')
def index():
    """Home page"""
    return render_template('index.html')

@app.route('/menu')
def menu():
    """Menu page"""
    return render_template('menu.html', menu_items=menu_data)

@app.route('/api/menu')
def api_menu():
    """API endpoint for menu data"""
    return jsonify(menu_data)

@app.route('/cart')
def cart():
    """Cart page"""
    cart_items = session.get('cart', [])
    totals = calculate_cart_total(cart_items)
    return render_template('cart.html', cart_items=cart_items, totals=totals)

@app.route('/add_to_cart', methods=['POST'])
def add_to_cart():
    """Add item to cart"""
    item_id = int(request.form['item_id'])
    quantity = int(request.form.get('quantity', 1))
    
    # Find the item in menu data
    item = next((item for item in menu_data if item['id'] == item_id), None)
    
    if item:
        # Get current cart from session
        cart = session.get('cart', [])
        
        # Check if item is already in cart
        existing_item = next((cart_item for cart_item in cart if cart_item['id'] == item_id), None)
        
        if existing_item:
            existing_item['quantity'] += quantity
        else:
            cart.append({
                'id': item['id'],
                'name': item['name'],
                'price': item['price'],
                'quantity': quantity,
                'image': item['image']
            })
        
        # Save cart to session
        session['cart'] = cart
        session.modified = True
    
    return redirect(url_for('menu'))

@app.route('/update_cart', methods=['POST'])
def update_cart():
    """Update cart item quantity"""
    item_id = int(request.form['item_id'])
    quantity = int(request.form['quantity'])
    
    # Get current cart from session
    cart = session.get('cart', [])
    
    # Find the item in cart
    for item in cart:
        if item['id'] == item_id:
            if quantity <= 0:
                # Remove item if quantity is 0 or less
                cart = [cart_item for cart_item in cart if cart_item['id'] != item_id]
            else:
                # Update quantity
                item['quantity'] = quantity
            break
    
    # Save cart to session
    session['cart'] = cart
    session.modified = True
    
    return redirect(url_for('cart'))

@app.route('/clear_cart')
def clear_cart():
    """Clear all items from cart"""
    session['cart'] = []
    session.modified = True
    return redirect(url_for('cart'))

@app.route('/api/cart_count')
def cart_count():
    """API endpoint for cart count"""
    cart = session.get('cart', [])
    count = sum(item['quantity'] for item in cart)
    return jsonify({'count': count})

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'POST':
        # Use .get() method to avoid KeyError if fields are missing
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Log the received data for debugging
        print(f"Login attempt - Username: {username}, Password provided: {password is not None}")
        
        # Check if required fields are provided
        if not username or not password:
            print("Missing username or password")
            return render_template('login.html', error="Please provide both username and password")
        
        # Check if user exists and password matches
        user_data = get_user(username)
        
        if user_data:
            print(f"User found: {username}, Role: {user_data['role']}")
            # Check if password is bytes or string
            if isinstance(user_data['password'], str):
                stored_password = user_data['password'].encode('utf-8')
            else:
                stored_password = user_data['password']
                
            print(f"Stored password type: {type(stored_password)}")
            print(f"Provided password: {password}")
            
            if bcrypt.checkpw(password.encode('utf-8'), stored_password):
                # Set session and redirect to home
                session['username'] = username
                session['role'] = user_data['role']
                print(f"Login successful for user: {username}")
                
                # Redirect to appropriate dashboard based on role
                if user_data['role'] == 'admin':
                    print("Redirecting to admin dashboard")
                    return redirect(url_for('admin_dashboard'))
                elif user_data['role'] == 'owner':
                    print("Redirecting to owner dashboard")
                    return redirect(url_for('owner_dashboard'))
                elif user_data['role'] == 'delivery':
                    print("Redirecting to delivery dashboard")
                    return redirect(url_for('delivery_dashboard'))
                else:
                    print("Redirecting to index")
                    return redirect(url_for('index'))
            else:
                print("Invalid password")
                return render_template('login.html', error="Invalid username or password")
        else:
            print("User not found")
            return render_template('login.html', error="Invalid username or password")
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """User registration - DEBUG VERSION"""
    print("=== SIGNUP ROUTE ACCESSED ===")
    print(f"Request method: {request.method}")
    print(f"Request URL: {request.url}")
    print(f"Request headers: {dict(request.headers)}")
    
    if request.method == 'POST':
        print("=== PROCESSING POST REQUEST ===")
        
        # Log raw form data
        print("Raw form data:")
        for key in request.form:
            print(f"  {key}: {request.form[key]}")
        
        # Get form data
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        role = request.form.get('role', 'customer')
        
        print(f"Extracted data - Username: '{username}', Email: '{email}', Role: '{role}'")
        print(f"Password length: {len(password)}")
        print(f"Confirm password length: {len(confirm_password)}")
        
        # Basic validation
        if not username or not email or not password or not confirm_password:
            print("ERROR: Missing required fields")
            return render_template('signup.html', error="All fields are required")
        
        if password != confirm_password:
            print("ERROR: Passwords don't match")
            return render_template('signup.html', error="Passwords do not match")
        
        # Validate email format
        if not validate_email(email):
            print("ERROR: Invalid email format")
            return render_template('signup.html', error="Please enter a valid email address")
        
        # Validate role
        valid_roles = ['customer', 'owner', 'delivery']
        if role not in valid_roles:
            print("ERROR: Invalid role")
            return render_template('signup.html', error="Please select a valid role")
        
        # Check if MongoDB is available
        if mongo_client is None:
            print("ERROR: MongoDB not available")
            return render_template('signup.html', error="Database connection error. Please try again later.")
        
        try:
            # Check if username already exists
            print("Checking if username exists...")
            existing_user = users_collection.find_one({'username': username})
            if existing_user:
                print("ERROR: Username already exists")
                return render_template('signup.html', error="Username already exists. Please choose a different username.")
            
            # Check if email already exists
            print("Checking if email exists...")
            existing_email = users_collection.find_one({'email': email})
            if existing_email:
                print("ERROR: Email already exists")
                return render_template('signup.html', error="Email already exists. Please use a different email address.")
            
            # Hash password
            print("Hashing password...")
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            
            # Create user document
            user_data = {
                'username': username,
                'email': email,
                'password': hashed_password,
                'role': role,
                'created_at': datetime.now(),
                'updated_at': datetime.now()
            }
            
            print(f"User data to insert: {user_data}")
            
            # Insert user into database
            print("Inserting user into database...")
            result = users_collection.insert_one(user_data)
            print(f"Insert result ID: {result.inserted_id}")
            
            if result.inserted_id:
                print("SUCCESS: User created successfully")
                # Set session
                session['username'] = username
                session['role'] = role
                print(f"Session set for user: {username} with role: {role}")
                print(f"Session data: {dict(session)}")
                
                # Test redirect - let's see what happens
                print("Attempting redirect...")
                if role == 'admin':
                    print("Redirecting to admin dashboard")
                    response = redirect(url_for('admin_dashboard'))
                    print(f"Redirect response: {response}")
                    return response
                elif role == 'owner':
                    print("Redirecting to owner dashboard")
                    response = redirect(url_for('owner_dashboard'))
                    print(f"Redirect response: {response}")
                    return response
                elif role == 'delivery':
                    print("Redirecting to delivery dashboard")
                    response = redirect(url_for('delivery_dashboard'))
                    print(f"Redirect response: {response}")
                    return response
                else:
                    print("Redirecting to home page")
                    response = redirect(url_for('index'))
                    print(f"Redirect response: {response}")
                    return response
            else:
                print("ERROR: Failed to insert user")
                return render_template('signup.html', error="Failed to create account. Please try again.")
                
        except Exception as e:
            print(f"ERROR: Exception during user creation: {e}")
            import traceback
            traceback.print_exc()
            return render_template('signup.html', error="An unexpected error occurred. Please try again.")
    
    print("Rendering signup form (GET request)")
    return render_template('signup.html')

@app.route('/logout')
def logout():
    """User logout"""
    session.pop('username', None)
    session.pop('role', None)
    session.pop('cart', None)
    return redirect(url_for('index'))

@app.route('/admin/dashboard')
@require_role('admin')
def admin_dashboard():
    return render_template('admin/dashboard.html')

@app.route('/admin/users')
@require_role('admin')
def admin_users():
    # Get all users from MongoDB
    if mongo_client is None:
        # Fallback to in-memory storage
        users = [
            {'username': 'admin', 'email': 'admin@foodcarve.com', 'role': 'admin'},
            {'username': 'owner', 'email': 'owner@foodcarve.com', 'role': 'owner'},
            {'username': 'delivery', 'email': 'delivery@foodcarve.com', 'role': 'delivery'}
        ]
    else:
        # Get users from MongoDB
        users = list(users_collection.find({}, {'password': 0}))  # Exclude password field
        # Convert ObjectId to string for JSON serialization
        for user in users:
            user['_id'] = str(user['_id'])
    
    return render_template('admin/users.html', users=users)

@app.route('/admin/add_user', methods=['GET', 'POST'])
@require_role('admin')
def admin_add_user():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        
        print(f"Attempting to create user: {username}, {email}, {role}")
        
        # Validate and create user
        if create_user(username, email, password, role):
            print(f"User {username} created successfully!")
            flash('User created successfully!', 'success')
            return redirect(url_for('admin_users'))
        else:
            print(f"Error creating user {username}")
            flash('Error creating user. Username or email may already exist.', 'error')
    
    return render_template('admin/add_user.html')

@app.route('/admin/edit_user/<user_id>', methods=['GET', 'POST'])
@require_role('admin')
def admin_edit_user(user_id):
    if mongo_client is None:
        flash('User editing not available in demo mode.', 'error')
        return redirect(url_for('admin_users'))
    
    if request.method == 'POST':
        # Update user details
        username = request.form['username']
        email = request.form['email']
        role = request.form['role']
        
        # Update user in MongoDB
        result = users_collection.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {'username': username, 'email': email, 'role': role, 'updated_at': datetime.now()}}
        )
        
        if result.modified_count > 0:
            flash('User updated successfully!', 'success')
        else:
            flash('Error updating user.', 'error')
        
        return redirect(url_for('admin_users'))
    
    # Get user details for the form
    user = users_collection.find_one({'_id': ObjectId(user_id)})
    if user:
        user['_id'] = str(user['_id'])
        return render_template('admin/edit_user.html', user=user)
    else:
        flash('User not found.', 'error')
        return redirect(url_for('admin_users'))

@app.route('/admin/delete_user/<user_id>', methods=['POST'])
@require_role('admin')
def admin_delete_user(user_id):
    if mongo_client is None:
        flash('User deletion not available in demo mode.', 'error')
        return redirect(url_for('admin_users'))
    
    # Delete user from MongoDB
    result = users_collection.delete_one({'_id': ObjectId(user_id)})
    
    if result.deleted_count > 0:
        flash('User deleted successfully!', 'success')
    else:
        flash('Error deleting user.', 'error')
    
    return redirect(url_for('admin_users'))

@app.route('/admin/orders')
@require_role('admin')
def admin_orders():
    # Get all orders from MongoDB
    if mongo_client is None:
        # Fallback to sample data
        orders = [
            {'id': 'FC-12345', 'customer': 'john_doe', 'total': 1250.00, 'status': 'Delivered', 'date': '2023-06-15'},
            {'id': 'FC-12344', 'customer': 'jane_smith', 'total': 890.50, 'status': 'In Progress', 'date': '2023-06-15'},
            {'id': 'FC-12343', 'customer': 'bob_johnson', 'total': 2100.75, 'status': 'Pending', 'date': '2023-06-14'}
        ]
    else:
        # Get orders from MongoDB
        orders = list(orders_collection.find({}))
        # Convert ObjectId to string for JSON serialization
        for order in orders:
            order['_id'] = str(order['_id'])
    
    return render_template('admin/orders.html', orders=orders)

@app.route('/admin/menu')
@require_role('admin')
def admin_menu():
    return render_template('admin/menu.html', menu_items=menu_data)

@app.route('/admin/add_menu_item', methods=['GET', 'POST'])
@require_role('admin')
def admin_add_menu_item():
    if request.method == 'POST':
        # Get form data
        name = request.form['name']
        description = request.form['description']
        price = float(request.form['price'])
        category = request.form['category']
        image = request.form['image']
        
        print(f"Adding menu item: {name}, {price}, {category}")
        
        # Generate a new ID (in a real app, this would come from the database)
        new_id = max([item['id'] for item in menu_data]) + 1 if menu_data else 1
        
        # Create new menu item
        new_item = {
            'id': new_id,
            'name': name,
            'description': description,
            'price': price,
            'category': category,
            'image': image
        }
        
        # Add to our in-memory menu data (in a real app, this would be saved to MongoDB)
        menu_data.append(new_item)
        
        print(f"Menu item added successfully with ID: {new_id}")
        flash('Menu item added successfully!', 'success')
        return redirect(url_for('admin_menu'))
    
    return render_template('admin/add_menu_item.html')

@app.route('/admin/edit_menu_item/<int:item_id>', methods=['GET', 'POST'])
@require_role('admin')
def admin_edit_menu_item(item_id):
    # Find the menu item
    item = next((item for item in menu_data if item['id'] == item_id), None)
    
    if request.method == 'POST':
        if item:
            # Update the menu item
            item['name'] = request.form['name']
            item['description'] = request.form['description']
            item['price'] = float(request.form['price'])
            item['category'] = request.form['category']
            item['image'] = request.form['image']
            
            flash('Menu item updated successfully!', 'success')
        else:
            flash('Menu item not found.', 'error')
        return redirect(url_for('admin_menu'))
    
    if item:
        return render_template('admin/edit_menu_item.html', item=item)
    else:
        flash('Menu item not found.', 'error')
        return redirect(url_for('admin_menu'))

@app.route('/admin/analytics')
@require_role('admin')
def admin_analytics():
    return render_template('admin/analytics.html')

@app.route('/admin/logs')
@require_role('admin')
def admin_logs():
    return render_template('admin/logs.html')

@app.route('/admin/settings')
@require_role('admin')
def admin_settings():
    return render_template('admin/settings.html')

@app.route('/owner/dashboard')
@require_role('owner')
def owner_dashboard():
    return render_template('owner/dashboard.html')

@app.route('/owner/orders')
@require_role('owner')
def owner_orders():
    # Get restaurant orders from MongoDB
    if mongo_client is None:
        # Fallback to sample data
        orders = [
            {'id': 'FC-12345', 'customer': 'john_doe', 'total': 1250.00, 'status': 'Pending', 'date': '2023-06-15'},
            {'id': 'FC-12344', 'customer': 'jane_smith', 'total': 890.50, 'status': 'In Progress', 'date': '2023-06-15'},
            {'id': 'FC-12343', 'customer': 'bob_johnson', 'total': 2100.75, 'status': 'Ready', 'date': '2023-06-14'}
        ]
    else:
        # Get orders from MongoDB for this restaurant
        # In a real implementation, we would filter by restaurant
        orders = list(orders_collection.find({}))
        # Convert ObjectId to string for JSON serialization
        for order in orders:
            order['_id'] = str(order['_id'])
    
    return render_template('owner/orders.html', orders=orders)

@app.route('/owner/order/<order_id>')
@require_role('owner')
def owner_order_details(order_id):
    # Get order details from MongoDB
    if mongo_client is None:
        # Fallback to sample data
        order = {
            'id': order_id,
            'customer': 'john_doe',
            'total': 1250.00,
            'status': 'Pending',
            'date': '2023-06-15',
            'items': [
                {'name': 'Margherita Pizza', 'quantity': 2, 'price': 1078.17},
                {'name': 'Caesar Salad', 'quantity': 1, 'price': 746.17}
            ]
        }
    else:
        # Get order from MongoDB
        order = orders_collection.find_one({'_id': ObjectId(order_id)})
        if order:
            order['_id'] = str(order['_id'])
    
    return render_template('owner/order_details.html', order=order)

@app.route('/owner/menu')
@require_role('owner')
def owner_menu():
    return render_template('owner/menu.html', menu_items=menu_data)

@app.route('/owner/add_menu_item', methods=['GET', 'POST'])
@require_role('owner')
def owner_add_menu_item():
    if request.method == 'POST':
        # Get form data
        name = request.form['name']
        description = request.form['description']
        price = float(request.form['price'])
        category = request.form['category']
        image = request.form['image']
        
        # Generate a new ID (in a real app, this would come from the database)
        new_id = max([item['id'] for item in menu_data]) + 1 if menu_data else 1
        
        # Create new menu item
        new_item = {
            'id': new_id,
            'name': name,
            'description': description,
            'price': price,
            'category': category,
            'image': image
        }
        
        # Add to our in-memory menu data (in a real app, this would be saved to MongoDB)
        menu_data.append(new_item)
        
        flash('Menu item added successfully!', 'success')
        return redirect(url_for('owner_menu'))
    
    return render_template('owner/add_menu_item.html')

@app.route('/owner/edit_menu_item/<int:item_id>', methods=['GET', 'POST'])
@require_role('owner')
def owner_edit_menu_item(item_id):
    # Find the menu item
    item = next((item for item in menu_data if item['id'] == item_id), None)
    
    if request.method == 'POST':
        if item:
            # Update the menu item
            item['name'] = request.form['name']
            item['description'] = request.form['description']
            item['price'] = float(request.form['price'])
            item['category'] = request.form['category']
            item['image'] = request.form['image']
            
            flash('Menu item updated successfully!', 'success')
        else:
            flash('Menu item not found.', 'error')
        return redirect(url_for('owner_menu'))
    
    if item:
        return render_template('owner/edit_menu_item.html', item=item)
    else:
        flash('Menu item not found.', 'error')
        return redirect(url_for('owner_menu'))

@app.route('/owner/inventory')
@require_role('owner')
def owner_inventory():
    return render_template('owner/inventory.html')

@app.route('/owner/analytics')
@require_role('owner')
def owner_analytics():
    return render_template('owner/analytics.html')

@app.route('/owner/reports')
@require_role('owner')
def owner_reports():
    return render_template('owner/reports.html')

@app.route('/delivery/dashboard')
@require_role('delivery')
def delivery_dashboard():
    return render_template('delivery/dashboard.html')

@app.route('/delivery/orders')
@require_role('delivery')
def delivery_orders():
    # Get delivery orders from MongoDB
    if mongo_client is None:
        # Fallback to sample data
        orders = [
            {'id': 'FC-12345', 'customer': 'john_doe', 'total': 1250.00, 'status': 'Pending Pickup', 'address': '123 Main St', 'phone': '+1234567890'},
            {'id': 'FC-12344', 'customer': 'jane_smith', 'total': 890.50, 'status': 'In Progress', 'address': '456 Oak Ave', 'phone': '+1234567891'},
            {'id': 'FC-12343', 'customer': 'bob_johnson', 'total': 2100.75, 'status': 'Delivered', 'address': '789 Pine Rd', 'phone': '+1234567892'}
        ]
    else:
        # Get orders from MongoDB for this delivery partner
        # In a real implementation, we would filter by delivery partner
        orders = list(orders_collection.find({}))
        # Convert ObjectId to string for JSON serialization
        for order in orders:
            order['_id'] = str(order['_id'])
    
    return render_template('delivery/orders.html', orders=orders)

@app.route('/delivery/order/<order_id>')
@require_role('delivery')
def delivery_order_details(order_id):
    # Get order details from MongoDB
    if mongo_client is None:
        # Fallback to sample data
        order = {
            'id': order_id,
            'customer': 'john_doe',
            'total': 1250.00,
            'status': 'Pending Pickup',
            'address': '123 Main St',
            'phone': '+1234567890',
            'items': [
                {'name': 'Margherita Pizza', 'quantity': 2, 'price': 1078.17},
                {'name': 'Caesar Salad', 'quantity': 1, 'price': 746.17}
            ]
        }
    else:
        # Get order from MongoDB
        order = orders_collection.find_one({'_id': ObjectId(order_id)})
        if order:
            order['_id'] = str(order['_id'])
    
    return render_template('delivery/order_details.html', order=order)

@app.route('/delivery/earnings')
@require_role('delivery')
def delivery_earnings():
    return render_template('delivery/earnings.html')

@app.route('/delivery/profile')
@require_role('delivery')
def delivery_profile():
    # Get delivery partner profile from MongoDB
    if mongo_client is None:
        # Fallback to sample data
        profile = {
            'name': 'Delivery Partner',
            'email': 'delivery@foodcarve.com',
            'phone': '+1234567890',
            'vehicle': 'Motorcycle',
            'license_plate': 'DL1234',
            'availability': 'Online'
        }
    else:
        # Get profile from MongoDB
        user = users_collection.find_one({'username': session['username']})
        if user:
            profile = {
                'name': user.get('username', ''),
                'email': user.get('email', ''),
                'phone': user.get('phone', ''),
                'vehicle': user.get('vehicle', ''),
                'license_plate': user.get('license_plate', ''),
                'availability': user.get('availability', 'Online')
            }
        else:
            # Fallback if user not found
            profile = {
                'name': session['username'],
                'email': '',
                'phone': '',
                'vehicle': '',
                'license_plate': '',
                'availability': 'Online'
            }
    
    return render_template('delivery/profile.html', profile=profile)

@app.route('/delivery/notifications')
@require_role('delivery')
def delivery_notifications():
    return render_template('delivery/notifications.html')

@app.route('/delivery/update_status/<order_id>/<status>', methods=['POST'])
@require_role('delivery')
def delivery_update_status(order_id, status):
    if mongo_client is None:
        flash('Order status update not available in demo mode.', 'error')
    else:
        # Update order status in MongoDB
        result = orders_collection.update_one(
            {'_id': ObjectId(order_id)},
            {'$set': {'status': status, 'updated_at': datetime.now()}}
        )
        
        if result.modified_count > 0:
            flash(f'Order status updated to {status}!', 'success')
        else:
            flash('Error updating order status.', 'error')
    
    return redirect(url_for('delivery_orders'))

@app.route('/restaurants')
def restaurants():
    # In a real app, this would fetch restaurants from database
    return render_template('restaurants.html')

@app.route('/subscription')
def subscription():
    # Sample subscription plans data
    plans = [
        {
            'id': 'weekly',
            'name': 'Weekly Plan',
            'description': 'Perfect for trying out our service',
            'price': 1500,
            'original_price': 1800,
            'savings': 300,
            'meals_count': 3,
            'meals_period': 'week',
            'features': [
                'Fresh, chef-prepared selections',
                'Free delivery (worth ₹150)',
                'Choose from 15+ rotating menu options',
                'Pause or cancel anytime',
                'Basic customization options'
            ],
            'popular': False
        },
        {
            'id': 'monthly',
            'name': 'Monthly Plan',
            'description': 'Most popular choice',
            'price': 3000,
            'original_price': 3600,
            'savings': 600,
            'meals_count': 3,
            'meals_period': 'month',
            'features': [
                'Fresh, chef-prepared selections',
                'Free delivery (worth ₹600)',
                'Choose from 20+ rotating menu options',
                'Priority customer support',
                'Advanced customization options',
                'Skip up to 2 weeks per month',
                'Pause or cancel anytime'
            ],
            'popular': True
        },
        {
            'id': 'yearly',
            'name': 'Yearly Plan',
            'description': 'Best value',
            'price': 12000,
            'original_price': 18000,
            'savings': 6000,
            'meals_count': 3,
            'meals_period': 'year',
            'features': [
                'Fresh, chef-prepared selections',
                'Free delivery (worth ₹7,200)',
                'Choose from 25+ rotating menu options',
                'Premium customer support',
                'Full customization options',
                'Skip up to 8 weeks per year',
                'Exclusive seasonal menus',
                'Pause or cancel anytime'
            ],
            'popular': False
        }
    ]
    return render_template('subscription.html', plans=plans)

@app.route('/kids_subscription')
def kids_subscription():
    # Sample kids subscription plans data
    kids_plans = [
        {
            'id': 'kids-weekly',
            'name': 'Kids Weekly Plan',
            'description': 'Nutritious kid-friendly options',
            'price': 1200,
            'original_price': 1500,
            'savings': 300,
            'meals_count': 5,
            'meals_period': 'week',
            'features': [
                'Kid-friendly options',
                'Age-appropriate portion sizes (2-12 years)',
                'Free delivery (worth ₹100)',
                'Customizable menu based on preferences',
                'Nutritionally balanced for children',
                'No artificial colors or preservatives',
                'Fun presentation that kids love',
                'Parental controls included'
            ],
            'popular': False
        },
        {
            'id': 'kids-monthly',
            'name': 'Kids Monthly Plan',
            'description': 'Nutritious kid-friendly options with savings',
            'price': 4000,
            'original_price': 5000,
            'savings': 1000,
            'meals_count': 3,
            'meals_period': 'month',
            'features': [
                'Kid-friendly options',
                'Age-appropriate portion sizes (2-12 years)',
                'Free delivery (worth ₹400)',
                'Customizable menu based on preferences',
                '15% savings compared to weekly',
                'Nutritionally balanced for children',
                'No artificial colors or preservatives',
                'Fun presentation that kids love',
                'Skip up to 1 week per month',
                'Growth tracking dashboard',
                'Parental controls included'
            ],
            'popular': True
        }
    ]
    return render_template('kids_subscription.html', kids_plans=kids_plans)

@app.route('/donate')
def donate():
    # Placeholder for donate page
    return render_template('donate.html')

@app.route('/contact')
def contact():
    # Placeholder for contact page
    return render_template('contact.html')

@app.route('/about')
def about():
    # Placeholder for about page
    return render_template('about.html')

@app.route('/order_tracking')
def order_tracking():
    # Placeholder for order tracking page
    return render_template('order_tracking.html')

@app.route('/profile')
def profile():
    # Placeholder for profile page
    return render_template('profile.html')

@app.route('/delivery_tracking')
def delivery_tracking():
    # Placeholder for delivery tracking page
    return render_template('delivery_tracking.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """Forgot password page"""
    if request.method == 'POST':
        email = request.form.get('email')
        # In a real application, you would send a password reset email
        # For now, we'll just show a success message
        return render_template('forgot_password.html', success=True)
    
    return render_template('forgot_password.html')

@app.route('/subscription_checkout')
def subscription_checkout():
    # Get the plan parameter from the URL
    plan_id = request.args.get('plan')
    
    # Sample plan data - in a real app, this would come from a database
    plans = {
        'weekly': {
            'id': 'weekly',
            'name': 'Weekly Plan',
            'description': 'Perfect for trying out our service',
            'price': 1500,
            'original_price': 1800,
            'savings': 300,
            'meals_count': 3,
            'meals_period': 'week'
        },
        'monthly': {
            'id': 'monthly',
            'name': 'Monthly Plan',
            'description': 'Most popular choice',
            'price': 3000,
            'original_price': 3600,
            'savings': 600,
            'meals_count': 3,
            'meals_period': 'month'
        },
        'yearly': {
            'id': 'yearly',
            'name': 'Yearly Plan',
            'description': 'Best value',
            'price': 12000,
            'original_price': 18000,
            'savings': 6000,
            'meals_count': 3,
            'meals_period': 'year'
        },
        'kids-weekly': {
            'id': 'kids-weekly',
            'name': 'Kids Weekly Plan',
            'description': 'Nutritious kid-friendly options',
            'price': 1200,
            'original_price': 1500,
            'savings': 300,
            'meals_count': 5,
            'meals_period': 'week'
        },
        'kids-monthly': {
            'id': 'kids-monthly',
            'name': 'Kids Monthly Plan',
            'description': 'Nutritious kid-friendly options with savings',
            'price': 4000,
            'original_price': 5000,
            'savings': 1000,
            'meals_count': 3,
            'meals_period': 'month'
        }
    }
    
    # Get the selected plan or default to monthly
    selected_plan = plans.get(plan_id) if plan_id else plans['monthly']
    
    return render_template('subscription_checkout.html', plan=selected_plan)

@app.route('/api/subscription_plan/<plan_id>')
def api_subscription_plan(plan_id):
    """API endpoint to get subscription plan details by ID"""
    # Sample plan data - in a real app, this would come from a database
    plans = {
        'weekly': {
            'id': 'weekly',
            'name': 'Weekly Plan',
            'description': 'Perfect for trying out our service',
            'price': 1500,
            'original_price': 1800,
            'savings': 300,
            'meals_count': 3,
            'meals_period': 'week',
            'features': [
                'Fresh, chef-prepared selections',
                'Free delivery (worth ₹150)',
                'Choose from 15+ rotating menu options',
                'Pause or cancel anytime',
                'Basic customization options'
            ]
        },
        'monthly': {
            'id': 'monthly',
            'name': 'Monthly Plan',
            'description': 'Most popular choice',
            'price': 3000,
            'original_price': 3600,
            'savings': 600,
            'meals_count': 3,
            'meals_period': 'month',
            'features': [
                'Fresh, chef-prepared selections',
                'Free delivery (worth ₹600)',
                'Choose from 20+ rotating menu options',
                'Priority customer support',
                'Advanced customization options',
                'Skip up to 2 weeks per month',
                'Pause or cancel anytime'
            ]
        },
        'yearly': {
            'id': 'yearly',
            'name': 'Yearly Plan',
            'description': 'Best value',
            'price': 12000,
            'original_price': 18000,
            'savings': 6000,
            'meals_count': 3,
            'meals_period': 'year',
            'features': [
                'Fresh, chef-prepared selections',
                'Free delivery (worth ₹7,200)',
                'Choose from 25+ rotating menu options',
                'Premium customer support',
                'Full customization options',
                'Skip up to 8 weeks per year',
                'Exclusive seasonal menus',
                'Pause or cancel anytime'
            ]
        },
        'kids-weekly': {
            'id': 'kids-weekly',
            'name': 'Kids Weekly Plan',
            'description': 'Nutritious kid-friendly options',
            'price': 1200,
            'original_price': 1500,
            'savings': 300,
            'meals_count': 5,
            'meals_period': 'week',
            'features': [
                'Kid-friendly options',
                'Age-appropriate portion sizes (2-12 years)',
                'Free delivery (worth ₹100)',
                'Customizable menu based on preferences',
                'Nutritionally balanced for children',
                'No artificial colors or preservatives',
                'Fun presentation that kids love',
                'Parental controls included'
            ]
        },
        'kids-monthly': {
            'id': 'kids-monthly',
            'name': 'Kids Monthly Plan',
            'description': 'Nutritious kid-friendly options with savings',
            'price': 4000,
            'original_price': 5000,
            'savings': 1000,
            'meals_count': 3,
            'meals_period': 'month',
            'features': [
                'Kid-friendly options',
                'Age-appropriate portion sizes (2-12 years)',
                'Free delivery (worth ₹400)',
                'Customizable menu based on preferences',
                '15% savings compared to weekly',
                'Nutritionally balanced for children',
                'No artificial colors or preservatives',
                'Fun presentation that kids love',
                'Skip up to 1 week per month',
                'Growth tracking dashboard',
                'Parental controls included'
            ]
        }
    }
    
    plan = plans.get(plan_id)
    if plan:
        return jsonify(plan)
    else:
        return jsonify({'error': 'Plan not found'}), 404

@app.route('/process_subscription_checkout', methods=['POST'])
def process_subscription_checkout():
    """Process subscription checkout"""
    try:
        # Get form data
        name = request.form.get('name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        address = request.form.get('address')
        payment_method = request.form.get('payment')
        plan_id = request.form.get('plan')
        
        # For Razorpay payments, we need to verify the payment
        if payment_method == 'razorpay':
            razorpay_payment_id = request.form.get('razorpay_payment_id')
            razorpay_order_id = request.form.get('razorpay_order_id')
            razorpay_signature = request.form.get('razorpay_signature')
            
            # In a real implementation, you would verify the payment with Razorpay
            # For now, we'll just check if we have the required fields
            if not all([razorpay_payment_id, razorpay_order_id, razorpay_signature]):
                return render_template('subscription_error.html', 
                                     error="Payment verification failed. Please try again.")
        
        # Sample plan data for confirmation
        plans = {
            'weekly': {
                'id': 'weekly',
                'name': 'Weekly Plan',
                'price': 1500,
                'meals_period': 'week'
            },
            'monthly': {
                'id': 'monthly',
                'name': 'Monthly Plan',
                'price': 3000,
                'meals_period': 'month'
            },
            'yearly': {
                'id': 'yearly',
                'name': 'Yearly Plan',
                'price': 12000,
                'meals_period': 'year'
            },
            'kids-weekly': {
                'id': 'kids-weekly',
                'name': 'Kids Weekly Plan',
                'price': 1200,
                'meals_period': 'week'
            },
            'kids-monthly': {
                'id': 'kids-monthly',
                'name': 'Kids Monthly Plan',
                'price': 4000,
                'meals_period': 'month'
            }
        }
        
        # Handle case where plan_id might be None
        if plan_id is None:
            selected_plan = plans['monthly']  # Default to monthly plan
        else:
            selected_plan = plans.get(plan_id, plans['monthly'])
        
        # In a real application, you would save this to the database
        # For now, we'll just show a success page
        return render_template('subscription_success.html', 
                             name=name, 
                             email=email, 
                             plan=selected_plan,
                             payment_method=payment_method)
                             
    except Exception as e:
        print(f"Error processing subscription: {e}")
        return render_template('subscription_error.html', 
                             error="An error occurred while processing your subscription. Please try again.")

@app.route('/api/admin/dashboard-stats')
@require_role('admin')
def api_admin_dashboard_stats():
    """API endpoint to get admin dashboard statistics"""
    try:
        if mongo_client is None:
            # Return sample data if MongoDB is not available
            stats = {
                'total_users': 1248,
                'total_orders': 3421,
                'total_revenue': 245678,
                'pending_orders': 24,
                'users_trend': 12,
                'orders_trend': 8,
                'revenue_trend': 15,
                'pending_orders_trend': -5
            }
        else:
            # Get real data from MongoDB
            total_users = users_collection.count_documents({})
            total_orders = orders_collection.count_documents({})
            
            # Calculate total revenue from orders
            total_revenue = 0
            pending_orders = 0
            
            orders = orders_collection.find({})
            for order in orders:
                if 'total' in order:
                    total_revenue += order['total']
                if 'status' in order and order['status'] in ['Pending', 'In Progress']:
                    pending_orders += 1
            
            # For trend data, we would need historical data
            # For now, we'll use sample values
            stats = {
                'total_users': total_users,
                'total_orders': total_orders,
                'total_revenue': round(total_revenue, 2),
                'pending_orders': pending_orders,
                'users_trend': 12,
                'orders_trend': 8,
                'revenue_trend': 15,
                'pending_orders_trend': -5
            }
        
        return jsonify(stats)
    except Exception as e:
        print(f"Error fetching admin dashboard stats: {e}")
        # Return sample data as fallback
        return jsonify({
            'total_users': 1248,
            'total_orders': 3421,
            'total_revenue': 245678,
            'pending_orders': 24,
            'users_trend': 12,
            'orders_trend': 8,
            'revenue_trend': 15,
            'pending_orders_trend': -5
        })

@app.route('/api/owner/dashboard-stats')
@require_role('owner')
def api_owner_dashboard_stats():
    """API endpoint to get owner dashboard statistics"""
    try:
        if mongo_client is None:
            # Return sample data if MongoDB is not available
            stats = {
                'today_orders': 42,
                'today_revenue': 18450,
                'active_menu_items': 28,
                'pending_deliveries': 8,
                'orders_trend': 12,
                'revenue_trend': 8,
                'pending_deliveries_trend': -3
            }
        else:
            # Get real data from MongoDB
            # For a real implementation, we would filter by restaurant
            today_orders = orders_collection.count_documents({})
            
            # Calculate today's revenue
            today_revenue = 0
            pending_deliveries = 0
            
            orders = orders_collection.find({})
            for order in orders:
                if 'total' in order:
                    today_revenue += order['total']
                if 'status' in order and order['status'] in ['Pending', 'In Progress']:
                    pending_deliveries += 1
            
            # For a real implementation, we would get active menu items from menu_collection
            active_menu_items = len(menu_data)
            
            stats = {
                'today_orders': today_orders,
                'today_revenue': round(today_revenue, 2),
                'active_menu_items': active_menu_items,
                'pending_deliveries': pending_deliveries,
                'orders_trend': 12,
                'revenue_trend': 8,
                'pending_deliveries_trend': -3
            }
        
        return jsonify(stats)
    except Exception as e:
        print(f"Error fetching owner dashboard stats: {e}")
        # Return sample data as fallback
        return jsonify({
            'today_orders': 42,
            'today_revenue': 18450,
            'active_menu_items': 28,
            'pending_deliveries': 8,
            'orders_trend': 12,
            'revenue_trend': 8,
            'pending_deliveries_trend': -3
        })

@app.route('/api/delivery/dashboard-stats')
@require_role('delivery')
def api_delivery_dashboard_stats():
    """API endpoint to get delivery dashboard statistics"""
    try:
        if mongo_client is None:
            # Return sample data if MongoDB is not available
            stats = {
                'today_deliveries': 12,
                'earnings_today': 1240,
                'pending_deliveries': 3,
                'completed_today': 9,
                'deliveries_trend': 5,
                'earnings_trend': 12,
                'pending_deliveries_trend': -2,
                'completed_trend': 8
            }
        else:
            # Get real data from MongoDB
            # For a real implementation, we would filter by delivery partner
            today_deliveries = orders_collection.count_documents({})
            
            # Calculate earnings
            earnings_today = 0
            pending_deliveries = 0
            completed_today = 0
            
            orders = orders_collection.find({})
            for order in orders:
                if 'total' in order:
                    # In a real implementation, we would calculate actual delivery earnings
                    earnings_today += order['total'] * 0.1  # 10% commission as example
                if 'status' in order:
                    if order['status'] in ['Pending Pickup', 'In Progress']:
                        pending_deliveries += 1
                    elif order['status'] == 'Delivered':
                        completed_today += 1
            
            stats = {
                'today_deliveries': today_deliveries,
                'earnings_today': round(earnings_today, 2),
                'pending_deliveries': pending_deliveries,
                'completed_today': completed_today,
                'deliveries_trend': 5,
                'earnings_trend': 12,
                'pending_deliveries_trend': -2,
                'completed_trend': 8
            }
        
        return jsonify(stats)
    except Exception as e:
        print(f"Error fetching delivery dashboard stats: {e}")
        # Return sample data as fallback
        return jsonify({
            'today_deliveries': 12,
            'earnings_today': 1240,
            'pending_deliveries': 3,
            'completed_today': 9,
            'deliveries_trend': 5,
            'earnings_trend': 12,
            'pending_deliveries_trend': -2,
            'completed_trend': 8
        })

@app.route('/api/check_username', methods=['POST'])
def api_check_username():
    """API endpoint to check if username is available"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'available': False, 'message': 'Invalid request data'})
            
        username = data.get('username', '').strip()
        
        if not username:
            return jsonify({'available': False, 'message': 'Username is required'})
        
        # Basic username validation
        if len(username) < 3:
            return jsonify({'available': False, 'message': 'Username must be at least 3 characters long'})
        
        if len(username) > 50:
            return jsonify({'available': False, 'message': 'Username must be less than 50 characters'})
        
        if mongo_client is None:
            # In demo mode, check against hardcoded users
            hardcoded_users = ['admin', 'owner', 'delivery']
            if username.lower() in hardcoded_users:
                return jsonify({'available': False, 'message': 'Username already exists'})
            else:
                return jsonify({'available': True, 'message': 'Username is available'})
        else:
            # Check if username exists in MongoDB
            existing_user = users_collection.find_one({'username': username}, {'_id': 1})
            if existing_user:
                return jsonify({'available': False, 'message': 'Username already exists'})
            else:
                return jsonify({'available': True, 'message': 'Username is available'})
    except Exception as e:
        print(f"Error checking username: {e}")
        # Don't block the signup process if this API fails
        return jsonify({'available': True, 'message': 'Unable to verify username availability'})

@app.route('/api/validate_email', methods=['POST'])
def api_validate_email():
    """API endpoint to validate email format and check if it exists"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'valid': False, 'message': 'Invalid request data'})
            
        email = data.get('email', '').strip()
        
        if not email:
            return jsonify({'valid': False, 'message': 'Email is required'})
        
        # Validate email format
        if not validate_email(email):
            return jsonify({'valid': False, 'message': 'Invalid email format'})
        
        # Check email length
        if len(email) > 254:  # RFC 5321 limit
            return jsonify({'valid': False, 'message': 'Email address is too long'})
        
        if mongo_client is None:
            # In demo mode, check against hardcoded emails
            hardcoded_emails = ['admin@foodcarve.com', 'owner@foodcarve.com', 'delivery@foodcarve.com']
            if email.lower() in hardcoded_emails:
                return jsonify({'valid': False, 'message': 'Email already exists'})
            else:
                return jsonify({'valid': True, 'message': 'Email is valid'})
        else:
            # Check if email exists in MongoDB
            existing_email = users_collection.find_one({'email': email}, {'_id': 1})
            if existing_email:
                return jsonify({'valid': False, 'message': 'Email already exists'})
            else:
                return jsonify({'valid': True, 'message': 'Email is valid'})
    except Exception as e:
        print(f"Error validating email: {e}")
        # Don't block the signup process if this API fails
        return jsonify({'valid': True, 'message': 'Unable to verify email availability'})

@app.route('/test-db')
def test_db():
    """Test route to check database status"""
    if mongo_client is None:
        return jsonify({'status': 'error', 'message': 'MongoDB not connected'})
    
    try:
        # Test connection
        mongo_client.admin.command('ping')
        
        # Check collections
        users_count = users_collection.count_documents({})
        orders_count = orders_collection.count_documents({})
        menu_count = menu_collection.count_documents({})
        
        # List first few users
        users = list(users_collection.find({}, {'password': 0}).limit(5))
        for user in users:
            user['_id'] = str(user['_id'])
        
        return jsonify({
            'status': 'success',
            'message': 'Database connected and working',
            'collections': {
                'users': users_count,
                'orders': orders_count,
                'menu': menu_count
            },
            'sample_users': users
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Database error: {str(e)}'})

@app.route('/test-redirect')
def test_redirect():
    """Test route to verify redirects are working"""
    print("Test redirect route accessed")
    return redirect(url_for('index'))

@app.route('/test-signup')
def test_signup():
    """Test signup form"""
    return render_template('test-signup.html')

# ==================== RUN APPLICATION ====================
if __name__ == '__main__':
    # Get configuration from environment
    debug = os.getenv('FLASK_DEBUG', 'True').lower() == 'true'
    host = os.getenv('FLASK_HOST', '127.0.0.1')
    port = int(os.getenv('FLASK_PORT', 5000))
    
    print(f"Starting Food Carve application...")
    print(f"Environment: {os.getenv('FLASK_ENV', 'development')}")
    print(f"Debug mode: {debug}")
    print(f"Server: http://{host}:{port}")
    
    app.run(debug=debug, host=host, port=port)