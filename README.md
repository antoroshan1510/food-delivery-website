# Crave Bite - Online Food Ordering System

## Overview
Crave Bite is a comprehensive online food ordering system built with Flask and MongoDB. It provides features for customers, restaurant owners, delivery partners, and administrators.

## Features
- User authentication (customer, admin, owner, delivery)
- Menu browsing and ordering
- Shopping cart functionality
- Subscription plans
- Order tracking
- Payment processing with Razorpay
- Admin dashboard for managing users, orders, and menu
- Restaurant owner dashboard for menu management
- Delivery partner dashboard for order fulfillment

## Prerequisites
- Python 3.7 or higher
- MongoDB 4.0 or higher
- Node.js and npm (for frontend dependencies)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd food-carve
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Install MongoDB:
   - Download and install MongoDB from https://www.mongodb.com/try/download/community
   - Start the MongoDB service

5. Configure environment variables:
   - Copy `.env.example` to `.env`
   - Update the values in `.env` as needed:
     ```
     MONGODB_URI=mongodb://localhost:27017/
     MONGODB_DATABASE=foodcarve
     SECRET_KEY=your-secure-secret-key
     RAZORPAY_KEY_ID=rzp_test_R8SjqiBx6bgTHd
     RAZORPAY_KEY_SECRET=yBxGwBq2QP4X6rMpXLwX3b6Y
     ```

## Running the Application

1. Start MongoDB service (if not already running)

2. Run the Flask application:
```bash
python app.py
```

3. Open your browser and navigate to `http://localhost:5000`

## Default Users
The application comes with default users for testing:
- Admin: username `admin`, password `Admin123!`
- Restaurant Owner: username `owner`, password `Owner123!`
- Delivery Partner: username `delivery`, password `Delivery123!`

## Database Structure
The application uses MongoDB with the following collections:
- `users`: Stores user information (customers, admins, owners, delivery partners)
- `orders`: Stores order information

## Development
- The application follows MVC architecture
- Templates are in the `templates/` directory
- Static assets (CSS, JS, images) are in the `static/` directory
- Database models and business logic are in `app.py`

## Testing
To run tests:
```bash
python -m pytest tests/
```

## Deployment
For production deployment:
1. Set `DEBUG = False` in the Flask configuration
2. Use a production WSGI server like Gunicorn
3. Configure a reverse proxy like Nginx
4. Use environment variables for sensitive configuration
5. Set up proper logging and monitoring

## Contributing
1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a pull request

## License
This project is licensed under the MIT License.