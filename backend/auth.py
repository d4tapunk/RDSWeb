# Import necessary modules
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
# - Blueprint: Allows the authentication routes to be modular.
# - render_template: Renders HTML files from the templates folder.
# - request: Retrieves form data sent by the user.
# - redirect, url_for: Redirects users after actions (like registration or login).
# - flash: Displays success or error messages to the user.
# - session: Stores information about the user login session.

from werkzeug.security import generate_password_hash, check_password_hash
# - generate_password_hash: Hashes passwords for secure storage.
# - check_password_hash: Compares plain-text and hashed passwords during login.

from backend.models.user import User  # Import the User model to interact with user data.
from backend import db  # Import the database instance for interacting with the database.

# Create a Blueprint for authentication-related routes.
auth = Blueprint('auth', __name__)

# Define the route for user registration.
@auth.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':  # Handle form submission
        userName = request.form.get('userName')  
        email = request.form.get('email')  
        password = request.form.get('password') 
        name = request.form.get('name')  
        lastName = request.form.get('lastName') 
        age = request.form.get('age') 

        # Validate required fields
        if not userName or not email or not password:
            flash('Please fill out all required fields.', category='error')
            return redirect(url_for('auth.register'))  # Redirect to the registration form

        # Check if username or email already exists in the database
        existing_user = User.query.filter((User.userName == userName) | (User.email == email)).first()
        if existing_user:  # If user exists, display error message
            flash('Username or email already exists.', category='error')
            return redirect(url_for('auth.register'))  # Redirect to the registration form

        # Hash the password before saving it to the database
        hashedPassword = generate_password_hash(password, method='pbkdf2:sha256')

        # Create a new user instance
        newUser = User(userName=userName, email=email, password=hashedPassword, 
                       name=name, lastName=lastName, age=age)

        # Add the new user to the database
        db.session.add(newUser)
        db.session.commit()  # Commit the transaction to save the user

        # Generate a custom user ID and commit the change
        newUser.customId = newUser.generateCustomId()
        db.session.commit()  # Save the custom ID

        # Flash success message and redirect to the login page
        flash('User registered successfully!', category='success')
        return redirect(url_for('auth.login'))

    # Render the registration form
    return render_template('register.html')

# Define the route for user login
@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':  # Handle form submission
        email = request.form.get('email')  # Get the email from the form
        password = request.form.get('password')  # Get the password from the form

        # Fetch the user from the database by email
        user = User.query.filter_by(email=email).first()

        # Check if the user exists and the password matches
        if user and check_password_hash(user.password, password):  
            session['user_id'] = user.id  # Store the user ID in session
            flash('Logged in successfully!', category='success')
            return redirect(url_for('dashboard'))  # Redirect to a dashboard or home page

        # If login failed, flash an error message
        flash('Invalid email or password. Please try again.', category='error')

    # Render the login form
    return redirect(url_for('auth.dashboard'))  # Correctly reference the dashboard route in the 'auth' blueprint

@auth.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')
