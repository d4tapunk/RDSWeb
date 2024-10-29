# Import necessary modules
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from datetime import timedelta
from backend.emailUtils import sendEmail  # Import the sendEmail function from email_utils.py
from backend.models.user import User  # Import the User model to interact with user data.
from backend import db  # Import the database instance for interacting with the database.
from backend.rateLimiter import limiter

# ------------------ Blueprint Setup ------------------

# Create a Blueprint for authentication-related routes.
auth = Blueprint('auth', __name__)

# ------------------ User Registration ------------------

@auth.route('/register', methods=['GET', 'POST'])
def register():
    """Register a new user."""
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

# ------------------ Login ------------------

# GET route to render the login form
@auth.route('/login', methods=['GET'])
def login_page():
    """Render the login form."""
    return render_template('login.html')  # Render the login form HTML

# POST route to handle login
@auth.route('/login', methods=['POST'])
@limiter.limit("10 per minute")  # Limits login attempts to 2 per minute
def login():
    """Authenticate user and provide JWT access token."""
    data = request.get_json()
    
    # Ensure data is received correctly
    if not data:
        print("Error: Missing JSON in request")  # Debugging statement
        return jsonify({"msg": "Missing JSON in request"}), 400

    email = data.get('email')
    password = data.get('password')

    # Verify both email and password are provided
    if not email or not password:
        print("Error: Email and password are required")  # Debugging statement
        return jsonify({"msg": "Email and password are required"}), 400

    # Attempt to retrieve user by email
    user = User.query.filter_by(email=email).first()
    if user is None:
        print(f"Error: User not found with email {email}")  # Debugging statement
        return jsonify({"msg": "Invalid email or password"}), 401

    print("Retrieved user:", user.userName)  # Confirm user retrieval

    # Check if password is correct
    if check_password_hash(user.password, password):
        # Generate access token for authenticated user
        access_token = create_access_token(identity=user.id, expires_delta=timedelta(minutes=30))
        print("Login successful, access token generated")  # Debugging statement
        return jsonify(accessToken=access_token), 200

    # Invalid login attempt if password hash does not match
    print("Error: Invalid email or password")  # Debugging statement
    return jsonify({"msg": "Invalid email or password"}), 401




# ------------------ Profile Management ------------------

@auth.route('/profile-page', methods=['GET'])
def profile_page():
    """Render the profile page."""
    return render_template('profile.html')  

@auth.route('/profile', methods=['GET'])
@jwt_required()
def profile():
    """Retrieve user profile information."""
    currentUserId = get_jwt_identity()
    user = User.query.get(currentUserId)
    
    if not user:
        return jsonify({"msg": "User not found"}), 404

    # Send user details as response
    return jsonify({
        "userName": user.userName,
        "email": user.email,
        "name": user.name,
        "lastName": user.lastName,
        "age": user.age,
        "registrationDate": user.registrationDate  
    }), 200

@auth.route('/profile', methods=['PUT'])
@jwt_required()
def update_profile():
    """Update user profile information."""
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not user:
        return jsonify({"msg": "User not found"}), 404

    # Get updated data from request
    data = request.get_json()
    user.name = data.get('name', user.name)
    user.lastName = data.get('lastName', user.lastName)
    user.age = data.get('age', user.age)

    # Save changes
    db.session.commit()

    return jsonify({"msg": "Profile updated successfully"}), 200

# ------------------ Password Reset ------------------

# GET route to render the password reset request form
@auth.route('/request-password-reset', methods=['GET'])
def show_password_reset_request_form():
    """Render the password reset request form."""
    return render_template('requestPasswordReset.html')

# POST route to handle password reset requests
@auth.route('/request-password-reset', methods=['POST'])
def handle_password_reset_request():
    """Send a password reset link to the user's email."""
    data = request.get_json()  # Expecting JSON data from frontend
    email = data.get('email')

    if not email:
        return jsonify({"msg": "Email is missing"}), 400

    # Find the user by email
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"msg": "User not found"}), 404

    # Generate a password reset token
    resetToken = create_access_token(identity=user.id, expires_delta=timedelta(minutes=30))

    # Create the password reset link
    resetLink = f"http://localhost:5000/auth/reset-password?token={resetToken}"

    # Send the reset link to the user's email
    sendEmail(user.email, "Password Reset Request", f"Click the link to reset your password: {resetLink}")

    return jsonify({"message": "Password reset link sent to your email"}), 200

# GET route to render the password reset form with token
@auth.route('/reset-password', methods=['GET'])
def show_reset_password_form():
    """Render the reset password form."""
    token = request.args.get('token')  # Extract token from the query parameter
    return render_template('resetPassword.html', token=token)  # Pass token to the form

# POST route to handle password reset using token
@auth.route('/reset-password', methods=['POST'])
@jwt_required()
def reset_password():
    """Reset the user's password."""
    data = request.get_json()
    newPassword = data.get('newPassword')

    if not newPassword:
        return jsonify({"msg": "New password is required"}), 400

    # Get the user ID from the JWT token
    userId = get_jwt_identity()
    user = User.query.get(userId)

    if not user:
        return jsonify({"msg": "User not found"}), 404

    # Update the user's password
    user.password = generate_password_hash(newPassword)
    db.session.commit()

    return jsonify({"msg": "Password reset successful"}), 200
