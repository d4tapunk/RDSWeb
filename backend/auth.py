# Import necessary modules
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from datetime import timedelta
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


# GET route to render the login form
@auth.route('/login', methods=['GET'])
def login_page():
    return render_template('login.html')  # Render the login form HTML


# POST route to handle login logic (already implemented)
@auth.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    # Fetch user and validate the password
    user = User.query.filter_by(email=email).first()
    if user and check_password_hash(user.password, password):
        access_token = create_access_token(identity=user.id, expires_delta=timedelta(minutes=30))
        return jsonify(access_token=access_token), 200

    return jsonify({"msg": "Invalid email or password"}), 401

@auth.route('/profile-page', methods=['GET'])
def profile_page():
    return render_template('profile.html')  


@auth.route('/profile', methods=['GET'])
@jwt_required()
def profile():
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
