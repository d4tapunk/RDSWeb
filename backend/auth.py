# Import necessary standard and third-party modules
from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from flasgger import swag_from

# Import local modules
from backend.emailUtils import sendEmail  # from email_utils.py
from backend.models.user import User  # Import the User model to interact with user data
from backend import db  # Import the database instance for interacting with the database
from backend.rateLimiter import limiter  # Import rate limiting functionality

# Create a Blueprint for authentication-related routes
auth = Blueprint('auth', __name__)

# User registration route
@auth.route('/register', methods=['GET', 'POST'])
@swag_from({
    'tags': ['Authentication'],
    'parameters': [
        {'name': 'userName', 'in': 'formData', 'type': 'string', 'required': True, 'description': 'Unique username'},
        {'name': 'email', 'in': 'formData', 'type': 'string', 'required': True, 'description': 'User email'},
        {'name': 'password', 'in': 'formData', 'type': 'string', 'required': True, 'description': 'Password'},
        {'name': 'name', 'in': 'formData', 'type': 'string', 'description': 'First name'},
        {'name': 'lastName', 'in': 'formData', 'type': 'string', 'description': 'Last name'},
        {'name': 'age', 'in': 'formData', 'type': 'integer', 'description': 'Age'},
    ],
    'responses': {
        200: {'description': 'User registered successfully'},
        400: {'description': 'Missing required fields or user already exists'}
    }
})
def register():
    if request.method == 'POST':
        user_name = request.form.get('userName')
        email = request.form.get('email')
        password = request.form.get('password')
        name = request.form.get('name')
        last_name = request.form.get('lastName')
        age = request.form.get('age')

        if not user_name or not email or not password:
            flash('Please fill out all required fields.', category='error')
            return redirect(url_for('auth.register'))

        existing_user = User.query.filter(
            (User.userName == user_name) | (User.email == email)
        ).first()

        if existing_user:
            flash('Username or email already exists.', category='error')
            return redirect(url_for('auth.register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        new_user = User(
            userName=user_name, email=email, password=hashed_password,
            name=name, lastName=last_name, age=age
        )
        db.session.add(new_user)
        db.session.commit()
        new_user.customId = new_user.generateCustomId()
        db.session.commit()

        flash('User registered successfully!', category='success')
        return redirect(url_for('auth.login'))

    return render_template('register.html')

# GET route for rendering login form
@auth.route('/login', methods=['GET'])
@swag_from({
    'tags': ['Authentication'],
    'responses': {
        200: {'description': 'Login page rendered successfully'}
    }
})
def login_page():
    return render_template('login.html')

# POST route to handle login attempts
@auth.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
@swag_from({
    'tags': ['Authentication'],
    'parameters': [
        {'name': 'email', 'in': 'body', 'type': 'string', 'required': True, 'description': 'User email'},
        {'name': 'password', 'in': 'body', 'type': 'string', 'required': True, 'description': 'Password'}
    ],
    'responses': {
        200: {'description': 'Login successful', 'schema': {'type': 'object', 'properties': {'access_token': {'type': 'string'}}}},
        401: {'description': 'Invalid email or password'}
    }
})
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    user = User.query.filter_by(email=email).first()

    if user and check_password_hash(user.password, password):
        access_token = create_access_token(
            identity=user.id, expires_delta=timedelta(minutes=30)
        )
        return jsonify(access_token=access_token), 200

    return jsonify({"msg": "Invalid email or password"}), 401

# Profile page rendering route
@auth.route('/profile-page', methods=['GET'])
@swag_from({
    'tags': ['Profile'],
    'responses': {
        200: {'description': 'Profile page rendered successfully'}
    }
})
def profile_page():
    return render_template('profile.html')

# Profile retrieval route (JWT protected)
@auth.route('/profile', methods=['GET'])
@jwt_required()
@swag_from({
    'tags': ['Profile'],
    'responses': {
        200: {
            'description': 'Profile information retrieved successfully',
            'schema': {
                'type': 'object',
                'properties': {
                    'userName': {'type': 'string'},
                    'email': {'type': 'string'},
                    'name': {'type': 'string'},
                    'lastName': {'type': 'string'},
                    'age': {'type': 'integer'},
                    'registrationDate': {'type': 'string'}
                }
            }
        },
        404: {'description': 'User not found'}
    }
})
def profile():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not user:
        return jsonify({"msg": "User not found"}), 404

    return jsonify({
        "userName": user.userName,
        "email": user.email,
        "name": user.name,
        "lastName": user.lastName,
        "age": user.age,
        "registrationDate": user.registrationDate
    }), 200

# Profile update route (JWT protected)
@auth.route('/profile', methods=['PUT'])
@jwt_required()
@swag_from({
    'tags': ['Profile'],
    'parameters': [
        {'name': 'name', 'in': 'body', 'type': 'string', 'description': 'First name'},
        {'name': 'lastName', 'in': 'body', 'type': 'string', 'description': 'Last name'},
        {'name': 'age', 'in': 'body', 'type': 'integer', 'description': 'Age'}
    ],
    'responses': {
        200: {'description': 'Profile updated successfully'},
        404: {'description': 'User not found'}
    }
})
def update_profile():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not user:
        return jsonify({"msg": "User not found"}), 404

    data = request.get_json()
    user.name = data.get('name', user.name)
    user.lastName = data.get('lastName', user.lastName)
    user.age = data.get('age', user.age)
    db.session.commit()

    return jsonify({"msg": "Profile updated successfully"}), 200

# GET route for rendering password reset form
@auth.route('/reset-password', methods=['GET'])
@swag_from({
    'tags': ['Password Reset'],
    'parameters': [
        {'name': 'token', 'in': 'query', 'type': 'string', 'description': 'Password reset token'}
    ],
    'responses': {
        200: {'description': 'Password reset form rendered successfully'}
    }
})
def show_reset_password_form():
    token = request.args.get('token')
    return render_template('resetPassword.html', token=token)

# GET route for requesting password reset
@auth.route('/request-password-reset', methods=['GET'])
@swag_from({
    'tags': ['Password Reset'],
    'responses': {
        200: {'description': 'Password reset request form rendered successfully'}
    }
})
def show_password_reset_request_form():
    return render_template('requestPasswordReset.html')

# POST route to handle password reset requests
@auth.route('/request-password-reset', methods=['POST'])
@swag_from({
    'tags': ['Password Reset'],
    'parameters': [
        {'name': 'email', 'in': 'body', 'type': 'string', 'required': True, 'description': 'User email'}
    ],
    'responses': {
        200: {'description': 'Password reset link sent to email'},
        400: {'description': 'Email is required'},
        404: {'description': 'User not found'}
    }
})
def handle_password_reset_request():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({"msg": "Email is required"}), 400

    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({"msg": "User not found"}), 404

    reset_token = create_access_token(identity=user.id, expires_delta=timedelta(minutes=30))
    user.resetToken = reset_token
    user.tokenUsed = False
    user.resetTokenCreatedAt = datetime.utcnow()
    db.session.commit()

    reset_link = f"http://localhost:5000/auth/reset-password?token={reset_token}"
    sendEmail(user.email, "Password Reset Request", f"Click the link to reset your password: {reset_link}")

    return jsonify({"message": "Password reset link sent to your email"}), 200

# POST route to handle password reset (JWT protected)
@auth.route('/reset-password', methods=['POST'])
@jwt_required()
@swag_from({
    'tags': ['Password Reset'],
    'parameters': [
        {'name': 'newPassword', 'in': 'body', 'type': 'string', 'required': True, 'description': 'New password'}
    ],
    'responses': {
        200: {'description': 'Password reset successful'},
        400: {'description': 'New password is required'},
        404: {'description': 'User not found'}
    }
})
def reset_password():
    data = request.get_json()
    new_password = data.get('newPassword')

    if not new_password:
        return jsonify({"msg": "New password is required"}), 400

    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return jsonify({"msg": "User not found"}), 404

    user.password = generate_password_hash(new_password)
    db.session.commit()

    try:
        sendEmail(
            user.email,
            "Your Password Has Been Reset",
            f"Hello {user.userName},\n\nYour password has been successfully reset. Please keep it secure."
        )
        return jsonify({"msg": "Password reset successful! An email with your new password has been sent."}), 200
    except Exception as e:
        print(f"Failed to send email: {e}")
        return jsonify({"msg": "Password reset successful, but failed to send email."}), 200