# Import necessary modules
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from datetime import timedelta
from backend.emailUtils import sendEmail
from backend.models.user import User
from backend import db
from backend.rateLimiter import limiter
import logging  # Use the global logger

# ------------------ Blueprint Setup ------------------

auth = Blueprint('auth', __name__)

# ------------------ User Registration ------------------

@auth.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            userName = request.form.get('userName')
            email = request.form.get('email')
            password = request.form.get('password')
            name = request.form.get('name')
            lastName = request.form.get('lastName')
            age = request.form.get('age')

            # Validate required fields
            if not userName or not email or not password:
                logging.warning("Registration failed: Missing required fields.")
                flash('Please fill out all required fields.', category='error')
                return redirect(url_for('auth.register'))

            # Check if username or email already exists in the database
            existing_user = User.query.filter((User.userName == userName) | (User.email == email)).first()
            if existing_user:
                logging.warning(f"Registration failed: Username or email already exists for {email}.")
                flash('Username or email already exists.', category='error')
                return redirect(url_for('auth.register'))

            # Hash the password before saving it to the database
            hashedPassword = generate_password_hash(password, method='pbkdf2:sha256')
            newUser = User(userName=userName, email=email, password=hashedPassword, 
                           name=name, lastName=lastName, age=age)

            db.session.add(newUser)
            db.session.commit()

            newUser.customId = newUser.generateCustomId()
            db.session.commit()

            logging.info(f"User {userName} registered successfully.")
            flash('User registered successfully!', category='success')
            return redirect(url_for('auth.login'))
        
        except Exception as e:
            logging.error(f"Error during user registration: {e}", exc_info=True)
            flash('An error occurred during registration. Please try again later.', category='error')
            return redirect(url_for('auth.register'))

    logging.info("Rendering registration form.")
    return render_template('register.html')

# ------------------ Login ------------------

@auth.route('/login', methods=['GET'])
def login_page():
    logging.info("Rendering login form.")
    return render_template('login.html')

@auth.route('/login', methods=['POST'])
@limiter.limit("10 per minute")  # Limits login attempts to 10 per minute
def login():
    try:
        data = request.get_json()

        if not data:
            logging.error("Login failed: Missing JSON in request.")
            return jsonify({"msg": "Missing JSON in request"}), 400

        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            logging.warning("Login failed: Email and password are required.")
            return jsonify({"msg": "Email and password are required"}), 400

        user = User.query.filter_by(email=email).first()
        if user is None:
            logging.warning(f"Login failed: User not found with email {email}.")
            return jsonify({"msg": "Invalid email or password"}), 401

        logging.info(f"Retrieved user: {user.userName}")

        if check_password_hash(user.password, password):
            access_token = create_access_token(identity=user.id, expires_delta=timedelta(minutes=30))
            logging.info(f"Login successful for user {user.userName}. Access token generated.")
            return jsonify(accessToken=access_token), 200

        logging.warning(f"Login failed for {email}: Invalid credentials.")
        return jsonify({"msg": "Invalid email or password"}), 401

    except Exception as e:
        logging.error(f"Error during login: {e}", exc_info=True)
        return jsonify({"msg": "An error occurred during login. Please try again later."}), 500

# ------------------ Profile Management ------------------

@auth.route('/profile-page', methods=['GET'])
def profile_page():
    logging.info("Rendering profile page.")
    return render_template('profile.html')

@auth.route('/profile', methods=['GET'])
@jwt_required()
def profile():
    try:
        currentUserId = get_jwt_identity()
        user = User.query.get(currentUserId)

        if not user:
            logging.warning(f"Profile retrieval failed: User {currentUserId} not found.")
            return jsonify({"msg": "User not found"}), 404

        logging.info(f"Profile data retrieved for user {user.userName}.")
        return jsonify({
            "userName": user.userName,
            "email": user.email,
            "name": user.name,
            "lastName": user.lastName,
            "age": user.age,
            "registrationDate": user.registrationDate
        }), 200

    except Exception as e:
        logging.error(f"Error during profile retrieval: {e}", exc_info=True)
        return jsonify({"msg": "An error occurred while retrieving the profile. Please try again later."}), 500

@auth.route('/profile', methods=['PUT'])
@jwt_required()
def update_profile():
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)

        if not user:
            logging.warning(f"Profile update failed: User {current_user_id} not found.")
            return jsonify({"msg": "User not found"}), 404

        data = request.get_json()
        user.name = data.get('name', user.name)
        user.lastName = data.get('lastName', user.lastName)
        user.age = data.get('age', user.age)

        db.session.commit()
        logging.info(f"Profile updated successfully for user {user.userName}.")
        return jsonify({"msg": "Profile updated successfully"}), 200

    except Exception as e:
        logging.error(f"Error during profile update: {e}", exc_info=True)
        return jsonify({"msg": "An error occurred while updating the profile. Please try again later."}), 500

# ------------------ Password Reset ------------------

@auth.route('/request-password-reset', methods=['GET'])
def show_password_reset_request_form():
    logging.info("Rendering password reset request form.")
    return render_template('requestPasswordReset.html')

@auth.route('/request-password-reset', methods=['POST'])
def handle_password_reset_request():
    try:
        data = request.get_json()
        email = data.get('email')

        if not email:
            logging.warning("Password reset request failed: Email is missing.")
            return jsonify({"msg": "Email is missing"}), 400

        user = User.query.filter_by(email=email).first()
        if not user:
            logging.warning(f"Password reset request failed: User with email {email} not found.")
            return jsonify({"msg": "User not found"}), 404

        resetToken = create_access_token(identity=user.id, expires_delta=timedelta(minutes=30))
        resetLink = f"http://localhost:5000/auth/reset-password?token={resetToken}"
        sendEmail(user.email, "Password Reset Request", f"Click the link to reset your password: {resetLink}")

        logging.info(f"Password reset link sent to {email}.")
        return jsonify({"message": "Password reset link sent to your email"}), 200

    except Exception as e:
        logging.error(f"Error during password reset request: {e}", exc_info=True)
        return jsonify({"msg": "An error occurred while processing your request. Please try again later."}), 500

@auth.route('/reset-password', methods=['GET'])
def show_reset_password_form():
    try:
        token = request.args.get('token')
        logging.info("Rendering reset password form.")
        return render_template('resetPassword.html', token=token)
    except Exception as e:
        logging.error(f"Error displaying reset password form: {e}", exc_info=True)
        return jsonify({"msg": "An error occurred. Please try again later."}), 500

@auth.route('/reset-password', methods=['POST'])
@jwt_required()
def reset_password():
    try:
        data = request.get_json()
        newPassword = data.get('newPassword')

        if not newPassword:
            logging.warning("Password reset failed: New password is missing.")
            return jsonify({"msg": "New password is required"}), 400

        userId = get_jwt_identity()
        user = User.query.get(userId)

        if not user:
            logging.warning(f"Password reset failed: User {userId} not found.")
            return jsonify({"msg": "User not found"}), 404

        user.password = generate_password_hash(newPassword)
        db.session.commit()
        logging.info(f"Password reset successful for user {user.userName}.")
        return jsonify({"msg": "Password reset successful"}), 200

    except Exception as e:
        logging.error(f"Error during password reset: {e}", exc_info=True)
        return jsonify({"msg": "An error occurred while resetting the password. Please try again later."}), 500
