from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Initialize the rate limiter
limiter = Limiter(
    get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Function to attach the rate limiter to the Flask app
def initRateLimiter(app):
    limiter.init_app(app)
