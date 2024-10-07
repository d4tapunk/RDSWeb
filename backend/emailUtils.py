import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

def sendEmail(to, subject, body):
    # Set up the server
    smtp_server = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
    smtp_port = os.getenv('MAIL_PORT', 587)
    smtp_username = os.getenv('MAIL_USERNAME')  # Your email
    smtp_password = os.getenv('MAIL_PASSWORD')  # Your app-specific password

    # Create the email content
    msg = MIMEMultipart()
    msg['From'] = smtp_username
    msg['To'] = to
    msg['Subject'] = subject

    # Attach the body text to the email
    msg.attach(MIMEText(body, 'plain'))

    try:
        # Connect to the server
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()  # Enable security
        server.login(smtp_username, smtp_password)  # Login with your credentials

        # Send the email
        text = msg.as_string()
        server.sendmail(smtp_username, to, text)

        # Close the server connection
        server.quit()

        print(f"Email sent to {to}")
    except Exception as e:
        print(f"Failed to send email: {e}")
