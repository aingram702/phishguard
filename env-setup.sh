# Create project directory
mkdir phishing-sim-platform && cd phishing-sim-platform
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install flask==3.0.0 anthropic==0.39.0 sendgrid==6.11.0 \
            stripe==7.0.0 python-dotenv==1.0.0 sqlalchemy==2.0.23 \
            flask-login==0.6.3 flask-bcrypt==1.0.1 pandas==2.1.4 \
            apscheduler==3.10.4 gunicorn==21.2.0 requests==2.31.0 \
            python-dateutil==2.8.2

# Save dependencies
pip freeze > requirements.txt
