from flask import Flask, render_template, send_from_directory
import logging
from logging.handlers import RotatingFileHandler
import os

app = Flask(__name__)

# Setup logging
if not os.path.exists('logs'):
    os.mkdir('logs')

log_handler = RotatingFileHandler('logs/app.log', maxBytes=10000, backupCount=3)
log_handler.setLevel(logging.INFO)
log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
log_handler.setFormatter(log_formatter)
app.logger.addHandler(log_handler)

@app.route('/')
def home():
    app.logger.info('Home page accessed')
    return 'Hello, Flask logging!'

@app.route('/log')
def log():
    app.logger.info('Log page accessed')
    return render_template('log.html')

@app.route('/logfile')
def logfile():
    app.logger.info('Log file accessed')
    return send_from_directory('logs', 'app.log')

if __name__ == '__main__':
    app.run(debug=True)
