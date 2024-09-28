# Web-Application-Firewall-WAF-using-Flask
This code creates a basic Web Application Firewall (WAF) using Flask. The purpose of this WAF is to detect potentially malicious patterns in incoming HTTP requests and block those that seem dangerous. 

Code Breakdown:
Imports:
from flask import Flask, request, abort
import re
Flask is used to create a web application. It handles HTTP requests and defines routes for the application.
re is Python’s regular expression library, used here to match patterns in incoming requests.
abort is a function that stops the request and sends an error code (e.g., 403 Forbidden).
Creating the Flask App:

app = Flask(__name__)
This line creates a Flask web application instance.

List of Potentially Malicious Patterns:
MALICIOUS_PATTERNS = [
    r"(?i)<script",  # Detect <script> tags
    r"(?i)SELECT.*FROM",  # Basic SQL injection attempt
    r"(?i)UNION.*SELECT",  # Another SQL injection pattern
    r"(?i)/etc/passwd",  # Attempt to access system files
    r"(?i)\.\./"  # Directory traversal attempt
]

This list defines common attack patterns such as:
<script> tags for cross-site scripting (XSS) attacks.
SQL queries like SELECT ... FROM or UNION SELECT, which can be part of an SQL injection.
Access to system files like /etc/passwd (a typical target in local file inclusion (LFI) attacks).
../ is a pattern for directory traversal attacks.
Function to Check for Malicious Data:

def check_malicious(data):
    for pattern in MALICIOUS_PATTERNS:
        if re.search(pattern, data):
            return True
    return False
This function takes a string data as input and checks it against each of the patterns in the MALICIOUS_PATTERNS list using re.search(). If any pattern matches, it returns True (indicating malicious content).
WAF (Web Application Firewall) Logic:
@app.before_request
def waf():
    # Check URL
    if check_malicious(request.path):
        abort(403)  # Forbidden

    # Check query parameters
    if check_malicious(str(request.args)):
        abort(403)

    # Check POST data
    if request.method == 'POST':
        if check_malicious(str(request.form)):
            abort(403)
The @app.before_request decorator ensures that this function runs before each request is processed.
request.path: This checks if the URL path contains any malicious patterns.
request.args: This checks for malicious patterns in the query parameters (like ?id=1&name=example).
request.form: For POST requests, this checks for malicious patterns in the form data.
If any of these checks return True, the request is aborted with a 403 Forbidden response, which denies access to the user.
Routes:

@app.route('/'): A simple home route that returns a basic response:

return "Hello, World! This is protected by a simple WAF."
@app.route('/test', methods=['GET', 'POST']): Another route that accepts both GET and POST requests and simply returns:

return "This is a test endpoint."
Starting the Flask App:

if __name__ == '__main__':
    app.run(debug=True)
This starts the Flask development server in debug mode.
How to Run This Code
Install Required Tools:

Install Flask by running:
pip install flask
  
Save the Code:
Save the code to a file, for example, simple_waf.py.
Run the Flask App:

Open a terminal, navigate to the directory where the code is saved, and run:
python simple_waf.py
This will start the Flask development server, and you can visit the application in your web browser at http://127.0.0.1:5000/.

Test the Application:
You can test the firewall by trying to access URLs with suspicious patterns. For example:

Normal request:
curl http://127.0.0.1:5000/
You should see the message: Hello, World! This is protected by a simple WAF.

Malicious request:
curl http://127.0.0.1:5000/?q=<script>alert('xss')</script>
This should return a 403 Forbidden status because <script> tags are detected as malicious.
