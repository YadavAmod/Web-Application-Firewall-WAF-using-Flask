from flask import Flask, request, abort
import re

app = Flask(__name__)

# List of potentially malicious patterns
MALICIOUS_PATTERNS = [
    r"(?i)<script",  # Detect <script> tags
    r"(?i)SELECT.*FROM",  # Basic SQL injection attempt
    r"(?i)UNION.*SELECT",  # Another SQL injection pattern
    r"(?i)/etc/passwd",  # Attempt to access system files
    r"(?i)\.\./"  # Directory traversal attempt
]

def check_malicious(data):
    for pattern in MALICIOUS_PATTERNS:
        if re.search(pattern, data):
            return True
    return False

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

@app.route('/')
def hello():
    return "Hello, World! This is protected by a simple WAF."

@app.route('/test', methods=['GET', 'POST'])
def test():
    return "This is a test endpoint."

if __name__ == '__main__':
    app.run(debug=True)