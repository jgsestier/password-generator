from http.server import BaseHTTPRequestHandler
import secrets
import string
import json


def generate_password(length=16, uppercase=True, lowercase=True, digits=True, special=True):
    """Generate a secure random password with specified criteria."""
    characters = ""
    required = []

    if uppercase:
        characters += string.ascii_uppercase
        required.append(secrets.choice(string.ascii_uppercase))
    if lowercase:
        characters += string.ascii_lowercase
        required.append(secrets.choice(string.ascii_lowercase))
    if digits:
        characters += string.digits
        required.append(secrets.choice(string.digits))
    if special:
        characters += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        required.append(secrets.choice("!@#$%^&*()_+-=[]{}|;:,.<>?"))

    if not characters:
        characters = string.ascii_letters + string.digits
        required = [secrets.choice(characters)]

    remaining_length = length - len(required)
    if remaining_length > 0:
        password_chars = required + [secrets.choice(characters) for _ in range(remaining_length)]
    else:
        password_chars = required[:length]

    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars)


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)

        try:
            data = json.loads(body) if body else {}
        except:
            data = {}

        length = min(max(int(data.get("length", 16)), 4), 128)
        uppercase = data.get("uppercase", True)
        lowercase = data.get("lowercase", True)
        digits = data.get("digits", True)
        special = data.get("special", True)

        password = generate_password(length, uppercase, lowercase, digits, special)
        response = json.dumps({"password": password})

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(response.encode())

    def do_GET(self):
        self.send_response(405)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'Method not allowed')
