from flask import Flask, request, jsonify
from password_manager import PasswordManager
from flask_cors import CORS
import getpass

app = Flask(__name__)
CORS(app)

master_password = getpass.getpass("Enter your master password: ")
pm = PasswordManager(master_password)

@app.route('/add_password', methods=['POST'])
def add_password():
    data = request.get_json()
    if not data:
        return jsonify({"message": "Invalid input: JSON data is required"}), 400

    site = data.get('site')
    password = data.get('password')
    expiry_days = data.get('expiry_days', 90)
    
    if not site or not password:
        return jsonify({"message": "Invalid input: 'site' and 'password' are required"}), 400

    pm.add_password(site, password, expiry_days)
    return jsonify({"message": "Password added successfully"}), 200

@app.route('/get_password', methods=['POST'])
def get_password():
    data = request.get_json()
    if not data:
        return jsonify({"message": "Invalid input: JSON data is required"}), 400

    site = data.get('site')
    if not site:
        return jsonify({"message": "Invalid input: 'site' is required"}), 400

    password = pm.get_password(site)
    if password:
        return jsonify({"password": password}), 200
    return jsonify({"message": "Password not found"}), 404

@app.route('/generate_password', methods=['GET'])
def generate_password():
    length = request.args.get('length', default=12, type=int)
    password = pm.generate_password(length)
    return jsonify({"password": password}), 200

@app.route('/analyze_password', methods=['POST'])
def analyze_password():
    data = request.get_json()
    if not data:
        return jsonify({"message": "Invalid input: JSON data is required"}), 400

    password = data.get('password')
    if not password:
        return jsonify({"message": "Invalid input: 'password' is required"}), 400

    strength = pm.analyze_password_strength(password)
    return jsonify({"strength": strength}), 200

@app.route('/auto_fill', methods=['POST'])
def auto_fill():
    data = request.get_json()
    if not data:
        return jsonify({"message": "Invalid input: JSON data is required"}), 400

    site = data.get('site')
    if not site:
        return jsonify({"message": "Invalid input: 'site' is required"}), 400

    password = pm.auto_fill(site)
    if password:
        return jsonify({"password": password}), 200
    return jsonify({"message": "Password not found"}), 404

@app.route('/verify_2fa', methods=['POST'])
def verify_2fa():
    data = request.get_json()
    if not data:
        return jsonify({"message": "Invalid input: JSON data is required"}), 400

    code = data.get('code')
    if not code:
        return jsonify({"message": "Invalid input: 'code' is required"}), 400

    if pm.verify_2fa(code):
        return jsonify({"message": "2FA verification successful!"}), 200
    return jsonify({"message": "2FA verification failed."}), 401

if __name__ == '__main__':
    app.run(port=3000)