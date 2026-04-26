import os
import json
import psycopg2
import logging
import jwt
import datetime
from flask import Flask, request, jsonify, send_from_directory, send_file
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from functools import wraps
import random
from typing import Dict, List
from dataclasses import dataclass
from collections import defaultdict

app = Flask(__name__)
CORS(app)

SECRET_KEY = os.environ.get("SECRET_KEY", "my-super-secret-key-123")
DATABASE_URL = os.environ.get("DATABASE_URL")

EXPORT_DIR = os.path.join(os.getcwd(), 'exports', 'timetables')
LOG_DIR = os.path.join(os.getcwd(), 'exports', 'logs')
os.makedirs(EXPORT_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

bcrypt = Bcrypt(app)

def get_db_connection():
    try:
        if DATABASE_URL:
            conn = psycopg2.connect(DATABASE_URL, sslmode='require')
        else:
            conn = psycopg2.connect(host='localhost', database='postgres', user='postgres', password='1616')
        return conn
    except psycopg2.Error as e:
        logger.error(f"Database connection failed: {e}")
        raise

def init_db():
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    role TEXT NOT NULL CHECK (role IN ('teacher', 'admin'))
                );
                CREATE TABLE IF NOT EXISTS subjects (
                    id SERIAL PRIMARY KEY,
                    name TEXT NOT NULL,
                    teacher TEXT NOT NULL,
                    max_daily_slots INTEGER DEFAULT 2,
                    preferred_rooms TEXT[],
                    created_by INTEGER REFERENCES users(id)
                );
                CREATE TABLE IF NOT EXISTS timetables (
                    id SERIAL PRIMARY KEY,
                    data JSONB NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    created_by INTEGER REFERENCES users(id),
                    is_deleted BOOLEAN DEFAULT FALSE
                );
            """)
            conn.commit()
            default_users = [('admin', 'admin123', 'admin'), ('teacher', 'teacher123', 'teacher')]
            for username, password, role in default_users:
                hashed = bcrypt.generate_password_hash(password).decode('utf-8')
                cur.execute("""
                    INSERT INTO users (username, password, role)
                    SELECT %s, %s, %s WHERE NOT EXISTS (SELECT 1 FROM users WHERE username = %s);
                """, (username, hashed, role, username))
            conn.commit()
            logger.info("Database initialized successfully")
    except psycopg2.Error as e:
        logger.error(f"Database initialization failed: {e}")
        raise
    finally:
        conn.close()

def generate_token(user_id, role):
    payload = {'user_id': user_id, 'role': role, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)}
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def verify_token(token):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'message': 'Token is missing or invalid'}), 401
        payload = verify_token(auth_header.split(' ')[1])
        if not payload:
            return jsonify({'message': 'Token is invalid or expired'}), 401
        request.user = payload
        return f(*args, **kwargs)
    return decorated

@dataclass
class Subject:
    name: str
    teacher: str
    max_daily_slots: int = 2
    preferred_rooms: List[str] = None

class TimetableGenerator:
    def __init__(self, subjects):
        self.days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday']
        self.slots = ['9:00', '10:00', '11:00', '12:00', '14:00', '15:00', '16:00']
        self.subjects = subjects

    def generate(self):
        timetable = {day: {} for day in self.days}
        teacher_schedule = defaultdict(set)
        room_schedule = defaultdict(set)
        for day in self.days:
            daily_subjects = defaultdict(int)
            last_subject = None
            for slot in self.slots:
                valid_subjects = [
                    s for s in self.subjects
                    if daily_subjects[s.name] < s.max_daily_slots and
                       (last_subject is None or last_subject.name != s.name) and
                       s.teacher not in teacher_schedule[(day, slot)]
                ]
                if not valid_subjects:
                    timetable[day][slot] = {"subject": "Free", "teacher": "-", "room": "-"}
                    continue
                subject = random.choice(valid_subjects)
                room = self._assign_room(subject, day, slot, room_schedule)
                timetable[day][slot] = {"subject": subject.name, "teacher": subject.teacher, "room": room}
                last_subject = subject
                daily_subjects[subject.name] += 1
                teacher_schedule[(day, slot)].add(subject.teacher)
                if room != "-":
                    room_schedule[(day, slot)].add(room)
        return timetable

    def _assign_room(self, subject, day, slot, room_schedule):
        if not subject.preferred_rooms:
            return "-"
        for room in subject.preferred_rooms:
            if room not in room_schedule[(day, slot)]:
                return room
        return "-"

def get_user_by_username(username):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, username, password, role FROM users WHERE username = %s", (username,))
            user = cur.fetchone()
            return {'id': user[0], 'username': user[1], 'password': user[2], 'role': user[3]} if user else None
    finally:
        conn.close()

def get_subjects_by_user(user_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT name, teacher, max_daily_slots, preferred_rooms FROM subjects WHERE created_by = %s", (user_id,))
            return [Subject(name=r[0], teacher=r[1], max_daily_slots=r[2], preferred_rooms=r[3]) for r in cur.fetchall()]
    finally:
        conn.close()

def get_timetables_by_user(user_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, data, created_at FROM timetables WHERE created_by = %s AND is_deleted = FALSE ORDER BY created_at DESC", (user_id,))
            return [{'id': r[0], 'data': r[1], 'created_at': r[2].isoformat()} for r in cur.fetchall()]
    finally:
        conn.close()

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400
    user = get_user_by_username(username)
    if user and bcrypt.check_password_hash(user['password'], password):
        token = generate_token(user['id'], user['role'])
        return jsonify({'message': 'Login successful', 'token': token, 'user': {'id': user['id'], 'username': user['username'], 'role': user['role']}}), 200
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/api/subjects', methods=['POST'])
@token_required
def create_subjects():
    user_id = request.user['user_id']
    if request.user['role'] not in ['teacher', 'admin']:
        return jsonify({'message': 'Permission denied'}), 403
    data = request.get_json()
    subjects = data.get('subjects', [])
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            for s in subjects:
                cur.execute("INSERT INTO subjects (name, teacher, max_daily_slots, preferred_rooms, created_by) VALUES (%s, %s, %s, %s, %s)",
                    (s['name'], s['teacher'], s.get('max_daily_slots', 2), s.get('preferred_rooms', []), user_id))
            conn.commit()
            return jsonify({'message': 'Subjects added successfully'}), 201
    except psycopg2.Error:
        conn.rollback()
        return jsonify({'message': 'Database error'}), 500
    finally:
        conn.close()

@app.route('/api/timetables', methods=['GET'])
@token_required
def get_timetables():
    return jsonify(get_timetables_by_user(request.user['user_id'])), 200

@app.route('/api/timetables', methods=['POST'])
@token_required
def create_timetable():
    user_id = request.user['user_id']
    if request.user['role'] not in ['teacher', 'admin']:
        return jsonify({'message': 'Permission denied'}), 403
    subjects = get_subjects_by_user(user_id)
    if not subjects:
        return jsonify({'message': 'No subjects defined. Add subjects first.'}), 400
    timetable_data = TimetableGenerator(subjects).generate()
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO timetables (data, created_by) VALUES (%s, %s) RETURNING id, created_at", (json.dumps(timetable_data), user_id))
            timetable_id, created_at = cur.fetchone()
            conn.commit()
            file_path = os.path.join(EXPORT_DIR, f'timetable_{timetable_id}.json')
            with open(file_path, 'w') as f:
                json.dump(timetable_data, f, indent=2)
            return jsonify({'id': timetable_id, 'data': timetable_data, 'created_at': created_at.isoformat()}), 201
    except psycopg2.Error:
        conn.rollback()
        return jsonify({'message': 'Database error'}), 500
    finally:
        conn.close()

@app.route('/api/timetables/<int:id>', methods=['GET'])
@token_required
def get_timetable(id):
    user_id = request.user['user_id']
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, data, created_at, created_by FROM timetables WHERE id = %s AND is_deleted = FALSE", (id,))
            t = cur.fetchone()
            if not t:
                return jsonify({'message': 'Timetable not found'}), 404
            if t[3] != user_id and request.user['role'] != 'admin':
                return jsonify({'message': 'Permission denied'}), 403
            return jsonify({'id': t[0], 'data': t[1], 'created_at': t[2].isoformat()}), 200
    finally:
        conn.close()

@app.route('/api/timetables/<int:id>', methods=['DELETE'])
@token_required
def delete_timetable(id):
    user_id = request.user['user_id']
    if request.user['role'] not in ['teacher', 'admin']:
        return jsonify({'message': 'Permission denied'}), 403
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT created_by FROM timetables WHERE id = %s", (id,))
            t = cur.fetchone()
            if not t:
                return jsonify({'message': 'Timetable not found'}), 404
            if t[0] != user_id and request.user['role'] != 'admin':
                return jsonify({'message': 'Permission denied'}), 403
            cur.execute("UPDATE timetables SET is_deleted = TRUE WHERE id = %s", (id,))
            conn.commit()
            return jsonify({'message': 'Timetable deleted successfully'}), 200
    except psycopg2.Error:
        conn.rollback()
        return jsonify({'message': 'Database error'}), 500
    finally:
        conn.close()

@app.route('/api/timetables/<int:id>/export', methods=['GET'])
@token_required
def export_timetable(id):
    user_id = request.user['user_id']
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, data, created_by FROM timetables WHERE id = %s AND is_deleted = FALSE", (id,))
            t = cur.fetchone()
            if not t:
                return jsonify({'message': 'Timetable not found'}), 404
            if t[2] != user_id and request.user['role'] != 'admin':
                return jsonify({'message': 'Permission denied'}), 403
            file_path = os.path.join(EXPORT_DIR, f'timetable_{id}.json')
            if not os.path.exists(file_path):
                with open(file_path, 'w') as f:
                    json.dump(t[1], f, indent=2)
            return send_file(file_path, as_attachment=True, download_name=f'timetable_{id}.json')
    finally:
        conn.close()

@app.route('/')
def serve_frontend():
    return send_from_directory('static', 'index.html')

@app.route('/favicon.ico')
def serve_favicon():
    try:
        return send_from_directory('static', 'favicon.ico')
    except:
        return '', 204

# Initialize DB on startup (works with gunicorn too)
init_db()

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
