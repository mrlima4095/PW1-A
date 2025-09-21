#!/usr/bin/env python
# -*- coding: utf-8 -*-
# |
# Imports
# | (Flask)
from flask import Flask, request, jsonify, send_from_directory, make_response, render_template
from flask_cors import CORS
from flask import send_file
# | (Others) 
import jwt
import time
import json
import uuid
import flask
import socket
import random
import bcrypt
import shutil
import sqlite3
import requests
import threading, pytz
from random import randint
from threading import Timer
from threading import Thread
from cryptography.fernet import Fernet
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
# |
# |
app = Flask(__name__)
CORS(app)
# |
SAO_PAULO_TZ = pytz.timezone("America/Sao_Paulo")
# |
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
# |
# | (JWT Settings)
JWT_SECRET = json.load(open("server.json", "r"))['JWT_SECRET']
JWT_ALGORITHM = 'HS256'
JWT_EXP_DELTA_SECONDS = 604800
# |
# SQLite3  
# | (Open Connection)
def getdb():
    conn = sqlite3.connect('salao.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    return conn, cursor
# |
# JWT Tokens
# |
def gen_token(username):
    payload = {
        'username': username,
        'exp': datetime.utcnow() + timedelta(seconds=JWT_EXP_DELTA_SECONDS)
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token
def get_user(token):
    if not token: return None

    try: return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except (ExpiredSignatureError, InvalidTokenError): return None
# |
# |
# Salao
# |
# Auth API
# | (Login)
@app.route('/aps/login', methods=['POST'])
def login():
    mailserver, mailcursor = getdb()
    if not request.is_json: return jsonify({"response": "Invalid content type. Must be JSON."}), 400

    payload = request.get_json()
    email = payload.get('email')

    mailcursor.execute("SELECT password FROM users WHERE email = ?", (email,))
    row = mailcursor.fetchone()

    if row and bcrypt.checkpw(payload.get('password').encode('utf-8'), row['password']):
        token = gen_token(email)
        response = make_response(jsonify({"response": "Login successful!"}), 200)
        response.set_cookie('token', token, httponly=True, secure=True, samesite='Lax', max_age=60*60*24*7)
        return response
    else: return jsonify({"response": "Bad credentials!"}), 401
# | (Signup)
@app.route('/aps/signup', methods=['POST'])
def signup():
    mailserver, mailcursor = getdb()
    if not request.is_json: return jsonify({"response": "Invalid content type. Must be JSON."}), 400

    payload = request.get_json()
    email = payload.get('email').strip().lower()
    fullname = payload.get('fullname').strip()
    phone = payload.get('phone').strip()
    birthday = payload.get('birthday').strip()
    password = bcrypt.hashpw(payload['password'].encode('utf-8'), bcrypt.gensalt())

    mailcursor.execute("SELECT 1 FROM users WHERE email = ?", (email,))
    if mailcursor.fetchone(): return jsonify({"response": "This email is already registered."}), 409

    mailcursor.execute(
        "INSERT INTO users (email, fullname, password, role, phone, birthday) VALUES (?, ?, ?, ?, 'user', ?, ?)",
        (email, fullname, password, phone, birthday)
    )
    mailserver.commit()

    token = gen_token(email)
    response = make_response(jsonify({"response": "Signup successful!"}), 200)
    response.set_cookie('token', token, httponly=True, secure=True, samesite='Lax', max_age=60*60*24*7)
    return response
# | (Logout)
@app.route('/aps/logout', methods=['POST'])
def logout():
    response = make_response(jsonify({"response": "Logout successful!"}), 200)
    response.set_cookie('token', '', httponly=True, secure=True, samesite='Lax', expires=0)
    return response
# |
# Main API
# | (Order Service)
@app.route('/reserva')
def reserva():
    token = request.cookies.get('token')
    user = get_user(token)

    return redirect('login.html' if not user else 'agendar.html')
@app.route('/aps/agendar', methods=['POST'])
def agendar():
    token = request.cookies.get('token')
    user_data = get_user(token)
    if not user_data: return jsonify({"response": "Unauthorized"}), 401

    payload = request.get_json()
    service = payload.get('service')
    datetime_str = payload.get('datetime')

    if not service or not datetime_str: return jsonify({"response": "Incomplete data!"}), 400

    conn, cursor = getdb()

    cursor.execute("SELECT role FROM users WHERE email = ?", (user_data['username'],))
    row = cursor.fetchone()
    role = row['role'] if row else 'user'

    cursor.execute("SELECT COUNT(*) as total FROM agendas WHERE datetime = ?", (datetime_str,))
    total_agendas = cursor.fetchone()['total']

    if role != 'worker' and total_agendas > 0: return jsonify({"response": "Busy agenda"}), 409

    cursor.execute(
        "INSERT INTO agendas (datetime, service, user_email) VALUES (?, ?, ?)",
        (datetime_str, service, user_data['username'])
    )
    conn.commit()
    conn.close()

    return jsonify({"response": "Service ordered!"})
# |
# |
# |
# Start API
if __name__ == '__main__':
    app.run(port=31523, debug=True, host="127.0.0.1")