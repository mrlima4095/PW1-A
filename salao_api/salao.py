#!/usr/bin/env python
# -*- coding: utf-8 -*-
# |
# Imports
# | (Flask)
from flask import Flask, request, jsonify, send_from_directory, make_response, render_template, redirect
from flask_cors import CORS
from flask import send_file
# | (Others) 
import os
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
    if not request.is_json:
        return jsonify({"response": "Invalid content type. Must be JSON."}), 400

    payload = request.get_json()
    email = payload.get('email')

    mailcursor.execute("SELECT password FROM users WHERE email = ?", (email,))
    row = mailcursor.fetchone()

    if row:
        stored_password = row['password']
        # garante que está em bytes
        if isinstance(stored_password, str):
            stored_password = stored_password.encode('utf-8')

        if bcrypt.checkpw(payload.get('password').encode('utf-8'), stored_password):
            token = gen_token(email)
            response = make_response(jsonify({"response": "Login successful!"}), 200)
            response.set_cookie(
                'token',
                token,
                httponly=True,
                secure=False,  # coloca True em produção com HTTPS
                samesite='Lax',
                max_age=60*60*24*7
            )
            return response

    return jsonify({"response": "Bad credentials!"}), 401
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
        "INSERT INTO users (email, fullname, password, role, phone, birthday) VALUES (?, ?, ?, 'user', ?, ?)",
        (email, fullname, password, phone, birthday)
    )
    mailserver.commit()

    token = gen_token(email)
    response = make_response(jsonify({"response": "Signup successful!"}), 200)
    response.set_cookie('token', token, httponly=True, secure=False, samesite='Lax', max_age=60*60*24*7)
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
@app.route('/aps/agendar', methods=['POST'])
def agendar():
    token = request.cookies.get('token')
    user_data = get_user(token)
    if not user_data: return jsonify({"response": "Unauthorized"}), 401

    payload = request.get_json()
    service = payload.get('service')
    datetime_str = payload.get('datetime')
    client_email = payload.get('clientEmail')

    if not service or not datetime_str: return jsonify({"response": "Incomplete data!"}), 400

    conn, cursor = getdb()

    cursor.execute("SELECT role FROM users WHERE email = ?", (user_data['username'],))
    row = cursor.fetchone()
    role = row['role'] if row else 'user'

    target_email = user_data['username']
    if role == 'worker' and client_email:
        target_email = client_email.strip().lower()

        cursor.execute("SELECT 1 FROM users WHERE email = ?", (target_email,))
        if not cursor.fetchone():
            conn.close()
            return jsonify({"response": "Cliente não encontrado."}), 404

    if role != 'worker':
        cursor.execute("SELECT COUNT(*) as total FROM agendas WHERE datetime = ?", (datetime_str,))
        total_agendas = cursor.fetchone()['total']
        if total_agendas > 0:
            conn.close()
            return jsonify({"response": "Busy agenda"}), 409

    cursor.execute(
        "INSERT INTO agendas (datetime, service, user_email) VALUES (?, ?, ?)",
        (datetime_str, service, target_email)
    )
    conn.commit()
    conn.close()

    return jsonify({"response": "Agendamento realizado com sucesso!"}), 200
@app.route('/aps/cancelar', methods=['POST'])
def cancelar():
    token = request.cookies.get('token')
    user_data = get_user(token)
    if not user_data: return jsonify({"response": "Unauthorized"}), 401

    payload = request.get_json()
    agenda_id = payload.get('id')

    if not agenda_id: return jsonify({"response": "Missing agenda ID"}), 400

    conn, cursor = getdb()

    cursor.execute("SELECT role FROM users WHERE email = ?", (user_data['username'],))
    row = cursor.fetchone()
    role = row['role'] if row else 'user'

    cursor.execute("SELECT user_email FROM agendas WHERE id = ?", (agenda_id,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        return jsonify({"response": "Agenda not found"}), 404

    if role != 'worker' and row['user_email'] != user_data['username']:
        conn.close()
        return jsonify({"response": "Forbidden"}), 403

    cursor.execute("DELETE FROM agendas WHERE id = ?", (agenda_id,))
    conn.commit()
    conn.close()

    return jsonify({"response": "Agenda cancelada com sucesso!"}), 200
# | (Panel)
@app.route('/aps/painel', methods=['GET'])
def painel():
    token = request.cookies.get('token')
    user_data = get_user(token)
    if not user_data:
        return jsonify({"response": "Unauthorized"}), 401

    conn, cursor = getdb()
    cursor.execute("SELECT role, fullname FROM users WHERE email = ?", (user_data['username'],))
    row = cursor.fetchone()

    role = row['role'] if row else 'user'
    fullname = row['fullname'] if row else ''

    if role == 'worker':
        cursor.execute("SELECT * FROM agendas ORDER BY datetime ASC")
    else:
        cursor.execute("SELECT * FROM agendas WHERE user_email = ? ORDER BY datetime ASC", (user_data['username'],))

    agendas = [dict(r) for r in cursor.fetchall()]
    conn.close()

    return jsonify({"role": role, "name": fullname, "agendas": agendas})
@app.route('/aps/check', methods=['GET'])
def check_auth():
    token = request.cookies.get('token')
    user_data = get_user(token)

    if not user_data:
        return redirect("login.html")  # redireciona para a tela de login
    return jsonify({"status": "ok"}), 200
@app.route('/aps/remarcar', methods=['POST'])
def remarcar():
    token = request.cookies.get('token')
    user_data = get_user(token)
    if not user_data:
        return jsonify({"response": "Unauthorized"}), 401

    payload = request.get_json()
    agenda_id = payload.get('id')
    new_datetime = payload.get('datetime')

    if not agenda_id or not new_datetime:
        return jsonify({"response": "Missing data"}), 400

    conn, cursor = getdb()
    # pega role
    cursor.execute("SELECT role FROM users WHERE email = ?", (user_data['username'],))
    row = cursor.fetchone()
    role = row['role'] if row else 'user'

    # verifica se a agenda existe
    cursor.execute("SELECT user_email FROM agendas WHERE id = ?", (agenda_id,))
    agenda_row = cursor.fetchone()
    if not agenda_row:
        conn.close()
        return jsonify({"response": "Agenda not found"}), 404

    # se não for worker, só pode remarcar a própria agenda
    if role != 'worker' and agenda_row['user_email'] != user_data['username']:
        conn.close()
        return jsonify({"response": "Forbidden"}), 403

    # verifica se o novo horário já está ocupado (somente se não for worker)
    if role != 'worker':
        cursor.execute("SELECT COUNT(*) as total FROM agendas WHERE datetime = ?", (new_datetime,))
        total = cursor.fetchone()['total']
        if total > 0:
            conn.close()
            return jsonify({"response": "Busy agenda"}), 409

    # atualiza a agenda
    cursor.execute("UPDATE agendas SET datetime = ? WHERE id = ?", (new_datetime, agenda_id))
    conn.commit()
    conn.close()

    return jsonify({"response": "Agenda remarcada com sucesso!"}), 200

# |
# |
# |
# Start API
if __name__ == '__main__':
    app.run(port=31523, debug=True, host="127.0.0.1")