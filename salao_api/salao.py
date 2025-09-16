from flask import Flask, Response, request, session, redirect, render_template, url_for, jsonify
from flask_cors import CORS
# |
import sqlite3

app = Flask(__name__)
CORS(app)



if __name__ == '__main__':
    app.run(host='127.0.0.1', port=10144, debug=True)
