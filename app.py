from flask import Flask, request, jsonify, g
from flask_cors import CORS
import sqlite3
import requests
import jwt
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from config import RECAPTCHA_SECRET, JWT_SECRET, JWT_EXP_SECONDS, DATABASE
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})  


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def generar_token(usuario_id):
    payload = {
        'user_id': usuario_id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=JWT_EXP_SECONDS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def token_requerido(f):
    @wraps(f)
    def decorador(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token no proporcionado'}), 403
        try:
            token = token.replace("Bearer ", "")
            data = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            g.user_id = data['user_id']
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expirado'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Token inválido'}), 401
        return f(*args, **kwargs)
    return decorador

def verificar_recaptcha(token):
    url = "https://www.google.com/recaptcha/api/siteverify"
    data = {'secret': RECAPTCHA_SECRET, 'response': token}
    r = requests.post(url, data=data)
    return r.json().get('success', False)

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    recaptcha_token = data.get('recaptcha_token')

    if not verificar_recaptcha(recaptcha_token):
        return jsonify({'error': 'reCAPTCHA inválido'}), 400

    hashed_password = generate_password_hash(data['contrasena'])

    try:
        conn = get_db()
        conn.execute("""
            INSERT INTO users (nombre, apellido, nombre_usuario, correo, contrasena)
            VALUES (?, ?, ?, ?, ?)
        """, (data['nombre'], data['apellido'], data['nombre_usuario'], data['correo'], hashed_password))

        conn.commit()
        return jsonify({'message': 'Usuario registrado con éxito'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'El correo ya está registrado'}), 400

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    dato = data.get('dato') 
    contrasena = data.get('contrasena')

    conn = get_db()
    user = conn.execute("""
        SELECT * FROM users 
        WHERE correo = ? OR nombre_usuario = ?
    """, (dato, dato)).fetchone()

    if user and check_password_hash(user[5], contrasena): 
        token = generar_token(user[0])  
        nombre_usuario = user[3]        

        return jsonify({
            'token': token,
            'nombre_usuario': nombre_usuario,
        })

    return jsonify({'error': 'Credenciales inválidas'}), 401

@app.route('/favoritos', methods=['POST'])
@token_requerido
def agregar_favorito():
    data = request.json

    conn = get_db()
    conn.execute("""
        INSERT INTO favoritos (user_id, video_id, titulo, thumbnail, canal, duracion)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        g.user_id,
        data['video_id'],
        data['titulo'],
        data['thumbnail'],
        data['canal'],
        data.get('duracion')
    ))
    conn.commit()
    return jsonify({'message': 'Video agregado a favoritos'})

@app.route('/favoritos', methods=['GET'])
@token_requerido
def listar_favoritos():
    conn = get_db()
    favoritos = conn.execute("""
        SELECT video_id, titulo, thumbnail, canal, duracion, fecha_guardado
        FROM favoritos
        WHERE user_id = ?
    """, (g.user_id,)).fetchall()

    return jsonify([dict(row) for row in favoritos])

@app.route('/favoritos/<video_id>', methods=['DELETE'])
@token_requerido
def eliminar_favorito(video_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        DELETE FROM favoritos 
        WHERE user_id = ? AND video_id = ?
    """, (g.user_id, video_id))
    conn.commit()

    if cursor.rowcount == 0:
        return jsonify({'message': 'No se encontró ese video en tus favoritos'}), 404

    return jsonify({'message': 'Video eliminado de favoritos'})


@app.route('/verificar-correo', methods=['POST'])
def verificar_correo():
    data = request.json
    correo = data.get('correo')

    if not correo:
        return jsonify({'error': 'Correo requerido'}), 400

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE correo = ?", (correo,)).fetchone()

    if user:
        return jsonify({'existe': True, 'user_id': user[0], 'nombre_usuario': user[3]})
    else:
        return jsonify({'existe': False}), 404

@app.route('/cambiar-contrasena', methods=['POST'])
def cambiar_contrasena():
    data = request.json
    correo = data.get('correo')
    nueva_contrasena = data.get('nuevacontrasena')

    if not correo or not nueva_contrasena:
        return jsonify({'error': 'Correo y nueva contraseña requeridos'}), 400

    hashed_password = generate_password_hash(nueva_contrasena)

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET contrasena = ? WHERE correo = ?", (hashed_password, correo))
    conn.commit()

    if cursor.rowcount == 0:
        return jsonify({'error': 'Correo no encontrado'}), 404

    return jsonify({'message': 'Contraseña actualizada exitosamente'})


if __name__ == '__main__':
    app.run(debug=True)
