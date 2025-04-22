from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import psycopg2
from psycopg2.extras import DictCursor
import secrets
import datetime
import logging
import time
import random
import string
import json
import hashlib
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# Configuração de Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
CORS(app, resources={
    r"/*": {
        "origins": "*",
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization", "Access-Control-Allow-Origin"],
        "expose_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True
    }
})

# Porta para o servidor
port = int(os.environ.get("PORT", 5000))

# Função para obter conexão com o banco de dados PostgreSQL
def get_db_connection():
    # Obter string de conexão da variável de ambiente
    DATABASE_URL = os.environ.get('DATABASE_URL')
    
    if not DATABASE_URL:
        raise Exception("DATABASE_URL não está definida nas variáveis de ambiente")
    
    logging.info(f"Conectando ao banco de dados: {DATABASE_URL[:20]}...") # Log parcial para não mostrar credenciais
    
    # Conectar ao PostgreSQL
    conn = psycopg2.connect(DATABASE_URL)
    
    # Configurar para retornar resultados como dicionários
    conn.cursor_factory = psycopg2.extras.DictCursor
    
    return conn

# Função para obter timestamp atual
def get_timestamp():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# Função para gerar um HWID simulado (caso o cliente não envie)
def generate_hwid():
    return str(uuid.uuid4())

# Middleware para autenticação de administradores
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        hwid = data.get('hwid')
        
        # Verificar se os dados necessários foram fornecidos
        if not username or not password:
            return jsonify({"success": False, "message": "Credenciais de administrador necessárias"}), 401
        
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            
            # Verificar se o usuário existe e é admin
            cur.execute("""
                SELECT * FROM users 
                WHERE username = %s AND password = %s AND is_admin = TRUE
            """, (username, password))
            
            admin = cur.fetchone()
            
            cur.close()
            conn.close()
            
            if not admin:
                return jsonify({"success": False, "message": "Acesso de administrador necessário"}), 403
                
            # Se o HWID for fornecido, verificar se corresponde
            if hwid and admin['hwid'] != '0' and hwid != admin['hwid']:
                return jsonify({"success": False, "message": "HWID não corresponde ao registrado"}), 403
                
            # Tudo ok, prosseguir com a função original
            return f(*args, **kwargs)
            
        except Exception as e:
            logging.error(f"Erro na autenticação de admin: {str(e)}")
            return jsonify({"success": False, "message": f"Erro na autenticação: {str(e)}"}), 500
            
    return decorated_function

# Middleware para logging
@app.before_request
def log_request_info():
    logging.info(f"Requisição recebida: {request.method} {request.url}")
    logging.info(f"Headers: {dict(request.headers)}")
    if request.is_json:
        logging.info(f"Body: {request.get_json()}")

# Rota para verificar se o servidor está online
@app.route('/ping', methods=['GET'])
def ping():
    return jsonify({"status": "ok", "message": "Servidor online!"})

# Rota de login
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    hwid = data.get('hwid', generate_hwid())  # Usa o HWID fornecido ou gera um
    
    # Verificações de dados
    if not username or not password:
        return jsonify({"success": False, "message": "Dados incompletos"})
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Verificar se o usuário existe
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        
        if not user:
            cur.close()
            conn.close()
            return jsonify({"success": False, "message": "Usuário ou senha incorretos"})
        
        # Verificar a senha
        if user['password'] != password:  # Ideal seria usar password hashing
            cur.close()
            conn.close()
            return jsonify({"success": False, "message": "Usuário ou senha incorretos"})
        
        # Verificar HWID se não for admin
        if not user['is_admin'] and user['hwid'] and user['hwid'] != '0' and user['hwid'] != hwid:
            cur.close()
            conn.close()
            return jsonify({
                "success": False, 
                "message": "HWID incorreto. Você não pode usar esta licença neste computador."
            })
        
        # Se o usuário não tiver HWID, atualize-o
        if not user['hwid'] or user['hwid'] == '0':
            cur.execute("UPDATE users SET hwid = %s WHERE username = %s", (hwid, username))
            conn.commit()
        
        # Verificar expiração
        is_expired = False
        expiration_date = user['expiration_date']
        expiration_str = None
        
        if expiration_date:
            is_expired = datetime.datetime.now() > expiration_date
            expiration_str = expiration_date.strftime("%d/%m/%Y %H:%M:%S")
            
            if is_expired and not user['is_admin']:
                cur.close()
                conn.close()
                return jsonify({
                    "success": False, 
                    "message": "Sua licença expirou em " + expiration_str
                })
        
        cur.close()
        conn.close()
        
        return jsonify({
            "success": True,
            "message": "Login bem-sucedido",
            "username": user['username'],
            "isAdmin": user['is_admin'],
            "expirationDate": expiration_str
        })
        
    except Exception as e:
        logging.error(f"Erro no login: {str(e)}")
        if 'conn' in locals():
            if 'cur' in locals():
                cur.close()
            conn.close()
        return jsonify({"success": False, "message": f"Erro no login: {str(e)}"})

# Rota de registro
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    key = data.get('key')
    hwid = data.get('hwid', generate_hwid())  # Usa o HWID fornecido ou gera um
    
    # Verificações de dados
    if not username or not password or not key:
        return jsonify({"success": False, "message": "Dados incompletos"})
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Verificar se o usuário já existe
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        if cur.fetchone():
            cur.close()
            conn.close()
            return jsonify({"success": False, "message": "Nome de usuário já existe"})
        
        # Verificar se a chave é válida
        cur.execute("SELECT * FROM keys WHERE key_value = %s AND is_used = FALSE", (key,))
        key_record = cur.fetchone()
        
        if not key_record:
            cur.close()
            conn.close()
            return jsonify({"success": False, "message": "Chave inválida ou já utilizada"})
        
        # Obter data de expiração e status admin da chave
        expiration_date = key_record['expiration_date']
        is_admin_key = key_record.get('is_admin_key', False)
        
        # Criar o usuário
        cur.execute("""
            INSERT INTO users (username, password, hwid, expiration_date, is_admin, created_at) 
            VALUES (%s, %s, %s, %s, %s, %s) RETURNING id
        """, (username, password, hwid, expiration_date, is_admin_key, datetime.datetime.now()))
        
        user_id = cur.fetchone()[0]
        
        # Marcar a chave como usada
        cur.execute("""
            UPDATE keys SET 
                is_used = TRUE, 
                used_by = %s, 
                used_at = %s, 
                user_id = %s
            WHERE key_value = %s
        """, (username, datetime.datetime.now(), user_id, key))
        
        conn.commit()
        cur.close()
        conn.close()
        
        return jsonify({
            "success": True,
            "message": "Registro concluído com sucesso!"
        })
        
    except Exception as e:
        logging.error(f"Erro no registro: {str(e)}")
        if 'conn' in locals():
            conn.rollback()
            if 'cur' in locals():
                cur.close()
            conn.close()
        return jsonify({"success": False, "message": f"Erro no registro: {str(e)}"})

# Rota para gerar chaves (apenas admin)
@app.route('/generate_keys', methods=['POST'])
@admin_required
def generate_keys():
    data = request.get_json()
    generated_by = data.get('username')  # Username do admin
    quantidade = data.get('quantidade', 1)
    duracao_dias = data.get('duracao_dias', 30)
    is_admin_key = data.get('is_admin_key', False)
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Gerar as chaves
        generated_keys = []
        expiration_date = datetime.datetime.now() + datetime.timedelta(days=duracao_dias)
        
        for _ in range(quantidade):
            # Gerar uma nova key
            if duracao_dias == 999999:  # Key permanente
                key = f"BRAVOS-{''.join(random.choices(string.ascii_uppercase + string.digits, k=5))}-{''.join(random.choices(string.ascii_uppercase + string.digits, k=5))}-PERM"
            else:
                key = f"BRAVOS-{''.join(random.choices(string.ascii_uppercase + string.digits, k=5))}-{''.join(random.choices(string.ascii_uppercase + string.digits, k=5))}-{duracao_dias}D"
            
            # Salvar a chave no banco
            cur.execute("""
                INSERT INTO keys (key_value, expiration_date, created_at, generated_by, duration_days, is_admin_key)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING key_value
            """, (key, expiration_date, datetime.datetime.now(), generated_by, duracao_dias, is_admin_key))
            
            # Adicionar à lista de chaves geradas
            generated_keys.append({
                "key": key,
                "expiration_date": expiration_date.strftime("%d/%m/%Y") if duracao_dias != 999999 else "Permanente"
            })
        
        conn.commit()
        cur.close()
        conn.close()
        
        return jsonify({
            "success": True,
            "message": f"{quantidade} chave(s) gerada(s) com sucesso",
            "keys": generated_keys
        })
        
    except Exception as e:
        logging.error(f"Erro ao gerar keys: {str(e)}")
        if 'conn' in locals():
            conn.rollback()
            if 'cur' in locals():
                cur.close()
            conn.close()
        return jsonify({"success": False, "message": f"Erro ao gerar keys: {str(e)}"})

# Rota para obter todas as keys (apenas admin)
@app.route('/get_all_keys', methods=['POST'])
@admin_required
def get_all_keys():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Buscar todas as chaves
        cur.execute("""
            SELECT 
                k.id,
                k.key_value,
                k.expiration_date,
                k.created_at,
                k.is_used,
                k.used_by,
                k.used_at,
                k.generated_by,
                k.duration_days,
                k.is_admin_key,
                u.hwid
            FROM 
                keys k
                LEFT JOIN users u ON k.used_by = u.username
            ORDER BY 
                k.created_at DESC
        """)
        
        keys_data = []
        for key in cur.fetchall():
            # Verificar status da key
            status = "Não Usada"
            if key['is_used']:
                status = "Usada"
                if key['expiration_date'] and datetime.datetime.now() > key['expiration_date']:
                    status = "Expirada"
            
            keys_data.append({
                "id": key['id'],
                "key": key['key_value'],
                "expiration_date": key['expiration_date'].strftime("%d/%m/%Y") if key['expiration_date'] else "Permanente",
                "created_at": key['created_at'].strftime("%d/%m/%Y %H:%M:%S"),
                "is_used": key['is_used'],
                "used_by": key['used_by'] or "Não Usada",
                "used_at": key['used_at'].strftime("%d/%m/%Y %H:%M:%S") if key['used_at'] else None,
                "generated_by": key['generated_by'],
                "duration_days": key['duration_days'],
                "is_admin_key": key['is_admin_key'],
                "status": status,
                "hwid": key['hwid'] if key['hwid'] else None
            })
        
        cur.close()
        conn.close()
        
        return jsonify({
            "success": True,
            "keys": keys_data
        })
        
    except Exception as e:
        logging.error(f"Erro ao obter keys: {str(e)}")
        if 'conn' in locals():
            if 'cur' in locals():
                cur.close()
            conn.close()
        return jsonify({"success": False, "message": f"Erro ao obter keys: {str(e)}"})

# Rota para ativar uma key (apenas admin)
@app.route('/activate_key', methods=['POST'])
@admin_required
def activate_key():
    data = request.get_json()
    key_value = data.get('key')
    
    if not key_value:
        return jsonify({"success": False, "message": "Chave não fornecida"}), 400
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Verificar se a chave existe
        cur.execute("SELECT id FROM keys WHERE key_value = %s", (key_value,))
        key_record = cur.fetchone()
        
        if not key_record:
            cur.close()
            conn.close()
            return jsonify({"success": False, "message": "Chave não encontrada"}), 404
        
        # Ativar a chave
        cur.execute("""
            UPDATE keys SET 
                is_active = TRUE,
                updated_at = %s
            WHERE key_value = %s
        """, (datetime.datetime.now(), key_value))
        
        conn.commit()
        cur.close()
        conn.close()
        
        return jsonify({
            "success": True,
            "message": f"Chave {key_value} ativada com sucesso"
        })
        
    except Exception as e:
        logging.error(f"Erro ao ativar key: {str(e)}")
        if 'conn' in locals():
            conn.rollback()
            if 'cur' in locals():
                cur.close()
            conn.close()
        return jsonify({"success": False, "message": f"Erro ao ativar key: {str(e)}"})

# Rota para bloquear uma key (apenas admin)
@app.route('/block_key', methods=['POST'])
@admin_required
def block_key():
    data = request.get_json()
    key_value = data.get('key')
    
    if not key_value:
        return jsonify({"success": False, "message": "Chave não fornecida"}), 400
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Verificar se a chave existe
        cur.execute("SELECT id FROM keys WHERE key_value = %s", (key_value,))
        key_record = cur.fetchone()
        
        if not key_record:
            cur.close()
            conn.close()
            return jsonify({"success": False, "message": "Chave não encontrada"}), 404
        
        # Bloquear a chave
        cur.execute("""
            UPDATE keys SET 
                is_active = FALSE,
                updated_at = %s
            WHERE key_value = %s
        """, (datetime.datetime.now(), key_value))
        
        conn.commit()
        cur.close()
        conn.close()
        
        return jsonify({
            "success": True,
            "message": f"Chave {key_value} bloqueada com sucesso"
        })
        
    except Exception as e:
        logging.error(f"Erro ao bloquear key: {str(e)}")
        if 'conn' in locals():
            conn.rollback()
            if 'cur' in locals():
                cur.close()
            conn.close()
        return jsonify({"success": False, "message": f"Erro ao bloquear key: {str(e)}"})

# Rota para resetar HWID (apenas admin)
@app.route('/reset_hwid', methods=['POST'])
@admin_required
def reset_hwid():
    data = request.get_json()
    target_username = data.get('target_username')
    
    if not target_username:
        return jsonify({"success": False, "message": "Nome de usuário não fornecido"}), 400
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Verificar se o usuário existe
        cur.execute("SELECT id FROM users WHERE username = %s", (target_username,))
        user = cur.fetchone()
        
        if not user:
            cur.close()
            conn.close()
            return jsonify({"success": False, "message": "Usuário não encontrado"}), 404
        
        # Resetar o HWID
        cur.execute("""
            UPDATE users SET 
                hwid = '0',
                updated_at = %s
            WHERE username = %s
        """, (datetime.datetime.now(), target_username))
        
        conn.commit()
        cur.close()
        conn.close()
        
        return jsonify({
            "success": True,
            "message": f"HWID do usuário {target_username} resetado com sucesso"
        })
        
    except Exception as e:
        logging.error(f"Erro ao resetar HWID: {str(e)}")
        if 'conn' in locals():
            conn.rollback()
            if 'cur' in locals():
                cur.close()
            conn.close()
        return jsonify({"success": False, "message": f"Erro ao resetar HWID: {str(e)}"})

# Rota para obter todos os usuários (apenas admin)
@app.route('/get_all_users', methods=['POST'])
@admin_required
def get_all_users():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Buscar todos os usuários
        cur.execute("""
            SELECT 
                id,
                username,
                hwid,
                created_at,
                expiration_date,
                is_admin,
                last_login
            FROM 
                users
            ORDER BY 
                created_at DESC
        """)
        
        users_data = []
        for user in cur.fetchall():
            status = "Ativo"
            if user['expiration_date'] and datetime.datetime.now() > user['expiration_date']:
                status = "Expirado"
            
            users_data.append({
                "id": user['id'],
                "username": user['username'],
                "hwid": user['hwid'] or "Não definido",
                "created_at": user['created_at'].strftime("%d/%m/%Y %H:%M:%S") if user['created_at'] else None,
                "expiration_date": user['expiration_date'].strftime("%d/%m/%Y") if user['expiration_date'] else "Sem expiração",
                "is_admin": user['is_admin'],
                "status": status,
                "last_login": user['last_login'].strftime("%d/%m/%Y %H:%M:%S") if user['last_login'] else "Nunca"
            })
        
        cur.close()
        conn.close()
        
        return jsonify({
            "success": True,
            "users": users_data
        })
        
    except Exception as e:
        logging.error(f"Erro ao obter usuários: {str(e)}")
        if 'conn' in locals():
            if 'cur' in locals():
                cur.close()
            conn.close()
        return jsonify({"success": False, "message": f"Erro ao obter usuários: {str(e)}"})

# Rota para validar uma chave (verificar se é válida)
@app.route('/validate_key', methods=['POST'])
def validate_key():
    data = request.get_json()
    key = data.get('key')
    
    if not key:
        return jsonify({"success": False, "message": "Chave não fornecida"}), 400
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Verificar se a chave existe e não foi usada
        cur.execute("""
            SELECT 
                key_value,
                expiration_date,
                is_used,
                is_active,
                duration_days
            FROM 
                keys
            WHERE 
                key_value = %s
        """, (key,))
        
        key_record = cur.fetchone()
        
        cur.close()
        conn.close()
        
        if not key_record:
            return jsonify({"success": False, "message": "Chave não encontrada"}), 404
        
        if key_record['is_used']:
            return jsonify({"success": False, "message": "Esta chave já foi utilizada"}), 400
        
        if not key_record.get('is_active', True):
            return jsonify({"success": False, "message": "Esta chave está bloqueada"}), 400
        
        return jsonify({
            "success": True,
            "message": "Chave válida",
            "key": key_record['key_value'],
            "duration_days": key_record['duration_days'],
            "expiration_date": key_record['expiration_date'].strftime("%d/%m/%Y") if key_record['expiration_date'] else "Permanente"
        })
        
    except Exception as e:
        logging.error(f"Erro ao validar chave: {str(e)}")
        if 'conn' in locals():
            if 'cur' in locals():
                cur.close()
            conn.close()
        return jsonify({"success": False, "message": f"Erro ao validar chave: {str(e)}"})

# Inicialização do servidor
if __name__ == '__main__':
    # Logs de inicialização
    logging.info("Servidor iniciando...")
    logging.info(f"Porta configurada: {port}")
    
    # Iniciar o servidor
    app.run(host='0.0.0.0', port=port, debug=True) 
