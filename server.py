from flask import Flask, request, jsonify
from flask_cors import CORS
import os
from dotenv import load_dotenv
import psycopg2
import psycopg2.extras
import datetime
import logging
import time

load_dotenv()

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

# Configuração do PostgreSQL para Render
DATABASE_URL = os.environ.get("DATABASE_URL")
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

port = int(os.environ.get("PORT", 5000))

def get_db_connection():
    """Retorna uma conexão com o banco de dados PostgreSQL"""
    conn = psycopg2.connect(DATABASE_URL)
    return conn

@app.before_request
def start_timer():
    """Inicia um temporizador para medir o tempo de resposta"""
    request.start_time = time.time()

@app.after_request
def log_response_time(response):
    """Registra o tempo que levou para responder à solicitação"""
    duration = time.time() - getattr(request, 'start_time', time.time())
    logging.info(f"Resposta enviada: {response.status} em {duration:.2f} segundos")
    return response

@app.before_request
def log_request_info():
    """Registra informações sobre a solicitação recebida"""
    logging.info(f"Requisição recebida: {request.method} {request.url}")
    logging.info(f"Headers: {dict(request.headers)}")
    logging.info(f"Body: {request.get_data(as_text=True)}")

@app.before_request
def verify_content_type():
    """Verifica se o Content-Type está correto para solicitações POST"""
    if request.method == "POST":
        if not request.is_json:
            return jsonify({
                "success": False,
                "message": "Content-Type deve ser application/json"
            }), 415

# ==================== ROTAS ESSENCIAIS ====================

@app.route('/ping', methods=['GET'])
def ping():
    """Rota para verificar se o servidor está online"""
    return jsonify({"status": "ok", "message": "Servidor online!"})

@app.route('/login', methods=['POST'])
def login():
    """Rota para autenticar um usuário"""
    # Verificar se a requisição é JSON
    if not request.is_json:
        logging.warning("Requisição de login sem Content-Type application/json")
        return jsonify({"success": False, "message": "Conteúdo deve ser enviado como JSON"}), 415
    
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')
        hwid = data.get('hwid')
        vmid = data.get('vmid', '')
        
        if not username or not password:
            return jsonify({"success": False, "message": "Dados incompletos"}), 400
        
        # Verificar credenciais
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cur.execute("SELECT * FROM users WHERE username = %s AND password = %s", [username, password])
        user = cur.fetchone()
        
        if not user:
            cur.close()
            conn.close()
            return jsonify({"success": False, "message": "Usuário ou senha incorretos"}), 401
        
        # Verificar hwid OU vmid (se um dos dois bater, permite o login)
        hwid_match = (hwid == user['hwid'])
        vmid_match = (vmid == user['vmid'] and vmid != '')
        hwid_is_zero = (user['hwid'] == '0')  # Caso especial para o admin
        
        logging.info(f"Login: HWID match: {hwid_match}, VMID match: {vmid_match}, HWID zero: {hwid_is_zero}")
        
        if not (hwid_match or vmid_match or hwid_is_zero):
            cur.close()
            conn.close()
            return jsonify({"success": False, "message": "HWID/VMID incorretos. Você não pode usar esta licença neste computador."}), 403
        
        # Atualizar hwid/vmid se necessário (se o login foi bem-sucedido por vmid mas hwid não bate)
        if vmid_match and not hwid_match and not hwid_is_zero:
            try:
                cur.execute("UPDATE users SET hwid = %s WHERE username = %s", [hwid, username])
                conn.commit()
                logging.info(f"HWID atualizado para o usuário {username}: {hwid}")
            except Exception as e:
                conn.rollback()
                logging.error(f"Erro ao atualizar HWID: {str(e)}")
        
        # Extrair data de expiração
        expiration_date = user['expiration_date']
        expiration_str = None
        
        if expiration_date:
            expiration_str = int(expiration_date.timestamp())  # Converter para timestamp UNIX
        
        # Fechar recursos
        cur.close()
        conn.close()
        
        # Registrar login bem-sucedido
        logging.info(f"Login bem-sucedido para o usuário: {username}")
        
        # Login bem-sucedido
        return jsonify({
            "success": True,
            "message": "Login bem-sucedido",
            "username": user['username'],
            "isAdmin": user.get('is_admin', False),
            "expirationDate": expiration_str
        })
    except Exception as e:
        logging.error(f"Erro no login: {str(e)}")
        if 'conn' in locals() and 'cur' in locals():
            cur.close()
            conn.close()
        return jsonify({"success": False, "message": f"Erro de servidor: {str(e)}"}), 500

@app.route('/register', methods=['POST'])
def register():
    """Rota para registrar um novo usuário"""
    # Verificar se o request está no formato correto
    if not request.is_json:
        logging.warning("Requisição de registro sem Content-Type application/json")
        return jsonify({"success": False, "message": "Conteúdo deve ser enviado como JSON (application/json)"}), 415
    
    try:
        data = request.json
        logging.info(f"Dados de registro recebidos: {data}")
        
        # Extrair campos
        username = data.get('username')
        password = data.get('password')
        discord_id = data.get('discord_id', '')  # ID do Discord é opcional
        key = data.get('key')
        hwid = data.get('hwid')
        vmid = data.get('vmid', '')  # Valor padrão para vmid se não fornecido
        
        # Verificações de dados obrigatórios
        if not username:
            return jsonify({"success": False, "message": "Nome de usuário é obrigatório"}), 400
        if not key:
            return jsonify({"success": False, "message": "Chave de registro é obrigatória"}), 400
        if not hwid:
            return jsonify({"success": False, "message": "HWID é obrigatório"}), 400
            
        # Senha não precisa mais de validação de comprimento mínimo
        if not password:
            password = ""  # Se a senha estiver em branco, usar string vazia
        
        logging.info(f"Verificando chave de registro: {key}")
        
        # Verificação da chave
        conn = get_db_connection()
        # Usar DictCursor para acessar os resultados como dicionário
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cur.execute("SELECT * FROM keys WHERE key_value = %s AND is_used = false", [key])
        key_record = cur.fetchone()
        
        if not key_record:
            cur.close()
            conn.close()
            logging.warning(f"Tentativa de registro com chave inválida: {key}")
            return jsonify({"success": False, "message": "Chave inválida ou já utilizada"}), 400
        
        # Verificar usuário existente
        cur.execute("SELECT * FROM users WHERE username = %s", [username])
        if cur.fetchone():
            cur.close()
            conn.close()
            logging.warning(f"Tentativa de registro com nome de usuário já existente: {username}")
            return jsonify({"success": False, "message": "Nome de usuário já existe"}), 409
        
        # Obter data de expiração e configurações da chave
        expiration_date = key_record['expiration_date']
        is_admin_key = key_record['is_admin_key']
        
        # Registrar usuário com a data de expiração da chave
        try:
            # Usar campo discord_id se existir na tabela, caso contrário usar email
            try:
                # Tentar inserir com discord_id
                cur.execute(
                    "INSERT INTO users (username, password, discord_id, hwid, vmid, expiration_date, is_admin) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    [username, password, discord_id, hwid, vmid, expiration_date, is_admin_key]
                )
            except psycopg2.errors.UndefinedColumn:
                # Se discord_id não existir, tentar com email
                cur.execute(
                    "INSERT INTO users (username, password, email, hwid, vmid, expiration_date, is_admin) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    [username, password, discord_id, hwid, vmid, expiration_date, is_admin_key]
                )
                
            cur.execute("UPDATE keys SET is_used = true, used_by = %s, used_at = CURRENT_TIMESTAMP WHERE key_value = %s", 
                        [username, key])
            conn.commit()
            
            # Formatando a data para log
            expiry_str = "sem expiração" if not expiration_date else expiration_date.strftime("%d/%m/%Y %H:%M:%S")
            logging.info(f"Usuário {username} registrado com sucesso. Data de expiração: {expiry_str}")
            
            # Resposta de sucesso
            return jsonify({
                "success": True, 
                "message": "Registro concluído com sucesso!",
                "expirationDate": expiry_str if expiration_date else None
            }), 201
            
        except Exception as e:
            conn.rollback()
            logging.error(f"Erro no banco de dados ao registrar usuário {username}: {str(e)}")
            return jsonify({"success": False, "message": f"Erro ao registrar: {str(e)}"}), 500
    
    except Exception as e:
        logging.error(f"Erro inesperado no registro: {str(e)}")
        return jsonify({"success": False, "message": f"Erro no processamento do registro: {str(e)}"}), 500
    
    finally:
        if 'cur' in locals():
            cur.close()
        if 'conn' in locals():
            conn.close()

@app.route('/registrar_click', methods=['POST'])
def registrar_click():
    """Registra cliques dos botões SPOOF e LIMPAR FIVEM"""
    try:
        logging.info(f"Requisição recebida em registrar_click: {request.get_data(as_text=True)}")
        logging.info(f"Cabeçalhos: {dict(request.headers)}")
        
        if not request.is_json:
            logging.error("A requisição não é JSON (Content-Type incorreto ou corpo inválido)")
            return jsonify({
                "success": False,
                "message": "Content-Type deve ser application/json"
            }), 415
        
        data = request.get_json()
        logging.info(f"JSON recebido: {data}")
        tipo = data.get('tipo')  # 'spoof' ou 'fivem_clean'
        logging.info(f"Tipo extraído: {tipo}")
        
        if not tipo or tipo not in ['spoof', 'fivem_clean']:
            logging.error(f"Tipo de operação inválido: {tipo}")
            return jsonify({
                "success": False,
                "message": "Tipo de operação inválido"
            }), 400
            
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Atualiza o contador correspondente
        if tipo == 'spoof':
            cur.execute("""
                UPDATE configuracoes_sistema 
                SET total_spoofs = total_spoofs + 1, 
                    ultima_atualizacao = CURRENT_TIMESTAMP 
                WHERE id = 1
                RETURNING total_spoofs
            """)
            novo_valor = cur.fetchone()[0]
        else:  # fivem_clean
            cur.execute("""
                UPDATE configuracoes_sistema 
                SET total_fivem_cleans = total_fivem_cleans + 1, 
                    ultima_atualizacao = CURRENT_TIMESTAMP 
                WHERE id = 1
                RETURNING total_fivem_cleans
            """)
            novo_valor = cur.fetchone()[0]
            
        conn.commit()
        
        return jsonify({
            "success": True,
            "message": f"Click de {tipo} registrado com sucesso",
            "novo_valor": novo_valor
        }), 200
    
    except Exception as e:
        logging.error(f"Erro ao registrar click: {str(e)}")
        if 'conn' in locals():
            conn.rollback()
        return jsonify({
            "success": False,
            "message": f"Erro ao registrar click: {str(e)}"
        }), 500
    finally:
        if 'cur' in locals():
            cur.close()
        if 'conn' in locals():
            conn.close()

@app.route('/estatisticas', methods=['GET'])
def obter_estatisticas():
    """Obter estatísticas de uso do sistema (total de spoofs e limpezas)"""
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        # Buscar as estatísticas
        cur.execute("""
            SELECT ultima_atualizacao, total_spoofs, total_fivem_cleans 
            FROM configuracoes_sistema 
            WHERE id = 1
        """)
        
        resultado = cur.fetchone()
        
        if resultado:
            # Formatar a data
            data_formatada = resultado['ultima_atualizacao'].strftime("%d/%m/%Y")
            
            return jsonify({
                "success": True,
                "atualizado": data_formatada,
                "spoofs": resultado['total_spoofs'],
                "fivem_cleans": resultado['total_fivem_cleans']
            }), 200
        else:
            return jsonify({
                "success": False,
                "message": "Nenhuma estatística encontrada"
            }), 404
    
    except Exception as e:
        logging.error(f"Erro ao obter estatísticas: {str(e)}")
        return jsonify({
            "success": False,
            "message": f"Erro ao obter estatísticas: {str(e)}"
        }), 500
    finally:
        if 'cur' in locals():
            cur.close()
        if 'conn' in locals():
            conn.close()

@app.route('/inicializar_estatisticas', methods=['GET'])
def inicializar_estatisticas():
    """Endpoint para compatibilidade com o cliente existente"""
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        # Buscar as estatísticas atuais
        cur.execute("""
            SELECT total_spoofs, total_fivem_cleans 
            FROM configuracoes_sistema 
            WHERE id = 1
        """)
        
        resultado = cur.fetchone()
        
        cur.close()
        conn.close()
        
        if resultado:
            return jsonify({
                "success": True,
                "message": "Estatísticas já inicializadas",
                "spoofs": resultado['total_spoofs'],
                "fivem_cleans": resultado['total_fivem_cleans']
            }), 200
        else:
            return jsonify({
                "success": False,
                "message": "Nenhuma estatística encontrada"
            }), 404
    
    except Exception as e:
        logging.error(f"Erro ao verificar estatísticas: {str(e)}")
        if 'conn' in locals():
            if 'cur' in locals():
                cur.close()
            conn.close()
        return jsonify({
            "success": False,
            "message": f"Erro ao verificar estatísticas: {str(e)}"
        }), 500

# Tratamento geral de erros
@app.errorhandler(Exception)
def handle_exception(e):
    logging.error(f"Erro não tratado: {str(e)}", exc_info=True)
    logging.error(f"Requisição que causou o erro: {request.method} {request.url}")
    if request.is_json:
        logging.error(f"Dados JSON recebidos: {request.get_json()}")
    return jsonify({"success": False, "message": f"Erro interno do servidor: {str(e)}"}), 500

# Rota principal
@app.route('/')
def index():
    return jsonify({
        "name": "MG Spoofer API",
        "version": "1.0.0",
        "status": "running",
        "endpoints": [
            "/ping",
            "/login",
            "/register",
            "/registrar_click",
            "/estatisticas",
            "/inicializar_estatisticas"
        ]
    })

if __name__ == '__main__':
    # Modo de desenvolvimento
    if os.environ.get('FLASK_ENV') == 'development':
        app.run(host='0.0.0.0', port=port, debug=True)
    else:
        # Modo de produção
        app.run(host='0.0.0.0', port=port) 
