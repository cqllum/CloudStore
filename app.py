from flask import Flask, request, jsonify, session, render_template, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import json
import hashlib
import os
from datetime import datetime
import threading
import queue
import time

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'CHANGE-THIS-SECRET-KEY-IN-PRODUCTION')
if app.secret_key == 'CHANGE-THIS-SECRET-KEY-IN-PRODUCTION':
    print("⚠️  WARNING: Using default secret key! Please set SECRET_KEY environment variable.")
app.config['SESSION_COOKIE_SAMESITE'] = None
app.config['SESSION_COOKIE_SECURE'] = False

# Database connection pool
class DatabasePool:
    def __init__(self, db_path, pool_size=10):
        self.db_path = db_path
        self.pool = queue.Queue(maxsize=pool_size)
        self.lock = threading.Lock()
        
        # Pre-populate pool
        for _ in range(pool_size):
            conn = self._create_connection()
            self.pool.put(conn)
    
    def _create_connection(self):
        conn = sqlite3.connect(self.db_path, timeout=30, check_same_thread=False)
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA synchronous=NORMAL')
        conn.execute('PRAGMA cache_size=10000')
        conn.execute('PRAGMA temp_store=MEMORY')
        return conn
    
    def get_connection(self):
        try:
            return self.pool.get(timeout=5)
        except queue.Empty:
            return self._create_connection()
    
    def return_connection(self, conn):
        try:
            self.pool.put_nowait(conn)
        except queue.Full:
            conn.close()

db_pool = DatabasePool('cloudstore.db')

# Context manager for database operations
from contextlib import contextmanager

@contextmanager
def get_db():
    conn = db_pool.get_connection()
    try:
        yield conn
    finally:
        db_pool.return_connection(conn)

@app.after_request
def after_request(response):
    response.headers.pop('X-Frame-Options', None)
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response

# Initialize database
def init_db():
    conn = db_pool.get_connection()
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT, 
                  is_admin BOOLEAN DEFAULT 0, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  account_id TEXT UNIQUE)''')
    
    # Add account_id to existing users if column doesn't exist
    try:
        c.execute("ALTER TABLE users ADD COLUMN account_id TEXT UNIQUE")
        # Generate account_ids for existing users without one
        import uuid
        c.execute("SELECT id FROM users WHERE account_id IS NULL")
        users_without_account_id = c.fetchall()
        for (user_id,) in users_without_account_id:
            account_id = str(uuid.uuid4())[:8]
            c.execute("UPDATE users SET account_id = ? WHERE id = ?", (account_id, user_id))
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    # Storage brokers table
    c.execute('''CREATE TABLE IF NOT EXISTS brokers
                 (id INTEGER PRIMARY KEY, name TEXT, type TEXT, config TEXT, active BOOLEAN)''')
    
    # Files metadata table
    c.execute('''CREATE TABLE IF NOT EXISTS files
                 (id INTEGER PRIMARY KEY, filename TEXT, virtual_path TEXT, 
                  file_hash TEXT, size INTEGER, broker_id INTEGER, 
                  storage_path TEXT, created_at TIMESTAMP, user_id INTEGER)''')
    
    # File replicas table
    c.execute('''CREATE TABLE IF NOT EXISTS file_replicas
                 (id INTEGER PRIMARY KEY, file_id INTEGER, broker_id INTEGER, 
                  storage_path TEXT, is_primary BOOLEAN DEFAULT 0,
                  FOREIGN KEY(file_id) REFERENCES files(id),
                  FOREIGN KEY(broker_id) REFERENCES brokers(id))''')
    
    # System settings table
    c.execute('''CREATE TABLE IF NOT EXISTS settings
                 (key TEXT PRIMARY KEY, value TEXT)''')
    
    # Set default replica count
    c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('replica_count', '2')")
    
    # Set default broker refresh interval (in minutes)
    c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('broker_refresh_interval', '5')")
    
    # Set default whitelabel settings
    c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('site_name', 'CloudStore')")
    c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('site_description', 'Decentralized File Storage System')")
    c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('custom_css', '')")
    c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('primary_color', '#2563eb')")
    c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('sidebar_bg', '#1e293b')")
    c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('sidebar_text', '#cbd5e1')")
    c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('card_bg', '#ffffff')")
    c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('card_text', '#1f2937')")
    c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('background_color', '#f8fafc')")
    
    # Add admin columns to existing users table if they don't exist
    try:
        c.execute("ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT 0")
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    try:
        c.execute("ALTER TABLE users ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    # Add broker status columns
    try:
        c.execute("ALTER TABLE brokers ADD COLUMN last_checked TIMESTAMP")
    except sqlite3.OperationalError:
        pass
    
    try:
        c.execute("ALTER TABLE brokers ADD COLUMN status_active BOOLEAN DEFAULT 1")
    except sqlite3.OperationalError:
        pass
    
    try:
        c.execute("ALTER TABLE brokers ADD COLUMN total_space INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass
    
    try:
        c.execute("ALTER TABLE brokers ADD COLUMN available_space INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass
    
    try:
        c.execute("ALTER TABLE brokers ADD COLUMN actual_used INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass
    
    # Create default admin user if none exists
    c.execute("SELECT COUNT(*) FROM users WHERE is_admin = 1")
    if c.fetchone()[0] == 0:
        admin_hash = generate_password_hash('admin')
        c.execute("INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
                 ('admin', admin_hash, 1))
        print("Created default admin user: admin/admin")
    
    conn.commit()
    conn.close()

# Import cloud brokers
from cloud_brokers import get_broker

# Storage broker manager
class StorageBroker:
    def __init__(self, broker_id, broker_type, config):
        self.broker_id = broker_id
        self.broker_type = broker_type
        self.config = json.loads(config) if isinstance(config, str) else config
        self.broker = get_broker(broker_type, self.config)
    
    def upload_file(self, file_data, filename):
        return self.broker.upload_file(file_data, filename)
    
    def get_file(self, storage_path):
        return self.broker.download_file(storage_path)
    
    def list_contents(self, path=''):
        if hasattr(self.broker, 'list_files'):
            return self.broker.list_files(path)
        return []

# Smart allocation logic with load balancing
def select_brokers(replica_count=None):
    if replica_count is None:
        conn = sqlite3.connect('cloudstore.db')
        c = conn.cursor()
        c.execute("SELECT value FROM settings WHERE key = 'replica_count'")
        result = c.fetchone()
        replica_count = int(result[0]) if result else 2
        conn.close()
    conn = sqlite3.connect('cloudstore.db')
    c = conn.cursor()
    
    # Get active brokers ordered by usage
    c.execute("""
        SELECT b.id, b.name, COUNT(f.id) as file_count, COALESCE(SUM(f.size), 0) as total_size
        FROM brokers b
        LEFT JOIN files f ON b.id = f.broker_id
        WHERE b.active = 1 AND b.status_active = 1
        GROUP BY b.id, b.name
        ORDER BY total_size ASC, file_count ASC
        LIMIT ?
    """, (replica_count,))
    results = c.fetchall()
    conn.close()
    return [r[0] for r in results] if results else []

@app.route('/file_metadata')
def file_metadata():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    filename = request.args.get('filename')
    path = request.args.get('path')
    
    conn = sqlite3.connect('cloudstore.db')
    c = conn.cursor()
    
    # Get file info
    c.execute("""
        SELECT f.id, f.filename, f.virtual_path, f.size, f.created_at
        FROM files f
        WHERE f.filename = ? AND f.virtual_path = ? AND f.user_id = ?
    """, (filename, path, session['user_id']))
    
    file_data = c.fetchone()
    if not file_data:
        conn.close()
        return jsonify({'error': 'File not found'}), 404
    
    file_id = file_data[0]
    
    # Get all replicas
    c.execute("""
        SELECT b.name, b.type, r.storage_path, r.is_primary
        FROM file_replicas r
        JOIN brokers b ON r.broker_id = b.id
        WHERE r.file_id = ?
        ORDER BY r.is_primary DESC
    """, (file_id,))
    
    replicas = c.fetchall()
    conn.close()
    
    return jsonify({
        'filename': file_data[1],
        'virtual_path': file_data[2],
        'size': file_data[3],
        'created_at': file_data[4],
        'replicas': [{
            'broker_name': r[0],
            'broker_type': r[1],
            'storage_path': r[2],
            'is_primary': bool(r[3])
        } for r in replicas]
    })

@app.route('/download_file')
def download_file():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    filename = request.args.get('filename')
    path = request.args.get('path', '/')
    
    conn = sqlite3.connect('cloudstore.db')
    c = conn.cursor()
    
    # Get file info and try primary replica first
    c.execute("""
        SELECT f.id FROM files f
        WHERE f.filename = ? AND f.virtual_path = ? AND f.user_id = ?
    """, (filename, path, session['user_id']))
    
    file_result = c.fetchone()
    if not file_result:
        conn.close()
        return jsonify({'error': 'File not found'}), 404
    
    file_id = file_result[0]
    
    # Try to get primary replica first, then any replica
    c.execute("""
        SELECT r.storage_path, b.id, b.type, b.config, r.is_primary
        FROM file_replicas r
        JOIN brokers b ON r.broker_id = b.id
        WHERE r.file_id = ? AND b.status_active = 1
        ORDER BY r.is_primary DESC
        LIMIT 1
    """, (file_id,))
    
    replica_data = c.fetchone()
    conn.close()
    
    if not replica_data:
        return jsonify({'error': 'No active storage found for file'}), 404
    
    storage_path, broker_id, broker_type, config, is_primary = replica_data
    broker = StorageBroker(broker_id, broker_type, config)
    
    try:
        file_content = broker.get_file(storage_path)
        if not file_content:
            return jsonify({'error': 'File content is empty'}), 404
        
        from flask import Response
        return Response(
            file_content,
            mimetype='application/octet-stream',
            headers={
                'Content-Disposition': f'attachment; filename="{filename}"',
                'Content-Length': str(len(file_content))
            }
        )
    except Exception as e:
        return jsonify({'error': 'Download failed. Please try again later.'}), 500

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    conn = sqlite3.connect('cloudstore.db')
    c = conn.cursor()
    
    try:
        password_hash = generate_password_hash(password)
        c.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", 
                 (username, password_hash))
        conn.commit()
        return jsonify({'message': 'User registered successfully'})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already exists'}), 400
    finally:
        conn.close()

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    conn = sqlite3.connect('cloudstore.db')
    c = conn.cursor()
    c.execute("SELECT id, password_hash, username, is_admin FROM users WHERE username=?", (username,))
    user = c.fetchone()
    
    if user and check_password_hash(user[1], password):
        session['user_id'] = user[0]
        session['username'] = user[2]
        session['is_admin'] = user[3] == 1
        
        # Create user home directory if it doesn't exist
        if not user[3]:  # Not admin
            home_path = f'/home/{user[2]}/'
            c.execute("SELECT COUNT(*) FROM files WHERE filename = '.folder' AND virtual_path = ? AND user_id = ?",
                     (home_path, user[0]))
            if c.fetchone()[0] == 0:
                c.execute("""INSERT INTO files 
                             (filename, virtual_path, file_hash, size, broker_id, storage_path, created_at, user_id)
                             VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                         ('.folder', home_path, '', 0, None, '', datetime.now(), user[0]))
                conn.commit()
        
        conn.close()
        return jsonify({'message': 'Login successful'})
    
    conn.close()
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/add_broker', methods=['POST'])
def add_broker():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    name = data.get('name')
    broker_type = data.get('type', 'local')
    config = json.dumps(data.get('config', {}))
    
    conn = sqlite3.connect('cloudstore.db')
    c = conn.cursor()
    
    # Check for duplicate broker with same type and config
    c.execute("SELECT COUNT(*) FROM brokers WHERE type = ? AND config = ?", (broker_type, config))
    if c.fetchone()[0] > 0:
        conn.close()
        return jsonify({'error': 'Broker with identical credentials already exists'}), 400
    
    c.execute("INSERT INTO brokers (name, type, config, active) VALUES (?, ?, ?, ?)",
             (name, broker_type, config, True))
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Broker added successfully'})

@app.route('/brokers')
def list_brokers():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    conn = sqlite3.connect('cloudstore.db')
    c = conn.cursor()
    c.execute("SELECT id, name, type, active FROM brokers")
    brokers = c.fetchall()
    conn.close()
    
    return jsonify([{
        'id': b[0],
        'name': b[1],
        'type': b[2],
        'active': bool(b[3])
    } for b in brokers])

@app.route('/remove_broker', methods=['DELETE'])
def remove_broker():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    broker_id = data.get('id')
    
    conn = sqlite3.connect('cloudstore.db')
    c = conn.cursor()
    c.execute("DELETE FROM brokers WHERE id=?", (broker_id,))
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Broker removed successfully'})

@app.route('/browse_storage/<int:broker_id>')
def browse_storage(broker_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    path = request.args.get('path', '')
    
    conn = sqlite3.connect('cloudstore.db')
    c = conn.cursor()
    c.execute("SELECT name, type, config FROM brokers WHERE id=?", (broker_id,))
    broker_data = c.fetchone()
    conn.close()
    
    if not broker_data:
        return jsonify({'error': 'Broker not found'}), 404
    
    name, broker_type, config = broker_data
    broker = StorageBroker(broker_id, broker_type, config)
    
    try:
        contents = broker.broker.list_files(path) if hasattr(broker.broker, 'list_files') else []
        return jsonify({
            'broker_name': name,
            'broker_type': broker_type,
            'path': path,
            'contents': contents
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/delete_storage_file/<int:broker_id>', methods=['DELETE'])
def delete_storage_file(broker_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    file_path = data.get('path')
    
    conn = sqlite3.connect('cloudstore.db')
    c = conn.cursor()
    c.execute("SELECT type, config FROM brokers WHERE id=?", (broker_id,))
    broker_data = c.fetchone()
    conn.close()
    
    if not broker_data:
        return jsonify({'error': 'Broker not found'}), 404
    
    broker_type, config = broker_data
    broker = StorageBroker(broker_id, broker_type, config)
    
    try:
        broker.broker.delete_file(file_path)
        return jsonify({'message': 'File deleted successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    virtual_path = request.form.get('virtual_path', '/')
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # Generate file hash
    file_data = file.read()
    file_hash = hashlib.sha256(file_data).hexdigest()
    
    # Check storage limit (5GB)
    conn = sqlite3.connect('cloudstore.db')
    c = conn.cursor()
    c.execute("SELECT COALESCE(SUM(size), 0) FROM files WHERE user_id = ? AND filename != '.folder'", (session['user_id'],))
    current_usage = c.fetchone()[0]
    conn.close()
    
    if current_usage + len(file_data) > 5 * 1024 * 1024 * 1024:  # 5GB limit
        return jsonify({'error': 'Storage limit exceeded (5GB max)'}), 400
    
    # Select brokers for storage (primary + replicas)
    broker_ids = select_brokers()
    if not broker_ids:
        return jsonify({'error': 'No active brokers available'}), 500
    
    conn = sqlite3.connect('cloudstore.db')
    c = conn.cursor()
    
    # Store file metadata
    c.execute("""INSERT INTO files 
                 (filename, virtual_path, file_hash, size, broker_id, storage_path, created_at, user_id)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
             (file.filename, virtual_path, file_hash, len(file_data), 
              broker_ids[0], '', datetime.now(), session['user_id']))
    file_id = c.lastrowid

    
    # Upload to all selected brokers
    for i, broker_id in enumerate(broker_ids):
        c.execute("SELECT type, config FROM brokers WHERE id=?", (broker_id,))
        broker_data = c.fetchone()
        if broker_data:
            broker_type, broker_config = broker_data
            broker = StorageBroker(broker_id, broker_type, broker_config)
            # Get user account_id for folder structure
            c.execute("SELECT account_id FROM users WHERE id = ?", (session['user_id'],))
            result = c.fetchone()
            account_id = result[0] if result and result[0] else f"user_{session['user_id']}"
            
            storage_path = broker.upload_file(file_data, f"{account_id}/{file_hash}_{secure_filename(file.filename)}")
            
            # Store replica info
            c.execute("""INSERT INTO file_replicas 
                         (file_id, broker_id, storage_path, is_primary)
                         VALUES (?, ?, ?, ?)""",
                     (file_id, broker_id, storage_path, i == 0))
    
    conn.commit()

    conn.close()
    
    return jsonify({'message': f'File uploaded with {len(broker_ids)} replicas', 'file_hash': file_hash})

@app.route('/search')
def search_files():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    query = request.args.get('q', '')
    path = request.args.get('path', '')
    
    conn = sqlite3.connect('cloudstore.db')
    c = conn.cursor()
    
    sql = "SELECT filename, virtual_path, size, created_at FROM files WHERE user_id=?"
    params = [session['user_id']]
    
    if query:
        sql += " AND filename LIKE ?"
        params.append(f"%{query}%")
    
    if path:
        sql += " AND virtual_path LIKE ?"
        params.append(f"{path}%")
    
    c.execute(sql, params)
    files = c.fetchall()
    conn.close()
    
    return jsonify([{
        'filename': f[0],
        'virtual_path': f[1],
        'size': f[2],
        'created_at': f[3]
    } for f in files])

@app.route('/files')
def list_files():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    path = request.args.get('path', '/')
    
    # Ensure user has home directory prefix
    conn = sqlite3.connect('cloudstore.db')
    c = conn.cursor()
    c.execute("SELECT username, is_admin FROM users WHERE id=?", (session['user_id'],))
    user_data = c.fetchone()
    
    if not user_data:
        conn.close()
        return jsonify({'error': 'User not found'}), 404
    
    username, is_admin = user_data
    
    # For regular users requesting root, check both root and home directory
    if not is_admin and path == '/':
        # First check root path for files
        c.execute("""SELECT f.filename, f.virtual_path, f.size, f.created_at, f.broker_id
                     FROM files f
                     WHERE f.user_id=? AND f.virtual_path = '/' AND f.filename != '.folder'""",
                 (session['user_id'],))
        root_files = c.fetchall()
        
        if root_files:
            # Files exist in root, use root path
            files = root_files
        else:
            # No files in root, try home directory
            user_home = f'/home/{username}/'
            path = user_home
            c.execute("""SELECT f.filename, f.virtual_path, f.size, f.created_at, f.broker_id
                         FROM files f
                         WHERE f.user_id=? AND f.virtual_path = ? AND f.filename != '.folder'""",
                     (session['user_id'], path))
            files = c.fetchall()
    else:
        # Admin or specific path request
        c.execute("""SELECT f.filename, f.virtual_path, f.size, f.created_at, f.broker_id
                     FROM files f
                     WHERE f.user_id=? AND f.virtual_path = ? AND f.filename != '.folder'""",
                 (session['user_id'], path))
        files = c.fetchall()
    

    
    # Files are already fetched above in the path handling logic

    

    
    # Get folders (look for .folder markers) - use the actual path being displayed
    c.execute("""SELECT virtual_path FROM files 
                 WHERE user_id=? AND filename = '.folder'""",
             (session['user_id'],))
    all_folders = c.fetchall()

    
    conn.close()
    
    result = {}
    
    # Add files
    for file_data in files:
        filename, vpath, size, created_at = file_data[:4]
        broker_id = file_data[4] if len(file_data) > 4 else None
        result[filename] = {
            'size': size,
            'created_at': created_at,
            'type': 'file',
            'broker_id': broker_id
        }
    
    # Add folders - use the actual path variable (which may have been updated)
    for (folder_path,) in all_folders:
        if folder_path.startswith(path) and folder_path != path:
            folder_name = folder_path[len(path):].rstrip('/')
            if folder_name and '/' not in folder_name:
                result[folder_name] = {'type': 'folder'}
    

    return jsonify(result)

@app.route('/storage_usage')
def storage_usage():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    conn = sqlite3.connect('cloudstore.db')
    c = conn.cursor()
    c.execute("SELECT COALESCE(SUM(size), 0) FROM files WHERE user_id = ? AND filename != '.folder'", (session['user_id'],))
    usage = c.fetchone()[0]
    conn.close()
    
    return jsonify({
        'used': usage,
        'limit': 5 * 1024 * 1024 * 1024,  # 5GB
        'percentage': (usage / (5 * 1024 * 1024 * 1024)) * 100
    })

@app.route('/folder_count')
def folder_count():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    path = request.args.get('path', '/')
    
    conn = sqlite3.connect('cloudstore.db')
    c = conn.cursor()
    
    # Count files in this path
    c.execute("""SELECT COUNT(*) FROM files 
                 WHERE user_id=? AND virtual_path = ? AND filename != '.folder'""",
             (session['user_id'], path))
    file_count = c.fetchone()[0]
    
    # Count subfolders (direct children only)
    c.execute("""SELECT COUNT(DISTINCT virtual_path) FROM files 
                 WHERE user_id=? AND filename = '.folder' AND virtual_path LIKE ? AND virtual_path != ?""",
             (session['user_id'], f"{path}%", path))
    all_subfolders = c.fetchone()[0]
    
    # Filter to direct children only
    c.execute("""SELECT virtual_path FROM files 
                 WHERE user_id=? AND filename = '.folder'""",
             (session['user_id'],))
    all_folders = c.fetchall()
    
    subfolder_count = 0
    for (folder_path,) in all_folders:
        if folder_path != path and folder_path.startswith(path):
            remaining_path = folder_path[len(path):].strip('/')
            if remaining_path and '/' not in remaining_path:
                subfolder_count += 1
    
    conn.close()
    
    total_count = file_count + subfolder_count
    return jsonify({'count': total_count})



@app.route('/create_folder', methods=['POST'])
def create_folder():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    folder_path = data.get('path', '')
    
    # Ensure folder path ends with /
    if not folder_path.endswith('/'):
        folder_path += '/'
    
    # Create empty marker file for folder
    conn = sqlite3.connect('cloudstore.db')
    c = conn.cursor()
    c.execute("""INSERT INTO files 
                 (filename, virtual_path, file_hash, size, broker_id, storage_path, created_at, user_id)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
             ('.folder', folder_path, '', 0, None, '', datetime.now(), session['user_id']))
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Folder created successfully'})

@app.route('/create_file', methods=['POST'])
def create_file():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    filename = data.get('filename')
    virtual_path = data.get('virtual_path', '/')
    content = data.get('content', '').encode()
    
    if not filename:
        return jsonify({'error': 'Filename required'}), 400
    
    # Check storage limit (5GB)
    conn = sqlite3.connect('cloudstore.db')
    c = conn.cursor()
    c.execute("SELECT COALESCE(SUM(size), 0) FROM files WHERE user_id = ? AND filename != '.folder'", (session['user_id'],))
    current_usage = c.fetchone()[0]
    conn.close()
    
    if current_usage + len(content) > 5 * 1024 * 1024 * 1024:  # 5GB limit
        return jsonify({'error': 'Storage limit exceeded (5GB max)'}), 400
    
    broker_ids = select_brokers()
    if not broker_ids:
        return jsonify({'error': 'No active brokers available. Please add a broker first.'}), 400
    
    file_hash = hashlib.sha256(content).hexdigest()
    
    conn = sqlite3.connect('cloudstore.db')
    c = conn.cursor()
    
    # Store file metadata
    c.execute("""INSERT INTO files 
                 (filename, virtual_path, file_hash, size, broker_id, storage_path, created_at, user_id)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
             (filename, virtual_path, file_hash, len(content), broker_ids[0], '', datetime.now(), session['user_id']))
    file_id = c.lastrowid
    
    # Upload to all selected brokers
    for i, broker_id in enumerate(broker_ids):
        c.execute("SELECT type, config FROM brokers WHERE id=?", (broker_id,))
        broker_data = c.fetchone()
        if broker_data:
            broker_type, broker_config = broker_data
            broker = StorageBroker(broker_id, broker_type, broker_config)
            # Get user account_id for folder structure
            c.execute("SELECT account_id FROM users WHERE id = ?", (session['user_id'],))
            result = c.fetchone()
            account_id = result[0] if result and result[0] else f"user_{session['user_id']}"
            
            storage_path = broker.upload_file(content, f"{account_id}/{file_hash}_{secure_filename(filename)}")
            
            c.execute("""INSERT INTO file_replicas 
                         (file_id, broker_id, storage_path, is_primary)
                         VALUES (?, ?, ?, ?)""",
                     (file_id, broker_id, storage_path, i == 0))
    
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'File created successfully'})

@app.route('/rename_file', methods=['POST'])
def rename_file():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    old_name = data.get('old_name')
    new_name = data.get('new_name')
    virtual_path = data.get('virtual_path', '/')
    
    conn = sqlite3.connect('cloudstore.db')
    c = conn.cursor()
    c.execute("UPDATE files SET filename=? WHERE filename=? AND virtual_path=? AND user_id=?",
             (new_name, old_name, virtual_path, session['user_id']))
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'File renamed successfully'})

@app.route('/rename_folder', methods=['POST'])
def rename_folder():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    old_path = data.get('old_path').rstrip('/') + '/'
    new_path = data.get('new_path').rstrip('/') + '/'
    
    conn = sqlite3.connect('cloudstore.db')
    c = conn.cursor()
    c.execute("UPDATE files SET virtual_path=REPLACE(virtual_path, ?, ?) WHERE virtual_path LIKE ? AND user_id=?",
             (old_path, new_path, f"{old_path}%", session['user_id']))
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Folder renamed successfully'})

@app.route('/delete_file', methods=['DELETE'])
def delete_file():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    filename = data.get('filename')
    virtual_path = data.get('virtual_path', '/')
    
    conn = sqlite3.connect('cloudstore.db')
    c = conn.cursor()
    c.execute("DELETE FROM files WHERE filename=? AND virtual_path=? AND user_id=?",
             (filename, virtual_path, session['user_id']))
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'File deleted successfully'})

@app.route('/delete_folder', methods=['DELETE'])
def delete_folder():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    folder_path = data.get('path').rstrip('/') + '/'
    
    conn = sqlite3.connect('cloudstore.db')
    c = conn.cursor()
    c.execute("DELETE FROM files WHERE virtual_path LIKE ? AND user_id=?",
             (f"{folder_path}%", session['user_id']))
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Folder deleted successfully'})

@app.route('/move_file', methods=['POST'])
def move_file():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    filename = data.get('filename')
    old_path = data.get('old_path')
    new_path = data.get('new_path')
    
    conn = sqlite3.connect('cloudstore.db')
    c = conn.cursor()
    
    # Check if file already exists in destination
    c.execute("SELECT COUNT(*) FROM files WHERE filename=? AND virtual_path=? AND user_id=?",
             (filename, new_path, session['user_id']))
    if c.fetchone()[0] > 0:
        conn.close()
        return jsonify({'error': f'File "{filename}" already exists in destination folder'}), 409
    
    c.execute("UPDATE files SET virtual_path=? WHERE filename=? AND virtual_path=? AND user_id=?",
             (new_path, filename, old_path, session['user_id']))
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'File moved successfully'})

@app.route('/move_folder', methods=['POST'])
def move_folder():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    folder_name = data.get('folder_name')
    old_path = data.get('old_path')
    new_path = data.get('new_path')
    
    old_folder_path = old_path + folder_name + '/'
    new_folder_path = new_path + folder_name + '/'
    
    conn = sqlite3.connect('cloudstore.db')
    c = conn.cursor()
    
    # Check if folder already exists in destination
    c.execute("SELECT COUNT(*) FROM files WHERE filename='.folder' AND virtual_path=? AND user_id=?",
             (new_folder_path, session['user_id']))
    if c.fetchone()[0] > 0:
        conn.close()
        return jsonify({'error': f'Folder "{folder_name}" already exists in destination'}), 409
    
    c.execute("UPDATE files SET virtual_path=REPLACE(virtual_path, ?, ?) WHERE virtual_path LIKE ? AND user_id=?",
             (old_folder_path, new_folder_path, f"{old_folder_path}%", session['user_id']))
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Folder moved successfully'})

@app.route('/copy_file', methods=['POST'])
def copy_file():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    filename = data.get('filename')
    old_path = data.get('old_path')
    new_path = data.get('new_path')
    new_filename = data.get('new_filename', filename)
    
    conn = sqlite3.connect('cloudstore.db')
    c = conn.cursor()
    c.execute("SELECT * FROM files WHERE filename=? AND virtual_path=? AND user_id=?",
             (filename, old_path, session['user_id']))
    file_data = c.fetchone()
    
    if file_data:
        c.execute("""INSERT INTO files 
                     (filename, virtual_path, file_hash, size, broker_id, storage_path, created_at, user_id)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                 (new_filename, new_path, file_data[3], file_data[4], file_data[5], file_data[6], datetime.now(), session['user_id']))
        conn.commit()
    
    conn.close()
    return jsonify({'message': 'File copied successfully'})

# Context processor for whitelabel settings
@app.context_processor
def inject_whitelabel_settings():
    conn = sqlite3.connect('cloudstore.db')
    c = conn.cursor()
    c.execute("SELECT key, value FROM settings WHERE key IN ('site_name', 'site_description', 'custom_css', 'primary_color', 'sidebar_bg', 'sidebar_text', 'card_bg', 'card_text', 'background_color')")
    results = c.fetchall()
    conn.close()
    
    settings = {key: value for key, value in results}
    return {
        'site_name': settings.get('site_name', 'CloudStore'),
        'site_description': settings.get('site_description', 'Decentralized File Storage System'),
        'custom_css': settings.get('custom_css', ''),
        'primary_color': settings.get('primary_color', '#2563eb'),
        'sidebar_bg': settings.get('sidebar_bg', '#1e293b'),
        'sidebar_text': settings.get('sidebar_text', '#cbd5e1'),
        'card_bg': settings.get('card_bg', '#ffffff'),
        'card_text': settings.get('card_text', '#1f2937'),
        'background_color': settings.get('background_color', '#f8fafc')
    }

# Web UI Routes
@app.route('/')
def index():
    print(f"Index accessed, session: {dict(session)}")
    if 'user_id' not in session:
        print("No user_id in session, redirecting to login")
        return redirect(url_for('login_page'))
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    return render_template('dashboard.html')

@app.route('/browse')
def browse_page():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login_page'))
    return render_template('storage.html')

@app.route('/manage')
def manage_page():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login_page'))
    return render_template('brokers.html')

@app.route('/storage_info')
def storage_info():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT id, name, type, config, active FROM brokers WHERE active = 1")
        brokers = c.fetchall()
        
        storage_data = []
        for broker_id, name, broker_type, config, active in brokers:
            # Get cached storage info from database
            c.execute("SELECT total_space, available_space, status_active FROM brokers WHERE id = ?", (broker_id,))
            cached_info = c.fetchone()
            
            if cached_info and cached_info[2]:  # If broker is active
                # Get virtual files stored on this broker (from database)
                c.execute("""
                    SELECT COALESCE(SUM(f.size), 0) 
                    FROM files f 
                    JOIN file_replicas r ON f.id = r.file_id 
                    WHERE r.broker_id = ?
                """, (broker_id,))
                virtual_used = c.fetchone()[0]
                
                # Get actual broker usage from cached data
                c.execute("SELECT actual_used FROM brokers WHERE id = ?", (broker_id,))
                actual_result = c.fetchone()
                actual_used = actual_result[0] if actual_result and actual_result[0] is not None else 0
                
                storage_data.append({
                    'id': broker_id,
                    'name': name,
                    'type': broker_type,
                    'total': cached_info[0] or 0,
                    'virtual_used': virtual_used,
                    'actual_used': actual_used,
                    'available': cached_info[1] or 0
                })
            else:
                # Get virtual usage even for offline brokers
                c.execute("""
                    SELECT COALESCE(SUM(f.size), 0) 
                    FROM files f 
                    JOIN file_replicas r ON f.id = r.file_id 
                    WHERE r.broker_id = ?
                """, (broker_id,))
                virtual_used = c.fetchone()[0]
                
                storage_data.append({
                    'id': broker_id,
                    'name': name,
                    'type': broker_type,
                    'virtual_used': virtual_used,
                    'actual_used': 0,
                    'error': 'Broker offline'
                })
        
        return jsonify(storage_data)

@app.route('/storage_space')
def storage_space_page():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login_page'))
    return render_template('storage_space.html')



@app.route('/broker_status')
def get_broker_status():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    conn = sqlite3.connect('cloudstore.db')
    c = conn.cursor()
    c.execute("SELECT id, status_active FROM brokers")
    brokers = c.fetchall()
    conn.close()
    
    return jsonify({broker[0]: bool(broker[1]) for broker in brokers})

def check_broker_status():
    """Background job to check broker status and storage info"""
    from datetime import datetime
    
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT id, type, config FROM brokers")
            brokers = c.fetchall()
            
            for broker_id, broker_type, config in brokers:
                try:
                    import socket
                    socket.setdefaulttimeout(5)
                    
                    broker = StorageBroker(broker_id, broker_type, config)
                    storage_info = broker.broker.get_storage_info()
                    
                    # Update status and storage info
                    c.execute("""UPDATE brokers SET 
                                status_active = 1, 
                                last_checked = ?, 
                                total_space = ?, 
                                available_space = ?, 
                                actual_used = ? 
                                WHERE id = ?""",
                             (datetime.now(), storage_info['total'], storage_info['available'], 
                              storage_info.get('used', 0), broker_id))
                    
                except Exception as e:
                    # Mark as inactive if test fails
                    c.execute("""UPDATE brokers SET 
                                status_active = 0, 
                                last_checked = ? 
                                WHERE id = ?""",
                             (datetime.now(), broker_id))
            
            conn.commit()
    except Exception as e:
        print(f"Broker status check failed: {e}")

# Start background broker checking
def broker_status_worker():
    while True:
        try:
            check_broker_status()
            # Get refresh interval from settings
            with get_db() as conn:
                c = conn.cursor()
                c.execute("SELECT value FROM settings WHERE key = 'broker_refresh_interval'")
                result = c.fetchone()
                interval_minutes = int(result[0]) if result else 5
            time.sleep(interval_minutes * 60)
        except Exception as e:
            print(f"Broker worker error: {e}")
            time.sleep(300)

@app.route('/admin/refresh_brokers', methods=['POST'])
def admin_refresh_brokers():
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Admin access required'}), 403
    
    try:
        check_broker_status()
        return jsonify({'message': 'Broker status refreshed'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Start background thread after app is ready
def start_background_tasks():
    broker_thread = threading.Thread(target=broker_status_worker, daemon=True)
    broker_thread.start()
    # Run initial check
    threading.Thread(target=check_broker_status, daemon=True).start()

@app.route('/admin')
def admin_page():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login_page'))
    return render_template('admin.html')

@app.route('/admin/users')
def admin_users():
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Admin access required'}), 403
    
    with get_db() as conn:
        c = conn.cursor()
        # Check if account_id column exists
        try:
            c.execute("""SELECT u.id, u.username, u.is_admin, u.account_id, u.created_at,
                                COUNT(CASE WHEN f.filename != '.folder' THEN f.id END) as file_count, 
                                COALESCE(SUM(CASE WHEN f.filename != '.folder' THEN f.size ELSE 0 END), 0) as total_size
                         FROM users u LEFT JOIN files f ON u.id = f.user_id
                         GROUP BY u.id ORDER BY u.id DESC""")
            users = c.fetchall()
            
            return jsonify([{
                'id': u[0],
                'username': u[1],
                'is_admin': bool(u[2]),
                'account_id': u[3],
                'created_at': u[4],
                'file_count': u[5],
                'total_size': u[6]
            } for u in users])
        except sqlite3.OperationalError:
            # Fallback for when account_id column doesn't exist
            c.execute("""SELECT u.id, u.username, u.is_admin, u.created_at,
                                COUNT(CASE WHEN f.filename != '.folder' THEN f.id END) as file_count, 
                                COALESCE(SUM(CASE WHEN f.filename != '.folder' THEN f.size ELSE 0 END), 0) as total_size
                         FROM users u LEFT JOIN files f ON u.id = f.user_id
                         GROUP BY u.id ORDER BY u.id DESC""")
            users = c.fetchall()
            
            return jsonify([{
                'id': u[0],
                'username': u[1],
                'is_admin': bool(u[2]),
                'account_id': 'N/A',
                'created_at': u[3],
                'file_count': u[4],
                'total_size': u[5]
            } for u in users])

@app.route('/admin/create_user', methods=['POST'])
def admin_create_user():
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Admin access required'}), 403
    
    data = request.json
    username = data.get('username')
    password = data.get('password')
    is_admin = data.get('is_admin', False)
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    conn = sqlite3.connect('cloudstore.db')
    c = conn.cursor()
    
    try:
        password_hash = generate_password_hash(password)
        import uuid
        account_id = str(uuid.uuid4())[:8]
        c.execute("INSERT INTO users (username, password_hash, is_admin, account_id) VALUES (?, ?, ?, ?)",
                 (username, password_hash, is_admin, account_id))
        user_id = c.lastrowid
        
        # Create home directory for regular users
        if not is_admin:
            home_path = f'/home/{username}/'
            c.execute("""INSERT INTO files 
                         (filename, virtual_path, file_hash, size, broker_id, storage_path, created_at, user_id)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                     ('.folder', home_path, '', 0, None, '', datetime.now(), user_id))
        
        conn.commit()
        return jsonify({'message': 'User created successfully'})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already exists'}), 400
    finally:
        conn.close()

@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'PUT'])
def admin_edit_user(user_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Admin access required'}), 403
    
    conn = sqlite3.connect('cloudstore.db', timeout=10)
    c = conn.cursor()
    
    if request.method == 'GET':
        c.execute("SELECT username, is_admin, account_id FROM users WHERE id = ?", (user_id,))
        user = c.fetchone()
        conn.close()
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({
            'username': user[0],
            'is_admin': bool(user[1]),
            'account_id': user[2]
        })
    
    # PUT request
    data = request.json
    username = data.get('username')
    is_admin = data.get('is_admin', False)
    new_password = data.get('password')
    
    if not username:
        conn.close()
        return jsonify({'error': 'Username is required'}), 400
    
    try:
        if new_password:
            password_hash = generate_password_hash(new_password)
            c.execute("UPDATE users SET username = ?, is_admin = ?, password_hash = ? WHERE id = ?",
                     (username, is_admin, password_hash, user_id))
        else:
            c.execute("UPDATE users SET username = ?, is_admin = ? WHERE id = ?",
                     (username, is_admin, user_id))
        
        conn.commit()
        conn.close()
        return jsonify({'message': 'User updated successfully'})
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'error': 'Username already exists'}), 400

@app.route('/admin/delete_user/<int:user_id>', methods=['DELETE'])
def admin_delete_user(user_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Admin access required'}), 403
    
    if user_id == session['user_id']:
        return jsonify({'error': 'Cannot delete yourself'}), 400
    
    conn = sqlite3.connect('cloudstore.db')
    c = conn.cursor()
    
    # Delete user files first
    c.execute("DELETE FROM files WHERE user_id = ?", (user_id,))
    # Delete user
    c.execute("DELETE FROM users WHERE id = ?", (user_id,))
    
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'User deleted successfully'})

@app.route('/admin/user_files/<int:user_id>')
def admin_user_files(user_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Admin access required'}), 403
    
    conn = sqlite3.connect('cloudstore.db')
    c = conn.cursor()
    c.execute("""
        SELECT f.filename, f.virtual_path, f.size, f.created_at,
               GROUP_CONCAT(b.name, ', ') as brokers,
               GROUP_CONCAT(r.storage_path, '; ') as storage_paths
        FROM files f
        LEFT JOIN file_replicas r ON f.id = r.file_id
        LEFT JOIN brokers b ON r.broker_id = b.id
        WHERE f.user_id = ? AND f.filename != '.folder'
        GROUP BY f.id
        ORDER BY f.created_at DESC
    """, (user_id,))
    files = c.fetchall()
    conn.close()
    
    return jsonify([{
        'filename': f[0],
        'virtual_path': f[1],
        'size': f[2],
        'created_at': f[3],
        'brokers': f[4] or 'No brokers',
        'storage_paths': f[5] or 'No paths'
    } for f in files])

@app.route('/admin/user_files_view/<int:user_id>')
def admin_user_files_view(user_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login_page'))
    return render_template('user_files.html')

@app.route('/admin/delete_file', methods=['DELETE'])
def admin_delete_file():
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Admin access required'}), 403
    
    data = request.json
    filename = data.get('filename')
    virtual_path = data.get('virtual_path')
    target_user_id = data.get('user_id')
    
    conn = sqlite3.connect('cloudstore.db')
    c = conn.cursor()
    c.execute("DELETE FROM files WHERE filename=? AND virtual_path=? AND user_id=?",
             (filename, virtual_path, target_user_id))
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'File deleted successfully'})

def check_single_broker(broker_id):
    """Background task to check a single broker"""
    try:
        conn = sqlite3.connect('cloudstore.db', timeout=10)
        c = conn.cursor()
        c.execute("SELECT type, config FROM brokers WHERE id = ?", (broker_id,))
        broker_data = c.fetchone()
        
        if broker_data:
            broker_type, config = broker_data
            try:
                import socket
                from datetime import datetime
                socket.setdefaulttimeout(5)
                
                broker = StorageBroker(broker_id, broker_type, config)
                storage_info = broker.broker.get_storage_info()
                
                c.execute("""UPDATE brokers SET 
                            status_active = 1, 
                            last_checked = ?, 
                            total_space = ?, 
                            available_space = ? 
                            WHERE id = ?""",
                         (datetime.now(), storage_info['total'], storage_info['available'], broker_id))
            except:
                c.execute("""UPDATE brokers SET 
                            status_active = 0, 
                            last_checked = ? 
                            WHERE id = ?""",
                         (datetime.now(), broker_id))
            
            conn.commit()
        conn.close()
    except Exception as e:
        print(f"Single broker check failed: {e}")

@app.route('/edit_broker/<int:broker_id>', methods=['PUT'])
def edit_broker(broker_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        data = request.json
        if not data:
            return jsonify({'error': 'No data provided'}), 400
            
        name = data.get('name')
        config_data = data.get('config', {})
        
        if not name:
            return jsonify({'error': 'Broker name is required'}), 400
        
        config = json.dumps(config_data)
        
        conn = sqlite3.connect('cloudstore.db')
        c = conn.cursor()
        c.execute("UPDATE brokers SET name = ?, config = ? WHERE id = ?",
                 (name, config, broker_id))
        conn.commit()
        conn.close()
        
        # Start background check for this broker
        threading.Thread(target=check_single_broker, args=(broker_id,), daemon=True).start()
        
        return jsonify({'message': 'Broker updated successfully'})
    except Exception as e:
        return jsonify({'error': f'Failed to update broker: {str(e)}'}), 500

@app.route('/get_broker/<int:broker_id>')
def get_broker_details(broker_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    conn = sqlite3.connect('cloudstore.db')
    c = conn.cursor()
    c.execute("SELECT name, type, config FROM brokers WHERE id = ?", (broker_id,))
    broker = c.fetchone()
    conn.close()
    
    if not broker:
        return jsonify({'error': 'Broker not found'}), 404
    
    try:
        config = json.loads(broker[2]) if broker[2] else {}
    except json.JSONDecodeError:
        config = {}
    
    return jsonify({
        'name': broker[0],
        'type': broker[1],
        'config': config
    })

@app.route('/login_page')
def login_page():
    return render_template('login.html')

@app.route('/web_login', methods=['POST'])
def web_login():
    username = request.form['username']
    password = request.form['password']
    print(f"Login attempt: {username}")
    
    conn = sqlite3.connect('cloudstore.db')
    c = conn.cursor()
    c.execute("SELECT id, password_hash, username, is_admin FROM users WHERE username=?", (username,))
    user = c.fetchone()
    print(f"User found: {user is not None}")
    
    if user and check_password_hash(user[1], password):
        print("Password correct, setting session")
        session['user_id'] = user[0]
        session['username'] = user[2]
        session['is_admin'] = user[3] == 1
        print(f"Session set: {dict(session)}")
        
        # Create user home directory if it doesn't exist
        if not user[3]:  # Not admin
            home_path = f'/home/{user[2]}/'
            c.execute("SELECT COUNT(*) FROM files WHERE filename = '.folder' AND virtual_path = ? AND user_id = ?",
                     (home_path, user[0]))
            if c.fetchone()[0] == 0:
                c.execute("""INSERT INTO files 
                             (filename, virtual_path, file_hash, size, broker_id, storage_path, created_at, user_id)
                             VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                         ('.folder', home_path, '', 0, None, '', datetime.now(), user[0]))
                conn.commit()
        
        conn.close()
        print("Redirecting to index")
        return redirect(url_for('index'))
    
    conn.close()
    print("Login failed")
    flash('Invalid credentials')
    return redirect(url_for('login_page'))

@app.route('/web_register', methods=['POST'])
def web_register():
    username = request.form['username']
    password = request.form['password']
    
    conn = sqlite3.connect('cloudstore.db')
    c = conn.cursor()
    
    try:
        import uuid
        password_hash = generate_password_hash(password)
        account_id = str(uuid.uuid4())[:8]
        c.execute("INSERT INTO users (username, password_hash, account_id) VALUES (?, ?, ?)", 
                 (username, password_hash, account_id))
        conn.commit()
        flash('Registration successful! Please login.')
    except sqlite3.IntegrityError:
        flash('Username already exists')
    finally:
        conn.close()
    
    return redirect(url_for('login_page'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))

@app.route('/admin/settings_page')
def admin_settings_page():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login_page'))
    return render_template('admin_settings.html')

@app.route('/admin/reset_theme', methods=['POST'])
def admin_reset_theme():
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Admin access required'}), 403
    
    conn = sqlite3.connect('cloudstore.db')
    c = conn.cursor()
    
    # Reset to default values
    c.execute("UPDATE settings SET value = 'CloudStore' WHERE key = 'site_name'")
    c.execute("UPDATE settings SET value = 'Decentralized File Storage System' WHERE key = 'site_description'")
    c.execute("UPDATE settings SET value = '' WHERE key = 'custom_css'")
    c.execute("UPDATE settings SET value = '#2563eb' WHERE key = 'primary_color'")
    c.execute("UPDATE settings SET value = '#1e293b' WHERE key = 'sidebar_bg'")
    c.execute("UPDATE settings SET value = '#cbd5e1' WHERE key = 'sidebar_text'")
    c.execute("UPDATE settings SET value = '#ffffff' WHERE key = 'card_bg'")
    c.execute("UPDATE settings SET value = '#1f2937' WHERE key = 'card_text'")
    c.execute("UPDATE settings SET value = '#f8fafc' WHERE key = 'background_color'")
    
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'Theme reset to defaults successfully'})

@app.route('/admin/settings', methods=['GET', 'POST'])
def admin_settings():
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'error': 'Admin access required'}), 403
    
    conn = sqlite3.connect('cloudstore.db')
    c = conn.cursor()
    
    if request.method == 'POST':
        data = request.json
        replica_count = data.get('replica_count', 2)
        broker_refresh_interval = data.get('broker_refresh_interval', 5)
        site_name = data.get('site_name', 'CloudStore')
        site_description = data.get('site_description', 'Decentralized File Storage System')
        custom_css = data.get('custom_css', '')
        primary_color = data.get('primary_color', '#2563eb')
        sidebar_bg = data.get('sidebar_bg', '#1e293b')
        sidebar_text = data.get('sidebar_text', '#cbd5e1')
        card_bg = data.get('card_bg', '#ffffff')
        card_text = data.get('card_text', '#1f2937')
        background_color = data.get('background_color', '#f8fafc')
        
        c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('replica_count', ?)", (str(replica_count),))
        c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('broker_refresh_interval', ?)", (str(broker_refresh_interval),))
        c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('site_name', ?)", (site_name,))
        c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('site_description', ?)", (site_description,))
        c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('custom_css', ?)", (custom_css,))
        c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('primary_color', ?)", (primary_color,))
        c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('sidebar_bg', ?)", (sidebar_bg,))
        c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('sidebar_text', ?)", (sidebar_text,))
        c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('card_bg', ?)", (card_bg,))
        c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('card_text', ?)", (card_text,))
        c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('background_color', ?)", (background_color,))
        conn.commit()
        return jsonify({'message': 'Settings updated successfully'})
    
    # GET request
    c.execute("SELECT key, value FROM settings WHERE key IN ('replica_count', 'broker_refresh_interval', 'site_name', 'site_description', 'custom_css', 'primary_color', 'sidebar_bg', 'sidebar_text', 'card_bg', 'card_text', 'background_color')")
    results = c.fetchall()
    settings = {key: value for key, value in results}
    
    return jsonify({
        'replica_count': int(settings.get('replica_count', '2')),
        'broker_refresh_interval': int(settings.get('broker_refresh_interval', '5')),
        'site_name': settings.get('site_name', 'CloudStore'),
        'site_description': settings.get('site_description', 'Decentralized File Storage System'),
        'custom_css': settings.get('custom_css', ''),
        'primary_color': settings.get('primary_color', '#2563eb'),
        'sidebar_bg': settings.get('sidebar_bg', '#1e293b'),
        'sidebar_text': settings.get('sidebar_text', '#cbd5e1'),
        'card_bg': settings.get('card_bg', '#ffffff'),
        'card_text': settings.get('card_text', '#1f2937'),
        'background_color': settings.get('background_color', '#f8fafc')
    })

if __name__ == '__main__':
    init_db()
    os.makedirs('storage', exist_ok=True)
    start_background_tasks()
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG', 'False').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug)