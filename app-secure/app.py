#!/usr/bin/env python3
"""
===============================================================================
SIGURNA DEMO APLIKACIJA - Primjer sigurnog zapisivanja
===============================================================================

Ova aplikacija demonstrira PRAVILNE sigurnosne prakse:
- Sanitizacija korisničkog unosa prije zapisivanja
- Strukturirano zapisivanje (JSON format)
- Ograničenje duljine unosa
- Uklanjanje kontrolnih znakova
- Rate limiting za zaštitu od flooding napada

Usporedi s ranjivom verzijom za razumijevanje razlika!
===============================================================================
"""

import os
import re
import json
import socket
import logging
import hashlib
import secrets
from datetime import datetime
from functools import wraps
from flask import Flask, request, jsonify, g
from collections import defaultdict
import time

# =============================================================================
# KONFIGURACIJA
# =============================================================================

LOGSTASH_HOST = os.environ.get('LOGSTASH_HOST', 'logstash')
LOGSTASH_PORT = int(os.environ.get('LOGSTASH_PORT', 5000))
LOG_FILE = '/var/log/app/secure.log'
MAX_INPUT_LENGTH = 500
RATE_LIMIT_REQUESTS = 100  # Maksimalni broj zahtjeva
RATE_LIMIT_WINDOW = 60     # Vremenski prozor u sekundama

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Rate limiting storage
request_counts = defaultdict(list)

# =============================================================================
# SIGURNO ZAPISIVANJE
# =============================================================================

# Osiguraj da direktorij postoji
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

class SecureJSONFormatter(logging.Formatter):
    """
    Siguran JSON formatter koji automatski escapira sve vrijednosti.
    """
    def format(self, record):
        log_entry = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'application': 'secure_app',
            'version': '1.0.0-SECURE'
        }
        
        # Dodaj extra polja ako postoje
        if hasattr(record, 'extra_data'):
            log_entry['data'] = record.extra_data
            
        # json.dumps automatski escapira problematične znakove
        return json.dumps(log_entry, ensure_ascii=False)

# Konfiguracija loggera
file_handler = logging.FileHandler(LOG_FILE)
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(SecureJSONFormatter())

logger = logging.getLogger('secure_app')
logger.setLevel(logging.INFO)
logger.addHandler(file_handler)

# =============================================================================
# SIGURNOSNE FUNKCIJE
# =============================================================================

def sanitize_input(text, max_length=MAX_INPUT_LENGTH):
    """
    Sanitizira korisnički unos za sigurno zapisivanje.
    
    Zaštite:
    1. Ograničenje duljine - sprječava DoS
    2. Uklanjanje kontrolnih znakova - sprječava CRLF injection
    3. Uklanjanje ANSI escape sekvenci - sprječava terminal injection
    4. Normalizacija whitespace karaktera
    
    Args:
        text: Ulazni tekst za sanitizaciju
        max_length: Maksimalna dozvoljena duljina
        
    Returns:
        Sanitizirani tekst
    """
    if not isinstance(text, str):
        text = str(text)
    
    # 1. Ograniči duljinu ODMAH
    text = text[:max_length]
    
    # 2. Ukloni kontrolne znakove (ASCII 0-31 i 127-159)
    # Ovo sprječava CRLF injection (\r\n) i druge kontrolne sekvence
    text = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', text)
    
    # 3. Ukloni ANSI escape sekvence
    text = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', text)
    text = re.sub(r'\x1b\][^\x07]*\x07', '', text)
    
    # 4. Normaliziraj whitespace (zamijeni višestruke razmake jednim)
    text = ' '.join(text.split())
    
    return text

def get_client_ip():
    """Sigurno dohvaćanje IP adrese klijenta."""
    # Provjeri X-Forwarded-For header (za reverse proxy)
    forwarded = request.headers.get('X-Forwarded-For', '')
    if forwarded:
        # Uzmi prvu IP adresu (originalni klijent)
        ip = forwarded.split(',')[0].strip()
    else:
        ip = request.remote_addr or 'unknown'
    
    # Sanitiziraj IP adresu
    return sanitize_input(ip, max_length=45)  # IPv6 max length

def generate_request_id():
    """Generira jedinstveni ID zahtjeva za praćenje."""
    return secrets.token_hex(8)

def rate_limit_check(ip):
    """
    Provjerava rate limit za danu IP adresu.
    
    Returns:
        tuple: (dozvoljen, preostalo_zahtjeva)
    """
    current_time = time.time()
    
    # Očisti stare zahtjeve izvan prozora
    request_counts[ip] = [
        t for t in request_counts[ip] 
        if current_time - t < RATE_LIMIT_WINDOW
    ]
    
    # Provjeri limit
    if len(request_counts[ip]) >= RATE_LIMIT_REQUESTS:
        return False, 0
    
    # Dodaj trenutni zahtjev
    request_counts[ip].append(current_time)
    remaining = RATE_LIMIT_REQUESTS - len(request_counts[ip])
    
    return True, remaining

def secure_log(event_type, **kwargs):
    """
    Sigurno zapisuje događaj s dodatnim kontekstom.
    
    Sve vrijednosti se automatski sanitiziraju.
    
    Args:
        event_type: Tip događaja (auth, access, error, etc.)
        **kwargs: Dodatni podaci za zapisivanje
    """
    # Sanitiziraj sve string vrijednosti
    sanitized_data = {}
    for key, value in kwargs.items():
        if isinstance(value, str):
            sanitized_data[key] = sanitize_input(value)
        else:
            sanitized_data[key] = value
    
    # Dodaj standardne metapodatke
    sanitized_data['event_type'] = event_type
    sanitized_data['source_ip'] = get_client_ip()
    sanitized_data['request_id'] = g.get('request_id', 'unknown')
    sanitized_data['user_agent'] = sanitize_input(
        request.user_agent.string if request.user_agent else 'unknown',
        max_length=200
    )
    
    # Kreiraj log record s extra podacima
    record = logging.LogRecord(
        name='secure_app',
        level=logging.INFO,
        pathname='',
        lineno=0,
        msg=f"Security event: {event_type}",
        args=(),
        exc_info=None
    )
    record.extra_data = sanitized_data
    
    logger.handle(record)
    
    # Pošalji na Logstash ako je dostupan
    send_to_logstash(sanitized_data)

def send_to_logstash(data):
    """Sigurno slanje podataka na Logstash."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((LOGSTASH_HOST, LOGSTASH_PORT))
        
        log_entry = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'application': 'secure_app',
            'version': '1.0.0-SECURE',
            **data
        }
        
        # json.dumps automatski escapira sve problematične znakove
        message = json.dumps(log_entry, ensure_ascii=False) + '\n'
        sock.sendall(message.encode('utf-8'))
        sock.close()
    except Exception as e:
        # Log lokalno ako Logstash nije dostupan
        logger.warning(f"Failed to send to Logstash: {type(e).__name__}")

# =============================================================================
# MIDDLEWARE
# =============================================================================

@app.before_request
def before_request():
    """Middleware koji se izvršava prije svakog zahtjeva."""
    # Generiraj request ID
    g.request_id = generate_request_id()
    
    # Rate limiting
    client_ip = get_client_ip()
    allowed, remaining = rate_limit_check(client_ip)
    
    if not allowed:
        secure_log('rate_limit_exceeded', ip=client_ip, severity='warning')
        return jsonify({
            'error': 'Rate limit exceeded',
            'retry_after': RATE_LIMIT_WINDOW
        }), 429
    
    # Dodaj rate limit info u response headere
    g.rate_limit_remaining = remaining

@app.after_request
def after_request(response):
    """Middleware koji se izvršava nakon svakog zahtjeva."""
    # Dodaj sigurnosne headere
    response.headers['X-Request-ID'] = g.get('request_id', 'unknown')
    response.headers['X-RateLimit-Remaining'] = str(g.get('rate_limit_remaining', 0))
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    return response

# =============================================================================
# SIMULIRANA BAZA KORISNIKA
# =============================================================================

KORISNICI = {
    'admin': {
        'lozinka_hash': hashlib.sha256('admin123'.encode()).hexdigest(),
        'uloga': 'administrator',
    },
    'korisnik': {
        'lozinka_hash': hashlib.sha256('korisnik123'.encode()).hexdigest(),
        'uloga': 'korisnik',
    },
    'test': {
        'lozinka_hash': hashlib.sha256('test123'.encode()).hexdigest(),
        'uloga': 'tester',
    }
}

# =============================================================================
# RUTE APLIKACIJE
# =============================================================================

@app.route('/')
def index():
    """Početna stranica."""
    secure_log('page_access', page='index')
    return jsonify({
        'aplikacija': 'Sigurna Demo Aplikacija',
        'verzija': '1.0.0-SECURE',
        'sigurnosne_mjere': [
            'Input sanitization',
            'Structured JSON logging',
            'Rate limiting',
            'Request ID tracking',
            'Security headers'
        ],
        'dostupne_rute': [
            'POST /login - Prijava korisnika',
            'GET /search?q=upit - Pretraživanje',
            'POST /comment - Ostavljanje komentara',
            'GET /user/<username> - Profil korisnika'
        ]
    })

@app.route('/login', methods=['POST'])
def login():
    """
    SIGURNA prijava - svi unosi su sanitizirani!
    
    Pokušaj injection napada će biti neutraliziran:
    {"username": "admin\\n2026-01-20 10:00:00 - FAKE LOG", "password": "x"}
    Rezultat: Kontrolni znakovi uklonjeni, log siguran.
    """
    podaci = request.get_json() or {}
    
    # SIGURNOST: Sanitiziraj unos ODMAH
    korisnicko_ime = sanitize_input(podaci.get('username', ''))
    lozinka = podaci.get('password', '')  # Lozinka se ne logira, samo hashira
    
    if not korisnicko_ime or not lozinka:
        secure_log('auth', 
                   status='failed', 
                   reason='missing_credentials',
                   severity='warning')
        return jsonify({
            'success': False, 
            'message': 'Nedostaju podaci za prijavu'
        }), 400
    
    korisnik = KORISNICI.get(korisnicko_ime)
    
    if not korisnik:
        # SIGURNOST: Sanitizirano korisničko ime u logu
        secure_log('auth',
                   status='failed',
                   username=korisnicko_ime,
                   reason='user_not_found',
                   severity='warning')
        return jsonify({
            'success': False, 
            'message': 'Neispravni podaci za prijavu'
        }), 401
    
    lozinka_hash = hashlib.sha256(lozinka.encode()).hexdigest()
    
    if lozinka_hash != korisnik['lozinka_hash']:
        secure_log('auth',
                   status='failed',
                   username=korisnicko_ime,
                   reason='wrong_password',
                   severity='warning')
        return jsonify({
            'success': False, 
            'message': 'Neispravni podaci za prijavu'
        }), 401
    
    # Uspješna prijava
    token = secrets.token_hex(32)
    secure_log('auth',
               status='success',
               username=korisnicko_ime,
               role=korisnik['uloga'])
    
    return jsonify({
        'success': True,
        'token': token,
        'role': korisnik['uloga'],
        'message': f'Dobrodošli!'  # Ne vraćaj korisničko ime u odgovoru
    })

@app.route('/search', methods=['GET'])
def search():
    """
    SIGURNA pretraga - query parametar je sanitiziran!
    """
    # SIGURNOST: Sanitiziraj query parametar
    query = sanitize_input(request.args.get('q', ''))
    
    if not query:
        return jsonify({
            'error': 'Query parameter q is required',
            'results': [],
            'count': 0
        }), 400
    
    secure_log('search',
               query=query,
               query_length=len(query))
    
    # Simulirani rezultati
    rezultati = [
        {'id': 1, 'naslov': f'Rezultat za pretragu'},
        {'id': 2, 'naslov': f'Povezani članak'}
    ]
    
    return jsonify({
        'query': query,
        'results': rezultati,
        'count': len(rezultati)
    })

@app.route('/comment', methods=['POST'])
def comment():
    """
    SIGURNO ostavljanje komentara - sva polja sanitizirana!
    """
    podaci = request.get_json() or {}
    
    # SIGURNOST: Sanitiziraj SVA polja
    user = sanitize_input(podaci.get('user', 'anonymous'))
    komentar = sanitize_input(podaci.get('comment', ''), max_length=1000)
    
    if not komentar:
        return jsonify({
            'success': False,
            'error': 'Comment cannot be empty'
        }), 400
    
    secure_log('comment',
               user=user,
               comment_length=len(komentar),
               comment_preview=komentar[:50])  # Samo preview, ne cijeli komentar
    
    return jsonify({
        'success': True,
        'message': 'Komentar spremljen',
        'comment_id': secrets.token_hex(8)
    })

@app.route('/user/<username>', methods=['GET'])
def user_profile(username):
    """
    SIGURAN profil korisnika - URL parametar sanitiziran!
    """
    # SIGURNOST: Sanitiziraj URL parametar
    safe_username = sanitize_input(username)
    
    secure_log('profile_access', username=safe_username)
    
    korisnik = KORISNICI.get(safe_username)
    
    if korisnik:
        return jsonify({
            'username': safe_username,
            'role': korisnik['uloga'],
            'exists': True
        })
    else:
        return jsonify({
            'exists': False,
            'message': 'Korisnik ne postoji'
        }), 404

@app.route('/admin/logs', methods=['GET'])
def view_logs():
    """
    Pregled log datoteke - za demonstraciju sigurnog zapisivanja.
    """
    try:
        with open(LOG_FILE, 'r') as f:
            logs = f.readlines()[-50:]
        
        # Parse JSON logove za ljepši prikaz
        parsed_logs = []
        for log in logs:
            try:
                parsed_logs.append(json.loads(log))
            except json.JSONDecodeError:
                parsed_logs.append({'raw': log})
        
        return jsonify({
            'log_file': LOG_FILE,
            'last_entries': parsed_logs,
            'count': len(parsed_logs),
            'note': 'Primijeti kako su svi unosi sigurno escapirani u JSON formatu'
        })
    except Exception as e:
        return jsonify({
            'error': 'Could not read logs'
        }), 500

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({
        'status': 'running',
        'type': 'SECURE',
        'timestamp': datetime.utcnow().isoformat(),
        'security_features': [
            'input_sanitization',
            'rate_limiting',
            'structured_logging',
            'request_tracking'
        ]
    })

# =============================================================================
# POKRETANJE APLIKACIJE
# =============================================================================

if __name__ == '__main__':
    print("=" * 70)
    print("SIGURNA DEMO APLIKACIJA")
    print("Implementira najbolje prakse za sigurno zapisivanje.")
    print("=" * 70)
    app.run(host='0.0.0.0', port=8080, debug=False)
