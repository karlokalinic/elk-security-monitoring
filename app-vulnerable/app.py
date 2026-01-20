#!/usr/bin/env python3
"""
===============================================================================
RANJIVA DEMO APLIKACIJA - SAMO ZA EDUKACIJSKE SVRHE!
===============================================================================

Ova aplikacija namjerno sadrži sigurnosne ranjivosti za demonstraciju:
- Log Injection (CRLF Injection)
- Nedostatak sanitizacije unosa
- Loše prakse zapisivanja

NE KORISTITI U PRODUKCIJSKOM OKRUŽENJU!
===============================================================================
"""

import os
import json
import socket
import logging
import hashlib
import secrets
from datetime import datetime
from flask import Flask, request, jsonify

# =============================================================================
# KONFIGURACIJA
# =============================================================================

LOGSTASH_HOST = os.environ.get('LOGSTASH_HOST', 'logstash')
LOGSTASH_PORT = int(os.environ.get('LOGSTASH_PORT', 5000))
LOG_FILE = '/var/log/app/vulnerable.log'

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# =============================================================================
# RANJIVO ZAPISIVANJE - Bez sanitizacije!
# =============================================================================

# Osiguraj da direktorij postoji
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

# Konfiguracija datotečnog loggera - RANJIVO!
file_handler = logging.FileHandler(LOG_FILE)
file_handler.setLevel(logging.INFO)
# RANJIVOST: Format bez ikakve zaštite
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))

logger = logging.getLogger('vulnerable_app')
logger.setLevel(logging.INFO)
logger.addHandler(file_handler)

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
# RANJIVA FUNKCIJA ZA ZAPISIVANJE
# =============================================================================

def ranjivo_zapisivanje(poruka):
    """
    RANJIVA FUNKCIJA - Zapisuje poruku BEZ ikakve sanitizacije!
    
    Ranjivosti:
    1. Nema filtriranja kontrolnih znakova (CRLF injection)
    2. Nema ograničenja duljine (DoS potencijal)
    3. Nema escapiranja specijalnih znakova
    4. Direktno ubacivanje korisničkog unosa u log
    """
    # RANJIVOST: Direktno zapisivanje bez sanitizacije
    logger.info(poruka)
    
    # Također pokušaj poslati na Logstash (ako je dostupan)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((LOGSTASH_HOST, LOGSTASH_PORT))
        
        # RANJIVOST: Nesiguran JSON koji može biti manipuliran
        log_entry = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'message': poruka,  # Nesanitizirano!
            'application': 'vulnerable_app',
            'version': '1.0.0-INSECURE'
        }
        sock.sendall((json.dumps(log_entry) + '\n').encode('utf-8'))
        sock.close()
    except Exception:
        pass  # Tiho ignoriraj greške - još jedna loša praksa!

# =============================================================================
# RUTE APLIKACIJE
# =============================================================================

@app.route('/')
def index():
    """Početna stranica."""
    ranjivo_zapisivanje(f"Pristup početnoj stranici s IP: {request.remote_addr}")
    return jsonify({
        'aplikacija': 'Ranjiva Demo Aplikacija',
        'verzija': '1.0.0-INSECURE',
        'upozorenje': 'OVA APLIKACIJA JE NAMJERNO RANJIVA!',
        'svrha': 'Demonstracija log injection napada',
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
    RANJIVA prijava - Log Injection moguć!
    
    Napad primjer:
    {"username": "admin\\n2026-01-20 10:00:00 - Login SUCCESSFUL for: hacker", "password": "x"}
    """
    podaci = request.get_json() or {}
    korisnicko_ime = podaci.get('username', '')
    lozinka = podaci.get('password', '')
    
    korisnik = KORISNICI.get(korisnicko_ime)
    
    if not korisnik:
        # RANJIVOST: Direktno ubacivanje korisničkog unosa u log!
        ranjivo_zapisivanje(f"Login FAILED for user: {korisnicko_ime} - User not found")
        return jsonify({
            'success': False, 
            'message': 'Neispravni podaci za prijavu'
        }), 401
    
    lozinka_hash = hashlib.sha256(lozinka.encode()).hexdigest()
    
    if lozinka_hash != korisnik['lozinka_hash']:
        # RANJIVOST: Log injection moguć kroz korisničko ime!
        ranjivo_zapisivanje(f"Login FAILED for user: {korisnicko_ime} - Wrong password")
        return jsonify({
            'success': False, 
            'message': 'Neispravni podaci za prijavu'
        }), 401
    
    # Uspješna prijava
    token = secrets.token_hex(32)
    ranjivo_zapisivanje(f"Login SUCCESSFUL for user: {korisnicko_ime} - Role: {korisnik['uloga']}")
    
    return jsonify({
        'success': True,
        'token': token,
        'role': korisnik['uloga'],
        'message': f'Dobrodošli, {korisnicko_ime}!'
    })

@app.route('/search', methods=['GET'])
def search():
    """
    RANJIVA pretraga - Log Injection moguć kroz query parametar!
    
    Napad primjer:
    /search?q=test%0A2026-01-20%2010:00:00%20-%20ADMIN%20ACCESS%20GRANTED
    """
    query = request.args.get('q', '')
    
    # RANJIVOST: Direktno zapisivanje query parametra!
    ranjivo_zapisivanje(f"Search performed: '{query}' from IP: {request.remote_addr}")
    
    # Simulirani rezultati
    rezultati = [
        {'id': 1, 'naslov': f'Rezultat za: {query}'},
        {'id': 2, 'naslov': f'Povezani članak: {query}'}
    ]
    
    return jsonify({
        'query': query,
        'results': rezultati,
        'count': len(rezultati)
    })

@app.route('/comment', methods=['POST'])
def comment():
    """
    RANJIVO ostavljanje komentara - Višestruke ranjivosti!
    
    Napad primjer:
    {"user": "hacker\\n2026-01-20 - SYSTEM: Database backup completed", "comment": "test"}
    """
    podaci = request.get_json() or {}
    user = podaci.get('user', 'anonymous')
    komentar = podaci.get('comment', '')
    
    # RANJIVOST: Oba polja su ranjiva na injection!
    ranjivo_zapisivanje(f"New comment from {user}: {komentar}")
    
    return jsonify({
        'success': True,
        'message': 'Komentar spremljen',
        'user': user,
        'comment': komentar
    })

@app.route('/user/<username>', methods=['GET'])
def user_profile(username):
    """
    RANJIV profil korisnika - Injection kroz URL parametar!
    
    Napad primjer:
    /user/admin%0A2026-01-20%20-%20Password%20changed%20for%20admin
    """
    # RANJIVOST: URL parametar direktno u logu!
    ranjivo_zapisivanje(f"Profile accessed for user: {username}")
    
    korisnik = KORISNICI.get(username)
    
    if korisnik:
        return jsonify({
            'username': username,
            'role': korisnik['uloga'],
            'exists': True
        })
    else:
        return jsonify({
            'username': username,
            'exists': False,
            'message': 'Korisnik ne postoji'
        }), 404

@app.route('/admin/logs', methods=['GET'])
def view_logs():
    """
    Pregled log datoteke - za demonstraciju rezultata napada.
    """
    try:
        with open(LOG_FILE, 'r') as f:
            logs = f.readlines()[-50:]  # Zadnjih 50 linija
        return jsonify({
            'log_file': LOG_FILE,
            'last_entries': logs,
            'count': len(logs)
        })
    except Exception as e:
        return jsonify({
            'error': str(e)
        }), 500

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({
        'status': 'running',
        'type': 'VULNERABLE',
        'timestamp': datetime.utcnow().isoformat()
    })

# =============================================================================
# POKRETANJE APLIKACIJE
# =============================================================================

if __name__ == '__main__':
    print("=" * 70)
    print("UPOZORENJE: Ova aplikacija je NAMJERNO RANJIVA!")
    print("Koristite je SAMO u izoliranom okruženju za edukaciju.")
    print("=" * 70)
    app.run(host='0.0.0.0', port=8081, debug=False)
