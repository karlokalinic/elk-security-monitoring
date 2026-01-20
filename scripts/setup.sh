#!/bin/bash
# =============================================================================
# Setup Script - ELK Security Monitoring Stack
# =============================================================================
# Inicijalizacija okruženja
# =============================================================================

set -e

echo "=============================================="
echo "ELK Security Monitoring Stack - Setup"
echo "=============================================="

# Boje za output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# -----------------------------------------------------------------------------
# Provjera preduvjeta
# -----------------------------------------------------------------------------
echo -e "\n${YELLOW}[1/5] Provjera preduvjeta...${NC}"

# Provjeri Podman
if ! command -v podman &> /dev/null; then
    echo -e "${RED}GREŠKA: Podman nije instaliran!${NC}"
    echo "Instalirajte Podman: sudo dnf install podman"
    exit 1
fi
echo -e "${GREEN}✓ Podman pronađen: $(podman --version)${NC}"

# Provjeri podman-compose
if ! command -v podman-compose &> /dev/null; then
    echo -e "${RED}GREŠKA: podman-compose nije instaliran!${NC}"
    echo "Instalirajte: sudo dnf install podman-compose"
    exit 1
fi
echo -e "${GREEN}✓ podman-compose pronađen${NC}"

# -----------------------------------------------------------------------------
# Sistemske postavke
# -----------------------------------------------------------------------------
echo -e "\n${YELLOW}[2/5] Podešavanje sistemskih parametara...${NC}"

# vm.max_map_count za Elasticsearch
CURRENT_MAP_COUNT=$(sysctl -n vm.max_map_count 2>/dev/null || echo "0")
if [ "$CURRENT_MAP_COUNT" -lt 262144 ]; then
    echo "Postavljanje vm.max_map_count=262144..."
    sudo sysctl -w vm.max_map_count=262144
    
    # Trajno postavljanje
    if ! grep -q "vm.max_map_count" /etc/sysctl.conf; then
        echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
    fi
fi
echo -e "${GREEN}✓ vm.max_map_count = $(sysctl -n vm.max_map_count)${NC}"

# -----------------------------------------------------------------------------
# Kreiranje .env datoteke
# -----------------------------------------------------------------------------
echo -e "\n${YELLOW}[3/5] Konfiguracija okruženja...${NC}"

if [ ! -f .env ]; then
    cp .env.example .env
    echo -e "${GREEN}✓ .env datoteka kreirana iz .env.example${NC}"
    echo -e "${YELLOW}  PREPORUČENO: Uredite lozinke u .env datoteci!${NC}"
else
    echo -e "${GREEN}✓ .env datoteka već postoji${NC}"
fi

# -----------------------------------------------------------------------------
# Build kontejnera
# -----------------------------------------------------------------------------
echo -e "\n${YELLOW}[4/5] Izgradnja kontejnera...${NC}"

podman-compose build --no-cache
echo -e "${GREEN}✓ Kontejneri izgrađeni${NC}"

# -----------------------------------------------------------------------------
# Pokretanje stacka
# -----------------------------------------------------------------------------
echo -e "\n${YELLOW}[5/5] Pokretanje stacka...${NC}"

podman-compose up -d
echo -e "${GREEN}✓ Stack pokrenut${NC}"

# -----------------------------------------------------------------------------
# Status i informacije
# -----------------------------------------------------------------------------
echo -e "\n=============================================="
echo -e "${GREEN}Setup uspješno završen!${NC}"
echo "=============================================="
echo ""
echo "Servisi:"
echo "  • Kibana:              http://localhost:5601"
echo "  • Elasticsearch:       https://localhost:9200"
echo "  • Demo App (Secure):   http://localhost:8080"
echo "  • Demo App (Vulnerable): http://localhost:8081"
echo ""
echo "Kredencijali (default):"
echo "  • Username: elastic"
echo "  • Password: ChangeMeNow123!"
echo ""
echo "Pričekajte 1-2 minute da se svi servisi pokrenu."
echo "Pratite logove: podman-compose logs -f"
echo ""
