#!/bin/bash
# =============================================================================
# Cleanup Script - Čišćenje ELK okruženja
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "=============================================="
echo "ELK Security Stack - Cleanup"
echo "=============================================="
echo ""

read -p "Ovo će zaustaviti sve kontejnere. Nastaviti? (y/N) " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Prekinuto."
    exit 0
fi

echo -e "\n${YELLOW}Zaustavljanje kontejnera...${NC}"
podman-compose down

read -p "Želite li obrisati i volumene s podacima? (y/N) " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}Brisanje volumena...${NC}"
    podman-compose down -v
    echo -e "${GREEN}✓ Volumeni obrisani${NC}"
fi

read -p "Želite li obrisati i slike kontejnera? (y/N) " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}Brisanje slika...${NC}"
    podman-compose down -v --rmi all
    echo -e "${GREEN}✓ Slike obrisane${NC}"
fi

echo ""
echo -e "${GREEN}Čišćenje završeno!${NC}"
echo ""
