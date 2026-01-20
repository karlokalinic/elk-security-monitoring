#  ELK Security Monitoring Stack

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Podman](https://img.shields.io/badge/Container-Podman-892CA0)](https://podman.io/)
[![ELK Stack](https://img.shields.io/badge/ELK-8.11.0-005571)](https://www.elastic.co/)

**Centralizirano zapisivanje događaja i sigurnosni nadzor u stvarnom vremenu**

Ovaj repozitorij sadrži potpuno funkcionalno okruženje za demonstraciju:
-  Centraliziranog zapisivanja događaja (ELK Stack)
-  SIEM funkcionalnosti i otkrivanja upada
-  Log injection napada i obrane
-  Automatizacije odgovora na incidente

---

##  Sadržaj

- [Značajke](#-značajke)
- [Preduvjeti](#-preduvjeti)
- [Brzo pokretanje](#-brzo-pokretanje)
- [Arhitektura](#-arhitektura)
- [Demonstracija napada](#-demonstracija-napada)
- [Kibana Dashboard](#-kibana-dashboard)
- [Konfiguracija](#-konfiguracija)
- [Troubleshooting](#-troubleshooting)
- [Licenca](#-licenca)

---

##  Značajke

| Značajka | Opis |
|----------|------|
| **ELK Stack** | Elasticsearch, Logstash, Kibana (v8.11.0) |
| **Filebeat** | Prikupljanje sistemskih logova |
| **Demo aplikacija** | Flask aplikacija s autentifikacijom |
| **Vulnerable verzija** | Demonstracija log injection napada |
| **Secure verzija** | Implementacija sigurnog zapisivanja |
| **Alerting** | Pravila za otkrivanje sumnjivih aktivnosti |
| **Dashboard** | Preddefinirani Kibana dashboardi |

---

##  Preduvjeti

### Sistemski zahtjevi
- **RAM:** Minimum 8 GB (preporučeno 16 GB)
- **Disk:** Minimum 20 GB slobodnog prostora
- **CPU:** 4+ jezgri preporučeno

### Softverski zahtjevi

```bash
# Rocky Linux / RHEL / Fedora
sudo dnf install podman podman-compose git curl

# Debian / Ubuntu
sudo apt update && sudo apt install podman podman-compose git curl

# Arch Linux
sudo pacman -S podman podman-compose git curl
```

### Verifikacija instalacije

```bash
podman --version
podman-compose --version
```

---

##  Brzo pokretanje

### 1. Kloniranje repozitorija

```bash
git clone https://github.com/VAŠE_KORISNIČKO_IME/elk-security-monitoring.git
cd elk-security-monitoring
```

### 2. Konfiguracija okruženja

```bash
# Kopirajte primjer konfiguracije
cp .env.example .env

# Uredite lozinke (opcionalno, ali preporučeno za produkciju)
nano .env
```

### 3. Pokretanje stacka

```bash
# Pokretanje svih servisa
podman-compose up -d

# Praćenje pokretanja
podman-compose logs -f
```

### 4. Provjera statusa

```bash
# Status svih kontejnera
podman-compose ps

# Health check
curl -k -u elastic:${ELASTIC_PASSWORD:-ChangeMeNow123!} https://localhost:9200/_cluster/health?pretty
```

### 5. Pristup servisima

| Servis | URL | Kredencijali |
|--------|-----|--------------|
| **Kibana** | http://localhost:5601 | elastic / ChangeMeNow123! |
| **Elasticsearch** | https://localhost:9200 | elastic / ChangeMeNow123! |
| **Demo App (Secure)** | http://localhost:8080 | admin / admin123 |
| **Demo App (Vulnerable)** | http://localhost:8081 | admin / admin123 |

---

## Arhitektura

```
┌─────────────────────────────────────────────────────────────────────┐
│                         ELK Security Stack                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────────┐ │
│  │   Filebeat  │───►│  Logstash   │───►│     Elasticsearch       │ │
│  │  (Collector)│    │ (Processor) │    │   (Storage & Search)    │ │
│  └─────────────┘    └─────────────┘    └───────────┬─────────────┘ │
│         ▲                                          │               │
│         │                                          ▼               │
│  ┌──────┴──────┐                         ┌─────────────────────┐   │
│  │ System Logs │                         │       Kibana        │   │
│  │ /var/log/*  │                         │   (Visualization)   │   │
│  └─────────────┘                         └─────────────────────┘   │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                      Demo Applications                       │   │
│  │  ┌─────────────────────┐    ┌─────────────────────────────┐ │   │
│  │  │   Secure App        │    │      Vulnerable App         │ │   │
│  │  │   (Port 8080)       │    │       (Port 8081)           │ │   │
│  │  │                     │    │                             │ │   │
│  │  │ ✓ Input sanitization│    │ ✗ No sanitization          │ │   │
│  │  │ ✓ Structured logs   │    │ ✗ Plain text logs          │ │   │
│  │  │ ✓ Rate limiting     │    │ ✗ No rate limiting         │ │   │
│  │  └─────────────────────┘    └─────────────────────────────┘ │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Demonstracija napada

### Log Injection napad na ranjivu aplikaciju

#### 1. Osnovni CRLF Injection

```bash
# Napad: Ubacivanje lažnog log zapisa
curl -X POST http://localhost:8081/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin\n2026-01-20 12:00:00 - Login SUCCESSFUL for user: hacker [ADMIN]", "password": "wrong"}'
```

**Očekivani rezultat u logu ranjive aplikacije:**
```
2026-01-20 10:30:00 - Login FAILED for user: admin
2026-01-20 12:00:00 - Login SUCCESSFUL for user: hacker [ADMIN]
```

#### 2. Log Flooding napad

```bash
# Generiranje velikog broja lažnih zapisa
for i in {1..1000}; do
  curl -s -X POST http://localhost:8081/login \
    -H "Content-Type: application/json" \
    -d '{"username": "flood'$i'", "password": "x"}' &
done
wait
```

#### 3. ANSI Escape Sequence napad

```bash
# Pokušaj skrivanja teksta u terminalu
curl -X POST http://localhost:8081/login \
  -H "Content-Type: application/json" \
  -d '{"username": "user\x1b[2J\x1b[1;1Hcleared", "password": "test"}'
```

### Usporedba sa sigurnom aplikacijom

```bash
# Isti napad na sigurnu aplikaciju
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin\n2026-01-20 12:00:00 - FAKE LOG", "password": "wrong"}'
```

**Očekivani rezultat:** Kontrolni znakovi su uklonjeni, log je siguran.

---

## Kibana Dashboard

### Pristup Kibani

1. Otvorite http://localhost:5601
2. Prijavite se: `elastic` / `ChangeMeNow123!`
3. Navigirajte na **Analytics → Dashboard**

### Preddefinirani dashboardi

| Dashboard | Opis |
|-----------|------|
| **Security Overview** | Pregled svih sigurnosnih događaja |
| **Authentication Monitor** | Praćenje prijava i odjava |
| **Attack Detection** | Otkrivanje log injection pokušaja |
| **System Health** | Zdravlje ELK stacka |

### Kreiranje novog dashboarda

1. **Analytics → Visualize Library → Create visualization**
2. Odaberite tip vizualizacije
3. Konfigurirajte data view: `security-*`
4. Spremite i dodajte na dashboard

---

## Konfiguracija

### Struktura direktorija

```
elk-security-monitoring/
├── podman-compose.yml          # Glavni compose file
├── .env.example                # Primjer environment varijabli
├── .env                        # Vaše konfiguracije (ne commitati!)
│
├── elasticsearch/
│   └── elasticsearch.yml       # Elasticsearch konfiguracija
│
├── logstash/
│   ├── logstash.yml           # Logstash konfiguracija
│   ├── pipelines.yml          # Pipeline definicije
│   └── pipeline/
│       ├── 01-input.conf      # Input konfiguracija
│       ├── 02-filter.conf     # Filter pravila
│       └── 03-output.conf     # Output konfiguracija
│
├── kibana/
│   └── kibana.yml             # Kibana konfiguracija
│
├── filebeat/
│   └── filebeat.yml           # Filebeat konfiguracija
│
├── app-secure/                 # Sigurna verzija aplikacije
│   ├── app.py
│   ├── requirements.txt
│   └── Containerfile
│
├── app-vulnerable/             # Ranjiva verzija aplikacije
│   ├── app.py
│   ├── requirements.txt
│   └── Containerfile
│
├── alerts/
│   └── rules.json             # Kibana alerting pravila
│
└── scripts/
    ├── setup.sh               # Inicijalni setup
    ├── demo-attack.sh         # Demo napada
    └── cleanup.sh             # Čišćenje okruženja
```

### Environment varijable (.env)

```bash
# Elasticsearch
ELASTIC_PASSWORD=ChangeMeNow123!
ELASTIC_VERSION=8.11.0

# Kibana
KIBANA_SYSTEM_PASSWORD=ChangeMeNow123!

# Stack resources
ES_JAVA_OPTS=-Xms2g -Xmx2g
LS_JAVA_OPTS=-Xms1g -Xmx1g

# Retention
LOG_RETENTION_DAYS=30
```

---

## Troubleshooting

### Elasticsearch ne starta

```bash
# Provjera memorijskih ograničenja
sudo sysctl -w vm.max_map_count=262144

# Trajno (dodati u /etc/sysctl.conf)
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

### Logstash connection refused

```bash
# Pričekajte da Elasticsearch bude spreman
podman-compose logs elasticsearch | grep "started"

# Restart Logstash
podman-compose restart logstash
```

### Kibana ne može pristupiti Elasticsearchu

```bash
# Provjera mreže
podman network ls
podman network inspect elk_mreza

# Reset mreže
podman-compose down
podman network rm elk_mreza
podman-compose up -d
```

### Provjera logova

```bash
# Svi logovi
podman-compose logs

# Specifični servis
podman-compose logs elasticsearch
podman-compose logs logstash
podman-compose logs kibana
```

---

## Zaustavljanje i čišćenje

```bash
# Zaustavljanje (podaci ostaju)
podman-compose down

# Zaustavljanje i brisanje volumena (OPREZ: briše sve podatke!)
podman-compose down -v

# Kompletno čišćenje
podman-compose down -v --rmi all
podman volume prune -f
```

---

## Dodatni resursi

- [Elastic Documentation](https://www.elastic.co/guide/)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Podman Documentation](https://docs.podman.io/)

---

## Licenca

Ovaj projekt je licenciran pod MIT licencom - pogledajte [LICENSE](LICENSE) datoteku za detalje.

---

## Autor

**Karlo Kalinić**

- Email: kalini.karlo@gmail.com
- TVZ - Diplomski studij Informacijska sigurnost i digitalna forenzika

---

## Odricanje odgovornosti

Ovaj projekt je namijenjen **isključivo u edukacijske svrhe**. Ranjiva aplikacija demonstrira sigurnosne propuste i ne smije se koristiti u produkcijskom okruženju. Autor ne snosi odgovornost za bilo kakvu zlouporabu ovog materijala.