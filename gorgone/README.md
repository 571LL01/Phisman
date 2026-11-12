# SIREN-CORE

Moteur de simulation de phishing (*Red Team as Code*). Délivre des pages d'hameçonnage, capture les artefacts chiffrés, exporte les résultats et envoie les emails de campagne. Toutes les opérations sont documentées, traçables et limitées aux autorisations du contrat RoE.

---

## Table des matières

1. [Architecture](#architecture)
2. [Prérequis](#prérequis)
3. [Démarrage rapide — dev](#démarrage-rapide--dev)
4. [Production — Docker](#production--docker)
5. [Référence de configuration](#référence-de-configuration)
6. [Clés de chiffrement](#clés-de-chiffrement)
7. [Templates intégrés](#templates-intégrés)
8. [Cycle de vie d'une campagne](#cycle-de-vie-dune-campagne)
9. [Export des artefacts](#export-des-artefacts)
10. [Admin TOTP](#admin-totp)
11. [Mailer](#mailer)
12. [Apostle — reconnaissance IMAP](#apostle--reconnaissance-imap)
13. [Purge et rotation](#purge-et-rotation)
14. [CI](#ci)
15. [Dettes techniques](#dettes-techniques)
16. [Règles d'engagement (RoE)](#règles-dengagement-roe)

---

## Architecture

```
cmd/sirencore        — binaire principal : HTTP, capture, CLI, export
internal/collect     — capture AES-256-GCM des artefacts
internal/tmpl        — rendu html/template, assets embarqués
internal/lethe       — templates built-in (TMP-001 … TMP-004)
internal/charon      — export JSON Lines authentifié par token
internal/store       — schéma opérationnel SQLite (campagnes, contacts, envois)
internal/db          — handle SQLite partagé, migrations, WAL
internal/dga         — génération déterministe de domaines (HMAC-SHA256)
internal/mail        — composition MIME + envoi SMTP STARTTLS
internal/admin       — session, TOTP, allowlist IP, PBKDF2
internal/apostle     — reconnaissance IMAP read-only stricte
deploy/              — Dockerfile.prod, docker-compose.yml, purge.sh, CI
```

---

## Prérequis

- **Dev** : Go 1.22+, pas de CGO requis (`modernc.org/sqlite` pure Go).
- **Production** : Docker ≥ 24, bash ≥ 4, curl, jq (pour `purge.sh`).
- **Race detector** : gcc requis (`CGO_ENABLED=1`), voir CI.

---

## Démarrage rapide — dev

```bash
# 1. Cloner
git clone … && cd gorgone

# 2. Clé de développement (32 octets, en mémoire uniquement)
export SIREN_DEV_KEYS=1
export SIREN_ARTIFACT_KEYS="$(openssl rand -hex 32):1"

# 3. Vérifier
go test ./... -count=1

# 4. Lancer
go run ./cmd/sirencore -config config.example.json
# → http://127.0.0.1:8080/healthz doit retourner "ok"
```

> `SIREN_DEV_KEYS=1` expose les clés dans l'environnement du processus.
> N'utiliser qu'en développement.

---

## Production — Docker

### 1. Générer la clé AES-256-GCM

```bash
mkdir -p secrets
openssl rand -out secrets/siren-key 32
# Protéger : chmod 600 secrets/siren-key
```

### 2. Générer la config (sans secret)

```bash
# TMP-001 (identifiant + OTP) :
CAMPAIGN=acme TEMPLATE=tmp-001 \
  STEP_B_TARGET=https://portal.example.com/done \
  bash deploy/generate-config.sh > config.json

# TMP-002 (vérification bancaire) :
CAMPAIGN=acme TEMPLATE=tmp-002 \
  STEP_B_TARGET=https://portal.example.com/done \
  bash deploy/generate-config.sh > config.json

# TMP-003 (signature de contrat, .p12/.pfx) :
CAMPAIGN=acme TEMPLATE=tmp-003 \
  ACCEPT_EXTS=".p12,.pfx" \
  STEP_B_TARGET=https://portal.example.com/done \
  bash deploy/generate-config.sh > config.json

# TMP-004 (seed de récupération, sans max_len) :
CAMPAIGN=acme TEMPLATE=tmp-004 \
  STEP_B_TARGET=https://portal.example.com/done \
  bash deploy/generate-config.sh > config.json
```

Variables optionnelles : `LISTEN` (défaut `0.0.0.0:8080`), `DATA_DIR` (défaut `/data`), `STEP_A_TARGET` (défaut `/c/$CAMPAIGN/$TEMPLATE/b`).

Puis éditer `config.json` pour ajouter d'autres campagnes ou templates.

### 3. Construire l'image

```bash
docker build -f deploy/Dockerfile.prod -t siren-core:latest .
```

Le binaire est compilé `CGO_ENABLED=0 -trimpath -ldflags="-s -w"`. L'image finale est `scratch` : aucun shell, aucune libc.

### 4. Préparer le volume de données

```bash
docker volume create siren-data

# Docker crée les volumes en 0755 root-owned.
# sirencore refuse de démarrer si data_dir est trop permissif (checkDataDirMode).
# Corriger les permissions avant le premier démarrage :
docker run --rm -u root \
  -v siren-data:/data \
  busybox chmod 700 /data
```

### 5. Démarrer

```bash
docker compose -f deploy/docker-compose.yml up -d

# Vérifier la santé
curl http://localhost:8080/healthz   # → ok
docker compose -f deploy/docker-compose.yml ps
```

### 6. Variables d'environnement

| Variable | Obligatoire | Valeur par défaut | Description |
|---|---|---|---|
| `SIREN_KEY_FILE` | **oui** | `/run/secrets/siren-key` | Chemin de la clé AES-256-GCM |
| `SIREN_DEV_KEYS` | non | — | `1` = clé depuis l'env (dev uniquement) |
| `SIREN_ARTIFACT_KEYS` | dev seulement | — | `<hex32>:<keyID>` si `SIREN_DEV_KEYS=1` |
| `SIREN_ARTIFACT_ACTIVE_KEY` | dev seulement | `1` | ID de la clé active |
| `SIREN_DEV` | non | — | `1` = CSRF admin désactivable + allowlist vide permise ; **incompatible avec `SIREN_KEY_FILE`** |

Le template `deploy/docker-compose.yml` monte quatre secrets : `siren-key` et
les trois secrets admin. Docker refuse de démarrer si un fichier listé sous
`secrets:` manque. Si vous n'activez pas l'admin, créez quand même les trois
fichiers (vides) ou retirez les trois entrées correspondantes du compose.
`generate-config.sh` ne génère pas le bloc `admin` : ajoutez-le à
`config.json` pour activer `/admin/*`.

### 7. Conteneur non-root et data_dir 0700

Le Dockerfile déclare `USER 1000:1000`. Le binaire appelle `checkDataDirMode` au démarrage et refuse tout répertoire accessible en lecture par groupe ou others. Le volume nommé Docker est créé 0755 : l'étape `chmod 700` ci-dessus est obligatoire, pas un contournement — c'est la contrainte documentée de Docker named volumes.

---

## Référence de configuration

Le fichier de config est du JSON strict (les champs inconnus font échouer le démarrage).

```jsonc
{
  "listen": "0.0.0.0:8080",
  "data_dir": "/data",
  // admin: optionnel. S'il est présent, /admin/* est monté et les trois
  // secrets sont lus depuis des fichiers. Voir "Référence Admin".
  // "admin": {
  //   "password_hash_file": "/run/secrets/admin-password-hash",
  //   "totp_secret_file": "/run/secrets/admin-totp-secret",
  //   "csrf_secret_file": "/run/secrets/admin-csrf-secret",
  //   "allowlist": ["10.0.0.0/8"],
  //   "rate_limit": 5
  // },
  // beacon_prefix: préfixe des routes beacon. Défaut "/__siren".
  // Ne pas utiliser /c, /assets, /export, /admin, /healthz.
  "beacon_prefix": "/__siren",
  // allow_http_target: autorise les cibles http:// (dev uniquement).
  "allow_http_target": false,
  // trusted_proxies: CIDRs des proxys qui peuvent positionner X-Forwarded-For.
  "trusted_proxies": ["172.16.0.0/12"],
  "campaigns": {
    "<campaign-id>": {
      "templates": {
        "<template-id>": {
          "<step-id>": {
            // target: cible après la soumission. Racine-relative (/c/…) pour
            // l'étape suivante, absolue (https://…) pour la sortie.
            "target": "/c/<campaign>/<template>/<next-step>",
            // mode: "inline" (défaut) ou "beacon".
            "mode": "inline",
            // fields: liste ordonnée des champs du formulaire.
            "fields": [
              {
                "name": "email",
                // kind: text | password | otp | iban | pan | seed | file
                "kind": "text",
                // max_len: interdit sur kind=seed (phrase irrécupérable si tronquée).
                "max_len": 254,
                // accept: extensions autorisées pour kind=file (minuscules, avec point).
                // Vide = accepter tout. Appliqué côté serveur indépendamment du filtre navigateur.
                "accept": [],
                // labels: texte visible par variante de langue.
                "labels": {
                  "fr": "Adresse e-mail",
                  "en": "Email address",
                  "de": "E-Mail-Adresse"
                }
              }
            ]
          }
        }
      }
    }
  }
}
```

### Référence SMTP (mailer)

Le mailer est configuré par code, pas par `config.json`. Paramètres `mail.SMTPConfig` :

| Champ | Type | Défaut | Description |
|---|---|---|---|
| `Host` | string | — | Hostname SMTP |
| `Port` | int | `993` | Port (587 = STARTTLS) |
| `Username` | string | — | Utilisateur SMTP |
| `Password` | string | — | Mot de passe SMTP (jamais dans config.json) |
| `ConnectTimeout` | duration | 10 s | Timeout dial + TLS |
| `SendTimeout` | duration | 30 s | Timeout DATA |

### Référence Admin

L'interface admin est **optionnelle** : elle n'est montée que si la clé
`admin` existe dans `config.json`. Les trois secrets viennent de **fichiers**,
jamais du JSON. Le décodage strict (`DisallowUnknownFields`) refuse un
`password_hash`, `totp_secret` ou `csrf_secret` écrit en clair dans la config.

```json
"admin": {
  "password_hash_file": "/run/secrets/admin-password-hash",
  "totp_secret_file": "/run/secrets/admin-totp-secret",
  "csrf_secret_file": "/run/secrets/admin-csrf-secret",
  "allowlist": ["127.0.0.1/32", "10.0.0.0/8"],
  "rate_limit": 5
}
```

| Champ JSON | Obligatoire | Description |
|---|---|---|
| `password_hash_file` | oui | Fichier contenant le vérifieur PBKDF2, une ligne |
| `totp_secret_file` | oui | Fichier contenant le secret base32 RFC 6238 |
| `csrf_secret_file` | oui hors `SIREN_DEV=1` | 32 octets **bruts** minimum, sans CR/LF |
| `allowlist` | oui hors `SIREN_DEV=1` | CIDRs autorisés sur tout `/admin/*` |
| `rate_limit` | non | Défaut `5` ; `0` désactive (dev uniquement) |

Les fichiers sont refusés s'ils sont répertoires, accessibles en écriture au
groupe ou au monde (POSIX ; contrôle ignoré sous Windows), ou au-delà de
64 Kio (4 Kio pour la clé CSRF). Les deux secrets texte sont `TrimSpace` ;
la clé CSRF est lue telle quelle : `openssl rand 32 > csrf.key`, pas d'écho.

**Invariants au démarrage** :

- `Config.Validate()` est appelé dans `loadAdminSecrets` avant l'ouverture du
  listener. Toute erreur est fatale : hash malformé, secret TOTP vide/invalide,
  `CSRFSecret` vide hors `SIREN_DEV=1`, allowlist vide hors `SIREN_DEV=1`,
  magasin de sessions ou logger absent.
- `SIREN_DEV=1` combiné à `SIREN_KEY_FILE` est **refusé** : le mode dev
  (CSRF désactivé, allowlist vide = tous les IPs) ne doit pas tourner sur des
  données de production.
- Une allowlist vide hors dev est un refus au boot, pas un « allow all »
  silencieux. En dev, vide signifie explicitement « tous les IPs ».
- Une session SQLite valide avant un redémarrage reste valide après ; elle est
  stockée hachée dans `admin_sessions` (migration 0005).

`newHandlerWithAdmin` monte le routeur sous une **garde unique**
`admin.Guard` : config invalide → 500, IP hors allowlist → 403 (avant toute
lecture de session, de formulaire ou de mot de passe), méthode mutante sans
CSRF → 403. `POST /admin/logout` est mutante : une déconnexion cross-origin
serait un déni de service, elle exige donc le jeton CSRF. `GET /admin/logout`
répond 405.

Générer les secrets :

```bash
# Hash du mot de passe admin (une ligne)
cat > /tmp/hash.go <<'EOF'
package main
import ("fmt"; "github.com/siren-core/gorgone/internal/admin")
func main() { h, _ := admin.HashPassword("mon-mot-de-passe"); fmt.Println(h) }
EOF
go run /tmp/hash.go > /run/secrets/admin-password-hash

# Secret TOTP base32 (une ligne)
openssl rand -base32 20 > /run/secrets/admin-totp-secret

# Clé CSRF brute, 32 octets, sans newline
openssl rand -out /run/secrets/admin-csrf-secret 32
```

Ne jamais stocker le mot de passe en clair. Le hash a la forme
`pbkdf2$600000$<salt-hex>$<hash-hex>`.

---

## Clés de chiffrement

Les artefacts sont chiffrés en **AES-256-GCM**, enveloppe `SCA1 | keyID | nonce | ciphertext`. L'AAD est l'ID de la ligne : un artefact ne peut pas être déplacé sur une autre ligne.

```bash
# Générer la clé active (32 octets)
openssl rand -out /run/secrets/siren-key 32

# La clé ne doit JAMAIS se trouver dans data_dir :
# sirencore vérifie au démarrage (GuardKeyLocation) et refuse si c'est le cas.
```

**Rotation des clés** :

```bash
# 1. Ajouter la nouvelle clé au fichier (format multi-clés dans keyset.go)
# 2. Re-sceller tous les artefacts avec la nouvelle clé active
sirencore -rotate-keys -config config.json

# 3. Vérifier qu'aucun artefact ne porte plus l'ancienne clé
# 4. Retirer l'ancienne clé (refusé si des artefacts la portent encore)
sirencore -retire-key 1 -config config.json
```

---

## Templates intégrés

| ID | Flux | Étape A | Étape B |
|---|---|---|---|
| `tmp-001` | Identité + OTP | Identifiant visible | Code à 6 chiffres (`otp`) |
| `tmp-002` | Vérification bancaire | Email + IBAN + Code postal | Confirmation (email rappelé) |
| `tmp-003` | Signature de contrat | Email professionnel | Upload certificat `.p12`/`.pfx` (`file`) |
| `tmp-004` | Réinitialisation | Email | Phrase de récupération (`seed`, jamais tronquée) |

Trois variantes de langue par template : **fr**, **en**, **de**.

Sélection de la langue : `?l=` exact → `Accept-Language` → `fr` → premier variant. La langue est portée dans l'action du formulaire pour que le POST suive la même langue.

**Attribution** : `?rid=<contactID>` dans le lien de livraison. L'ID est validé contre la campagne avant d'être stocké dans `contact_id` de l'artefact. Un `rid` inconnu ou hors-campagne laisse `contact_id` vide sans rejeter la soumission.

---

## Cycle de vie d'une campagne

```
1. Créer la campagne        → store.CreateCampaign
2. Importer les contacts    → store.AddContacts (email + vars, dédoublonnage par email)
3. Émettre un token d'export → sirencore -issue-token <campaign-id>
4. Envoyer les emails étape A → mail.Runner.Send (DryRun=true pour prévisualiser)
5. Collecter les artefacts  → les visiteurs soumettent les formulaires
6. Exporter les artefacts   → sirencore -export <campaign-id>  ou  GET /export/<campaign-id>
7. Envoyer les emails étape B → mail.Runner{PriorStep: "a"}.Send (uniquement les contacts qui ont reçu A)
8. Purger / archiver        → purge.sh keep (conserve) ou purge.sh rotate (détruit)
```

**Idempotence des envois** : un contact ayant déjà un enregistrement `sent` pour ce template+étape est sauté. Un enregistrement `failed` est réessayé.

**Plafond `PriorStep`** : basé sur les enregistrements d'envoi (ce que le mailer a envoyé), pas sur les artefacts collectés (ce que le visiteur a soumis). La gating par artefact est différée.

---

## Export des artefacts

```bash
# Émettre un token (une seule fois ; la valeur claire est affichée une seule fois)
sirencore -issue-token acme -config config.json

# Exporter via CLI (stdout, JSON Lines)
sirencore -export acme -config config.json
sirencore -export acme -since 2026-11-06T00:00:00Z -config config.json

# Exporter via HTTP
curl -H "Authorization: Bearer <token>" \
  http://localhost:8080/export/acme
```

**Format JSON Lines** (`application/x-ndjson`) :

```json
{"type":"artifact","id":"…","campaign_id":"…","template_id":"…","step":"…",
 "contact_id":"…","received_at":"…","remote_ip":"…",
 "fields":{…},"secrets":{…},"files":[…],"target":"…","fingerprint":null}
```

- `"type":"artifact"` sur chaque ligne normale.
- `"type":"error"` sur la dernière ligne si le flux a été interrompu. L'ID de la ligne corrompue est dans `"id"`. Reprendre avec `?since=<last_good_received_at>`.
- `contact_id` est toujours présent (chaîne vide si attribution absente).

**Authentification** : token haché SHA-256, jamais la valeur claire. 401 (+ `WWW-Authenticate`) si absent, 403 si mauvais token ou token d'une autre campagne.

**Plafond concurrent** : 2 exports simultanés (semaphore de 4 connexions SQLite, 2 réservées aux collecteurs). Au-delà : 503.

---

## Admin TOTP

```
GET  /admin/login    — formulaire de connexion (CSRF)
POST /admin/login    — mot de passe + code TOTP → cookie de session
GET  /admin/         — page stylée, lecture seule : compte + tableau des campagnes
POST /admin/logout   — révocation immédiate de la session (CSRF obligatoire)
```

`GET /admin/` rend une vraie page HTML autonome (CSS inline, aucun JavaScript,
aucune ressource externe) : en-tête, nombre de campagnes, tableau
identifiant/nom/état/date, bouton de déconnexion. Ce n'est pas un tableau de
bord métrique : aucun compteur d'envois, aucun graphique. En cas d'échec du
magasin, la page reste servie avec un avertissement et le bouton de
déconnexion reste accessible. Sans session : 302 vers `/admin/login`.
Une IP hors allowlist reçoit 403 avant toute lecture de session ou de mot de
passe.

**Mot de passe** : PBKDF2-SHA256, 600 000 itérations, sel 16 octets aléatoire.
Format : `pbkdf2$600000$<salt-hex>$<hash-hex>`. Comparaison en temps constant (`subtle.ConstantTimeCompare`). Voir section [Référence de configuration → Admin](#référence-de-configuration) pour la génération.

**TOTP** : RFC 6238, fenêtre ±1 pas (30 s), comparaison `hmac.Equal` (temps constant). Le secret base32 est validé au démarrage (`admin.ValidateTOTPSecret`). Un secret vide ou malformé fait échouer le démarrage avec un message explicite. Rejouer le même code (même pas, même utilisateur) retourne 401.

```bash
# Générer un secret TOTP et le QR code (provisioning hors ligne)
openssl rand -base32 20   # → secret à scanner dans un authenticator
```

**Rate limiting** : `admin.rate_limit` = N → 429 après N échecs par IP. Remis à zéro sur succès. `0` = désactivé (dev uniquement). Absent = `5`.

**Cookie** : `__Host-siren-session`, HttpOnly, Secure, SameSite=Lax, TTL 15 min glissantes. Requiert un reverse proxy TLS en production (`Secure=true` interdit le cookie sur HTTP).

---

## Mailer

```go
// 1. Composer
comp, _ := mail.NewComposer(mail.Config{
    Renderer:    renderer,          // *tmpl.Renderer configuré avec les templates
    FromAddress: "siren@example.com",
    FromName:    "Siren Platform",
    BaseURL:     "https://siren.example.com", // slash final interdit
    Campaign:    "acme",
    Template:    "tmp-001",
    Step:        "a",
    UnsubURL:    "https://siren.example.com/unsub?c=acme", // optionnel
})

// 2. Sender SMTP (STARTTLS obligatoire, TLS 1.2 minimum)
sender, _ := mail.NewSender(mail.SMTPConfig{
    Host:     "smtp.example.com",
    Port:     587,
    Username: "siren@example.com",
    Password: "smtp-pass",          // jamais dans config.json
})

// 3. Runner
runner, _ := mail.NewRunner(mail.RunnerConfig{
    Composer:  comp,
    Sender:    sender,
    Ops:       ops,       // store.Store
    Resolve:   resolver,  // collect.Resolver
    PriorStep: "a",       // vide = envoyer à tous les contacts
    DryRun:    false,     // true = rendre et loguer, ne pas envoyer
    Logger:    logger,
})

// 4. Envoyer
summary, err := runner.Send(ctx, "acme")
// summary.Sent / summary.Failed / summary.Skipped
```

**Corps HTML** : rendu complet de la page template, action absolue (`BaseURL + /c/…?rid=…&l=…`). Les blocs `<script>` et `<style>` sont supprimés avant la génération de la partie texte (le fingerprinter JavaScript ne doit pas apparaître dans le texte).

**Sécurité des en-têtes** : CR et LF refusés dans `To`, `From` et `Subject`. Noms d'affichage échappés (`"` et `\`) avant le Q-encoding.

**Langue** : résolue depuis les vars du contact (`lang`, `language`, `locale` en comparaison insensible à la casse). Repli sur le premier variant si langue inconnue.

---

## Apostle — reconnaissance IMAP

```go
result, err := apostle.Examine(ctx, apostle.Config{
    Host:         "imap.example.com",
    Port:         993,                 // 993 = TLS implicite ; 143 = STARTTLS automatique
    // STARTTLS:  true,                // force STARTTLS sur un autre port
    // ImplicitTLS: true,              // force le TLS implicite même sur 143
    Username:     "alice@example.com",
    Password:     "secret",
    FilterDomain: "example.com",       // vide = tout domaine
    MaxMessages:  200,                 // 0 = pas de limite (déconseillé)
    Timeout:      30 * time.Second,    // défaut 30 s même avec context.Background()
})
// result.Contacts       — adresses uniques, normalisées (minuscules), propriétaire exclu
// result.Partial        — vrai si MaxMessages atteint
// result.AddressTruncated — vrai si > 500 adresses extraites
```

```go
ok, err := apostle.Authenticate(ctx, cfg, "alice@example.com", "submitted-pass")
// ok = true → le serveur IMAP a accepté les identifiants capturés
// Reste intra-tenant : aucune exfiltration vers un tiers
```

**Garanties de lecture seule** (garanties par `internal/apostle/imap.go`) :

- `bannedCommands` : `SELECT`, `STORE`, `COPY`, `UID STORE`, `UID COPY`, `EXPUNGE`, `CLOSE`, `DELETE`, `RENAME`, `SUBSCRIBE`, `UNSUBSCRIBE`, `CREATE`, `APPEND`, `SETACL`, `DELETEACL`, `SETQUOTA` → `ErrWriteCommand` avant tout envoi réseau.
- Tout `FETCH BODY[` sans `.PEEK` → `ErrFetchWithoutPeek` avant tout envoi réseau. `BODY.PEEK` ne pose pas le flag `\Seen`.
- `EXAMINE` (jamais `SELECT`) : le mode read-only est refusé par le serveur si quelqu'un tente `STORE` même en mode EXAMINE.
- Contenu des messages non conservé : seules les adresses des en-têtes `From`, `To`, `Cc` sont retenues.
- Plafond d'adresses : 500 (`const maxAddresses = 500` dans `apostle.go`). `result.AddressTruncated = true` si atteint.
- Timeout global appliqué dès le `context.WithDeadline` (même avec `context.Background()`).

> **Note** : `LOGIN` envoie le mot de passe sur la couche TLS. Le port 993 utilise le TLS implicite ; le port 143 négocie `STARTTLS` automatiquement (échec explicite si le serveur le refuse). `Config.STARTTLS` force le chemin STARTTLS sur un autre port, `Config.ImplicitTLS` force le TLS implicite sur 143.

---

## Purge et rotation

```bash
# Exporter sans détruire (server intact)
EXPORT_DIR=./exports bash deploy/purge.sh keep acme $TOKEN siren-core

# Avec borne temporelle
EXPORT_DIR=./exports bash deploy/purge.sh keep acme $TOKEN siren-core 2026-11-06T00:00:00Z

# Exporter, vérifier, détruire le volume et redémarrer sur un nouveau nom
EXPORT_DIR=./exports bash deploy/purge.sh rotate acme $TOKEN siren-core
```

**Vérifications avant toute destruction** (le serveur n'est jamais touché en cas d'échec) :

1. Fichier non vide → sinon exit 2.
2. Dernier octet = `0x0a` (stream NDJSON complet) → sinon exit 3.
3. Chaque ligne valide JSON via `jq` → sinon exit 3.

En mode `rotate`, le redémarrage utilise `docker compose up -d` avec un nom de conteneur horodaté (`<container>-<unix-timestamp>`), ce qui change le hostname interne et garantit un démarrage propre.

---

## CI

Cinq jobs indépendants dans `.github/workflows/ci.yml` :

| Job | `CGO_ENABLED` | Description |
|---|---|---|
| `fmt` | — | `gofmt -l .` — échoue si des fichiers divergent |
| `build` | 0 | `go build -trimpath -ldflags="-s -w"` + vérification binaire statique |
| `test` | 0 | `go test ./... -count=1 -timeout 300s` |
| `race` | 1 | `go test -race ./... -count=1` avec gcc (ubuntu-latest) |
| `symlink` | 0 | Tests symlink — échoue si `--- SKIP` apparaît sur Linux |

Le job `race` installe gcc via `apt-get`. En production le build reste `CGO_ENABLED=0` (binaire entièrement statique).

---

## Dettes techniques

Voir [DEBT.md](DEBT.md) pour la liste complète avec commits de preuve.

**Aucune dette de sécurité ouverte.** D-1 (CSRF) est soldée : double-submit cookie HMAC-SHA256 dans `csrf.go`, `LoginPageHandler` sert le formulaire avec le token, `LoginHandler` le vérifie avant le mot de passe, et les handlers refusent de servir sans `CSRFSecret` hors `SIREN_DEV=1`. D-2 (sessions SQLite) et D-5 (STARTTLS 143) sont également soldées.

| Réf | Dette | Atténuation | Bloquant |
|---|---|---|---|
| ~~D-1~~ | ~~CSRF sur mutations admin~~ | Soldée | — |
| ~~D-2~~ | ~~Sessions admin en mémoire~~ | Soldée : `SQLiteSessionStore`, migration 0005 | — |
| D-3 | `Secure` cookie sur HTTP | Proxy TLS documenté dans compose | Non (proxy requis) |
| D-4 | Gating par soumission | PriorStep par envoi, documenté | Non |
| ~~D-5~~ | ~~STARTTLS IMAP port 143~~ | Soldée : `dialSTARTTLS` + tests | — |
| D-6 | 400 brut sur upload refusé | `accept=` guide le navigateur | Non |

---

## Règles d'engagement (RoE)

> Ce document est un **modèle contractuel**. Il doit être complété, relu par les deux parties et signé avant toute opération. L'exécution de SIREN-CORE hors d'un cadre RoE signé est **strictement interdite**.

---

### 1. Parties

| Rôle | Entité | Représentant | Contact |
|---|---|---|---|
| Commanditaire | _organisation cliente_ | _nom, fonction_ | _email, téléphone_ |
| Équipe Red Team | _prestataire_ | _nom, fonction_ | _email, téléphone_ |
| Responsable RSSI | _organisation cliente_ | _nom_ | _email_ |
| Point de contact opérationnel | _organisation cliente_ | _nom_ | _email, téléphone 24/7_ |

---

### 2. Périmètre autorisé

#### 2.1 Organisations et tenants cibles

| Tenant | Domaine principal | Boîtes IMAP autorisées |
|---|---|---|
| _acme_ | _acme.example.com_ | _liste exhaustive_ |

Toute boîte hors de cette liste est **hors périmètre**. L'opérateur doit vérifier que `FilterDomain` dans la configuration Apostle correspond exactement au domaine listé.

#### 2.2 Campagnes autorisées

| Campaign-ID | Template | Étapes | Description |
|---|---|---|---|
| _acme-q4_ | tmp-001, tmp-002 | a, b | Phishing bancaire Q4 2026 |

#### 2.3 Contacts

La liste de contacts est fournie par le commanditaire et importée via `store.AddContacts`. Aucun contact ne peut être ajouté sans accord écrit du commanditaire.

#### 2.4 Infrastructure autorisée

| Ressource | Valeur |
|---|---|
| Serveur SIREN-CORE | _IP ou FQDN_ |
| Domaines d'envoi | _liste_ |
| Relais SMTP | _FQDN : port_ |
| Serveur IMAP cible | _FQDN : 993_ |

---

### 3. Fenêtre d'opération

| Champ | Valeur |
|---|---|
| Date de début | _YYYY-MM-DD HH:MM UTC_ |
| Date de fin | _YYYY-MM-DD HH:MM UTC_ |
| Plages horaires autorisées | _ex. lundi–vendredi 08h00–18h00 UTC_ |
| Zones horaires exclues | _ex. jours fériés France_ |

Toute opération hors fenêtre requiert une autorisation écrite préalable.

---

### 4. Déconfliction

- Le commanditaire notifie ses équipes SOC/CERT de la campagne avant le début (sans détailler le scénario).
- Les adresses IP du serveur SIREN-CORE sont communiquées au SOC pour éviter le blocage automatique.
- Tout déclenchement d'alerte SOC en cours de campagne est communiqué à l'équipe Red Team dans les 2 heures.
- En cas d'incident de sécurité indépendant, l'équipe Red Team suspend les opérations jusqu'à déconfliction explicite.

---

### 5. Ce qui est autorisé

- Délivrance de pages d'hameçonnage aux contacts de la liste.
- Capture des artefacts soumis (chiffrés AES-256-GCM, jamais en clair en base).
- Envoi d'emails depuis les adresses et domaines listés en §2.4.
- Lecture IMAP read-only (`EXAMINE`, `SEARCH`, `FETCH BODY.PEEK`) sur les boîtes listées en §2.1.
- Vérification du mot de passe capturé contre le serveur IMAP intra-tenant (§2.4). Résultat : booléen. Le mot de passe n'est ni stocké ni loggué.

---

### 6. Ce qui est interdit (enforcement technique + contractuel)

| Interdiction | Enforcement technique |
|---|---|
| Écriture IMAP (`SELECT`, `STORE`, `COPY`, `EXPUNGE`, …) | `bannedCommands` dans `apostle/imap.go` |
| `FETCH` sans `.PEEK` (poserait `\Seen`) | `ErrFetchWithoutPeek` avant envoi réseau |
| Conservation du contenu des messages | Seules les adresses en-têtes sont retenues |
| Mot de passe en clair en base | `NewSecret` → SHA-256 + longueur uniquement |
| Clé de chiffrement dans `data_dir` | `GuardKeyLocation` au démarrage |
| `max_len` sur une seed | Refusé au boot (`validKind`) |
| Exfiltration des identifiants captifs vers un tiers | Authentification intra-tenant uniquement |
| Envoi hors des domaines autorisés | Configuration opérateur + RoE |
| Ajout de contacts hors liste approuvée | Autorisation écrite requise |

---

### 7. Plafonds techniques

| Paramètre | Valeur | Modifiable par RoE |
|---|---|---|
| Adresses IMAP extraites par boîte | 500 | non |
| Messages IMAP examinés | configurable (`MaxMessages`) | oui |
| Timeout IMAP | 30 s (défaut) | oui |
| Exports simultanés | 2 | non |
| Durée de session admin | 15 min glissantes | non |
| Tentatives de login admin | configurable (`RateLimit`) | oui |
| Fenêtre TOTP | ±1 pas (90 s) | non |

---

### 8. Données et rétention

- Les artefacts sont chiffrés dès l'entrée dans le handler et ne sont déchiffrés que lors d'un export authentifié.
- Le fichier d'export est en clair. Il doit être transmis chiffré (GPG, SFTP) et supprimé du serveur après livraison.
- `purge.sh rotate` exporte et vérifie le fichier avant toute destruction. Le rapport est livré au commanditaire avant l'effacement du volume.
- Durée de rétention des artefacts : _à définir, ex. 30 jours après fin de campagne_.
- Les logs du serveur (`journald` / `json-file`) contiennent les IPs et les IDs d'artefact. Ils sont soumis à la même politique de rétention.

---

### 9. Exclusions déclarées

Les éléments suivants sont **hors périmètre** de la présente campagne :

- Toute boîte IMAP non listée en §2.1.
- Tout domaine non listé en §2.4.
- Les systèmes d'infrastructure (routeurs, switches, DNS, AD) du commanditaire.
- Les filiales et partenaires du commanditaire non explicitement listés.
- Toute action destructrice non couverte par `purge.sh rotate` (ex. `DROP TABLE`).

---

### 10. Arrêt d'urgence

```bash
# Arrêt immédiat du serveur
docker stop <container-name>
```

**Révocation du token d'export** : le token est un hash SHA-256 stocké dans la
colonne `export_token_hash` de la table `campaigns`. Pour le révoquer, écraser
avec un nouveau token (la valeur précédente est perdue) :

```bash
# Émet un nouveau token ; l'ancien cesse immédiatement d'être valide.
sirencore -issue-token <campaign-id> -config config.json
```

Ou, pour interdire tout export jusqu'à la prochaine émission, mettre la colonne
à vide directement :

```bash
sqlite3 artifacts.db \
  "UPDATE campaigns SET export_token_hash = '' WHERE id = '<campaign-id>';"
# → GET /export/<campaign-id> retourne désormais 403 "campaign has no export token"
```

Contacter le point de contact opérationnel (§1) dans les **30 minutes** suivant
tout arrêt non planifié.

---

### 11. Signature

| | Commanditaire | Red Team lead |
|---|---|---|
| Nom | | |
| Fonction | | |
| Date | | |
| Signature | | |

---

*Modèle SIREN-CORE — version du dépôt `github.com/siren-core/gorgone`.*
