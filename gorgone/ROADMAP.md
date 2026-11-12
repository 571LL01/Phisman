# ROADMAP — SIREN-CORE

## État

Les étapes 0 à 12 sont livrées. L'historique fait foi (`git log`).
L'étape 13 est la première qui expose l'interface d'administration dans le
binaire : `internal/admin` n'est plus un paquet mort.

---

## Étape 13 — Monter l'interface admin dans `cmd/sirencore`

### Objectif

`GET /admin/` doit être une route réellement servie par le binaire de
production, derrière une garde unique et fail-closed, avec des secrets lus
depuis des fichiers. « Dashboard » signifie ici une page HTML stylée en
lecture seule (campagnes + déconnexion), pas un tableau de bord métrique.

### Périmètre

1. **Config `admin` optionnelle et stricte**
   - Bloc `admin` dans `config.json` : `password_hash_file`,
     `totp_secret_file`, `csrf_secret_file`, `allowlist`, `rate_limit`.
   - `DisallowUnknownFields` déjà en place : un `password_hash`,
     `totp_secret` ou `csrf_secret` inline est refusé au chargement.
   - Absent = interface non montée. Présent = `/admin/*` actif.
   - Aucun secret n'est lu par `-healthcheck` ni par les modes CLI
     (`-rotate-keys`, `-retire-key`, `-export`, `-issue-token`).

2. **Chargement des secrets au boot**
   - `loadAdminSecrets` lit les trois fichiers après le `switch` des modes CLI
     et avant l'ouverture du listener.
   - Fichiers réguliers uniquement ; refus si accessibles en écriture au
     groupe ou au monde (POSIX ; ignoré sous Windows) ; plafond 64 Kio
     (4 Kio pour la clé CSRF).
   - Secrets texte `TrimSpace` ; clé CSRF brute, minimum 32 octets, CR/LF
     refusés (pas de trim silencieux).
   - `admin.NewSQLiteSessionStore` sur le handle partagé (migration 0005).
   - `Config.Validate()` appelé avant le listener : toute erreur = exit non nul.

3. **Ordre de démarrage**
   - `SIREN_DEV=1` + `SIREN_KEY_FILE` défini → refus **avant** `loadKeys`.
   - Le refus est explicite : le mode dev (CSRF désactivé, allowlist vide =
     tous les IPs) ne doit pas tourner sur des données de production.
   - `run` monte l'admin via `newHandlerWithAdmin` ; `newHandler` reste le
     wrapper 4 arguments des tests existants.

4. **Garde unique sur tout `/admin/*`**
   - `admin.Guard` enveloppe le routeur, monté sur `/admin` et `/admin/`.
   - Ordre : config invalide → 500 ; IP hors allowlist → 403 ; méthode
     mutante sans CSRF → 403 ; handler.
   - `POST /admin/logout` est mutante et exige le CSRF : un logout
     cross-origin serait un déni de service.
   - `GET /admin/logout` → 405. Chemin inconnu sous `/admin/` → 404.

5. **Page `GET /admin/`**
   - HTML autonome : CSS inline, aucun JavaScript, aucune ressource externe.
   - En-tête, nombre de campagnes, tableau identifiant/nom/état/date, bouton
     de déconnexion avec jeton CSRF.
   - CSP `default-src 'none'`, `form-action 'self'`, `frame-ancestors 'none'`,
     `nosniff`, `no-store`.
   - Échec du magasin : page 200 avec avertissement, déconnexion toujours
     accessible.

6. **Tests**
   - `GET /admin/` sans session → 302 vers `/admin/login`.
   - `POST /admin/logout` sans CSRF → 403 **et** session toujours valide.
   - `POST /admin/logout` avec CSRF → 303 et session révoquée.
   - `POST /admin/login` avec `CSRFSecret` vide hors `SIREN_DEV=1` → 500.
   - Démarrage sans CSRF (fichier vide) → `run` retourne une erreur,
     `exitCodeFor` non nul.
   - IP hors allowlist → 403 avant toute lecture de session, de formulaire ou
     de mot de passe ; aucun cookie émis.
   - `SIREN_DEV=1` + `SIREN_KEY_FILE` → refus au boot.
   - Session SQLite valide avant redémarrage → acceptée après
     (`TestSQLiteSessionStoreSurvivesRestart`).
   - Décodage strict : secret admin inline refusé.
   - Allowlist vide hors dev → `Validate` refuse ; en dev → acceptée.

### Gate

Identique aux étapes précédentes :

```bash
gofmt -l .
go vet ./...
go build ./...
go test ./... -count=1 -p 1
```

Plus le test dédié **IP hors allowlist → 403 avant tout traitement**
(`TestRouterAllowlistBeforePassword` et `TestAdminRouteOutsideAllowlistIs403`).

Non vérifiables localement sur cette machine (absence d'outils) :
`go test -race` (pas de gcc), build/run Docker, `shellcheck`. Ils restent
dans la gate CI.

### Cas limites tranchés

| Cas | Décision |
|---|---|
| `SIREN_DEV=1` + `SIREN_KEY_FILE` | Refus au boot, avant lecture de la clé. Message nommant les deux variables. |
| Session valide avant redémarrage | Acceptée après : sessions SQLite hachées, migration 0005. |
| Logout sans CSRF | 403 ; la session n'est pas révoquée. |
| Allowlist vide hors `SIREN_DEV=1` | Refus au boot. Pas de « allow all » implicite. |
| Allowlist vide avec `SIREN_DEV=1` | Tous les IPs, comportement documenté et testé. |
| `csrf_secret_file` vide avec `SIREN_DEV=1` | Autorisé : CSRF désactivé, uniquement en dev. |
| Fichier CSRF < 32 octets ou avec CR/LF | Refus au boot ; pas de normalisation silencieuse. |
| `rate_limit` absent | Défaut 5. |
| `rate_limit: 0` | Désactivé explicitement (dev uniquement). |
| Magasin de campagnes indisponible | Page 200 avec avertissement ; logout toujours possible. |

### Décisions

- **Option 1** : monter l'admin dans `cmd/sirencore`, ne pas documenter un
  paquet mort.
- **Un seul middleware** : `admin.Guard` couvre toutes les routes, y compris
  les chemins inconnus et le logout. Pas de garde par handler.
- **Secrets fichiers uniquement** : `config.json` ne peut pas porter un secret,
  même par accident ; le décodage strict le refuse.
- **Dashboard** : page stylée en lecture seule. Aucune mutation de campagne,
  aucun compteur d'envois, aucun graphique dans cette étape.
- **Sessions** : SQLite pour la persistance ; le store mémoire reste réservé
  aux tests.

### Hors périmètre

- Création/armement de campagnes depuis l'admin.
- Rendu configurable ou thème.
- `go test -race`, Docker et shellcheck en local (gate CI uniquement).

---

## Étape 14 — Tunnel de suivi (ouvertures et clics)

### Objectif

Rendre visibles les deux étapes du tunnel situées entre l'envoi et la
soumission : l'**ouverture** de l'email et le **clic** sur le lien. Avant cette
étape, une cible qui ouvrait, cliquait et lisait la fausse page sans rien
soumettre était invisible.

### Périmètre

1. **Table `events` (migration 0007)** — métadonnée opérationnelle en clair, à
   côté de `sends` : `campaign_id`, `contact_id`, `template_id`, `step_id`,
   `kind ∈ {open, click}`, `occurred_at`, `remote_ip`, `user_agent`. FK vers
   `campaigns` et `contacts`, index `(campaign_id, kind, contact_id)`. Jamais
   de secret.
2. **Store** — `RecordEvent`, `EventStats` (contacts distincts par `kind`),
   `ListEventsByCampaign`, implémentés par `SQL` et `Fake`, couverts par le
   contrat partagé `TestStoreContract`.
3. **Ouverture** — pixel GIF 1×1 transparent servi sur
   `<beacon_prefix>/o/{campaign}/{template}/{step}?rid=…` (4 segments : aucun
   conflit avec le beacon post-interaction à 3 segments). Le mailer injecte le
   pixel dans tout corps HTML ; jeton `{{.Pixel}}` pour un placement explicite.
   L'image est toujours servie, l'attribution est best-effort.
4. **Clic** — le `GET` de la page enregistre un `click` dès que le `rid` résout,
   sur contexte détaché, sans jamais changer le rendu.
5. **Statistiques** — tunnel en contacts distincts sur le dashboard et la page
   de campagne, avec taux `Ouverts/Envois A` et `Cliqués/Envois A`.

### Cas limites tranchés

| Cas | Décision |
|---|---|
| `rid` absent ou inconnu sur le pixel/clic | Image/page servie, aucun événement enregistré. |
| Coordonnée (template/step) inexistante sur le pixel | Image servie, non enregistrée (funnel propre). |
| Même contact ouvre/clique N fois | Compté 1 fois par étape (`COUNT(DISTINCT contact_id)`). |
| Corps d'email en texte brut | Pas de pixel (une partie texte ne porte pas d'image). |
| Panne de stockage sur `RecordEvent` | Journalisée ; la page/le pixel répond normalement. |

### Fiabilité (documentée, pas masquée)

Le suivi d'ouverture dépend du chargement d'une image : sur-compté par les
proxys d'images (Gmail, Outlook), sous-compté si les images sont bloquées. Il
mesure « vu ou préchargé », jamais une certitude. Voir README § Suivi.

### Hors périmètre (différé)

- Export NDJSON des événements (le tunnel est visible en UI ; l'export reste
  limité aux artefacts).
- Décompte des soumissions dans le tunnel du dashboard (reste sur la page
  Artefacts).
- Suivi d'ouverture pour le chemin `internal/mail` (Composer/Runner), non câblé
  dans l'UI actuelle.
