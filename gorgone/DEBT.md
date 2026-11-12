# DEBT.md — Dettes techniques soldées et ouvertes

Ce fichier liste toutes les dettes connues. Les dettes soldées ont un commit de
preuve. Les dettes ouvertes ont une raison explicite et un impact déclaré.

---

## Soldées

| Dette | Commit | Preuve |
|---|---|---|
| Digest certificat borné (`LimitReader`) | `6f5c486` | `TestFileDigestCoversWholeUploadWithinBudget` |
| `accept` non validé au boot | `916dc9f` | `TestAcceptNormalizesAndValidatesExtensions` |
| Seed tronquée en silence | `916dc9f` | `TestTMP004RejectsSeedMaxLen` |
| `accept` insensible à la casse | `c114658` | `TestUploadAcceptIsEnforcedServerSide` (cert.P12) |
| Sync copie TMP-003 ↔ config | `7e569ac` | `TestTMP003AcceptListMatchesSignatureCopy` |
| `preferredLang` direct sur `vars[key]` | `318885e` | `send.go` : `tmpl.Vars.Lookup` case-insensible |
| `truncateRunes` tronquant un rune | `318885e` | `recordFailure` dans `send.go` |
| Mot de passe SHA-256 nu | `57db743` | PBKDF2-SHA256 600k iter, `TestHashPasswordAndCheck` |
| Rate limit absent sur login | `57db743` | `rateLimiter`, `TestRateLimitLockout` |
| Map de rejeu TOTP globale | `57db743` | `replayStore` par `(user,step)`, `TestReplayIsPerUserNotGlobal` |
| Secret TOTP non validé au boot | `57db743` | `ValidateTOTPSecret`, `TestValidateTOTPSecret` |
| **D-1 CSRF sur mutations admin** | `3ecf330` + `6a4c032` | Double-submit cookie HMAC-SHA256, `LoginPageHandler`, `CSRFSecret`; `Config.Validate` + garde fail-closed refusent tout démarrage/requête sans CSRF hors `SIREN_DEV=1` |
| **D-2 Sessions admin en mémoire** | commit suivant | `SQLiteSessionStore`, migration `0005_admin_sessions`, `TestSQLiteSessionStoreSurvivesRestart` |
| **D-5 STARTTLS IMAP port 143** | commit suivant | `useSTARTTLS`, `dialSTARTTLS`, `TestDialSTARTTLSUpgradesToTLS`, `TestDialSTARTTLSRefused` |
| `SELECT` IMAP non interdit | `3cc9892` | `bannedCommands`, `TestBannedCommandGuard` |
| `FETCH` sans `.PEEK` | `3cc9892` | `ErrFetchWithoutPeek`, `TestFetchWithoutPeekIsRefused` |
| Connexion IMAP non fermée | `3cc9892` | `defer conn.Close()` dans `logout()` |
| Adresses non bornées | `3cc9892` | `maxAddresses=500`, `TestAddressTruncation` |
| Secrets Docker 0444 refusés | `d92bcc4` | `LoadKeyFile &0o022`, `TestLoadKeyFileAcceptsDockerSecretPermissions` |
| Healthcheck `wget` absent de scratch | `978bd18` | `-healthcheck` flag, `TestRunHealthcheckReturnsZeroOnOK` |
| `COPY /dev/null` fragile | `d92bcc4` | `RUN mkdir+touch+chown` dans builder |
| CA certs absents de scratch | `d92bcc4` | `apk add ca-certificates` + `COPY --from=builder` |
| `chown` absent sur volume | `978bd18` | Init container `busybox: chown 1000:1000 && chmod 700` |
| `/tmp` absent avec `read_only` | `978bd18` | `tmpfs: /tmp:size=64m,mode=1777` |
| VOLUME capturé après `docker rm` | `1c9ca89` | Capturé avant `docker stop` dans `purge.sh` |
| Ligne `type:error` indiscernable | `f38da42` | `"type":"artifact"` / `"type":"error"` sur toutes les lignes |
| `python3` dans `purge.sh` | `1c9ca89` | `curl --get --data-urlencode` |
| Pas de `.dockerignore` | `1c9ca89` | `.dockerignore`, `secrets/` en tête |
| Export bloquant indéfiniment | `1c9ca89` | `--max-time`, `CURL_MAX_TIME` |
| Injections d'en-têtes mail | `318885e` | `validateHeaderValue` To/From/Subject, `TestComposeRejectsCRLFInFromConfig` |
| Noms d'affichage non échappés | `318885e` | `sanitizeDisplayName`, `TestSanitizeDisplayNameEscapesQuotesAndBackslash` |
| `<script>/<style>` dans le texte | `318885e` | `scriptRe/styleRe`, `TestHTMLToTextStripsScriptAndStyle` |
| `makeAbsolute` double slash | `318885e` | `rewriteAttr`, `TestMakeAbsoluteDoesNotDoubleSlash` |
| `RequestedLang` vs `SelectedLang` | `318885e` | `RenderFull`, `TestComposeRequestedVsSelectedLang` |

---

## Ouvertes

Les dettes ci-dessous sont connues, documentées et non régressives : elles ne
causent pas de corruption silencieuse ni de fuite de données. Elles sont
conservées ouvertes par choix de scope ou par dépendance externe.

Aucune dette de sécurité n'est ouverte. D-1 (CSRF), D-2 (sessions) et D-5
(STARTTLS) sont soldées.

---

### D-3 — `Secure=true` incompatible avec HTTP local

**Impact** : le cookie `__Host-siren-session` n'est pas envoyé par le navigateur
sur une connexion HTTP. L'admin panel est inaccessible sans HTTPS.

**Atténuation en place** : le compose expose uniquement `127.0.0.1:8080`
(loopback), ce qui impose un reverse proxy TLS sur le même hôte. C'est documenté
dans `docker-compose.yml` et le README.

**Résolution** : option `--insecure-cookies` ou `allow_insecure_cookies: true`
en config, qui retire `Secure` et `__Host-` pour les déploiements de
développement sans TLS. Produire un avertissement visible au démarrage.

**Horizon** : commodité dev, non bloquant en prod avec le proxy documenté.

---

### D-4 — Gating par soumission (PriorStep basé sur les envois)

**Impact** : `Runner.PriorStep` gate l'envoi de l'étape B sur la présence d'un
enregistrement `sent` pour l'étape A dans la table `sends` — ce que le mailer
a envoyé, pas ce que le visiteur a soumis. Un contact qui a reçu l'email A mais
n'a pas cliqué sera quand même éligible à l'email B.

**Atténuation en place** : le comportement est documenté dans le code et le
README. Les campagnes de phishing expédient généralement les deux étapes en
séquence ou gate sur le click tracker, pas sur le collecteur.

**Résolution** : `Runner` requêterait `collect.Store.Export` pour vérifier
l'existence d'un artefact pour l'étape A avant d'envoyer B. Implique un accès
croisé entre `internal/mail` et `internal/collect`.

**Horizon** : campagnes multi-étapes avec gate stricte par soumission.

---

### D-5 — STARTTLS IMAP (port 143)

**Soldée.** `apostle.dial` détecte le port 143, ouvre une connexion TCP nue, lit
le greeting, envoie `STARTTLS`, vérifie le `OK`, puis upgrage via
`tls.Client`. `Config.STARTTLS` force le chemin sur un autre port et
`Config.ImplicitTLS` force le TLS implicite sur 143. Les tests
`TestDialSTARTTLSUpgradesToTLS` et `TestDialSTARTTLSRefused` couvrent les deux
issues.

---

### D-6 — Réponse 400 brut sur upload refusé (UX)

**Impact** : si un visiteur téléverse un fichier avec une mauvaise extension sur
l'étape B de TMP-003, il reçoit un 400 en texte brut et perd le formulaire
(re-chargement nécessaire).

**Atténuation en place** : l'attribut `accept=".p12,.pfx"` du champ file guide
le sélecteur de fichiers du navigateur. Les navigateurs récents ne proposent que
les fichiers conformes. La validation serveur reste nécessaire mais touche peu
de visiteurs réels.

**Résolution** : `Capture` retournerait un 200 avec le formulaire ré-rendu et un
message d'erreur visible. Implique que le renderer accepte un message d'erreur
et que la réponse soit 200 (formulaire affiché) plutôt que 400.

**Horizon** : amélioration UX, pas bloquant pour la collecte.

---

## Résumé

| Débt | Sécurité | Bloquant prod |
|---|---|---|
| D-1 CSRF | ✅ soldée | — |
| D-2 Sessions mémoire | ✅ soldée | — |
| D-3 Secure+HTTP | non | Non (proxy documenté) |
| D-4 PriorStep | non | Non |
| D-5 STARTTLS 143 | ✅ soldée | — |
| D-6 400 brut upload | non | Non |

**Aucune dette de sécurité n'est ouverte.** D-1, D-2 et D-5 sont soldées avec
tests à l'appui.
