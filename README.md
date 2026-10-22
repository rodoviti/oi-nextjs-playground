# SPID OIDC Playground

PoC minimale in Next.js (App Router), TypeScript e Better Auth: login OIDC con livello
minimo SPID L2/L3 e sessioni JWE stateless con scadenza assoluta di **1 ora**.
Non richiede database.

## Avvio

Usare Node.js >= 20.19 (consigliato Node.js 22 LTS).

```sh
npm ci
```

Configurare le variabili nell'ambiente del processo o, in locale, nel proprio
`.env.local` non versionato:

| Variabile | Descrizione |
| --- | --- |
| `BETTER_AUTH_URL` | URL pubblico dell'app, letto automaticamente da Better Auth: `http://localhost:3000` senza proxy, `https://localhost:3000` nel Dev Container con Traefik |
| `BETTER_AUTH_SECRET` | Segreto casuale di almeno 32 caratteri, letto automaticamente da Better Auth, generabile con `openssl rand -base64 32` |
| `OIDC_ISSUER` | Issuer dell'IdP, con discovery OIDC standard |
| `OIDC_CLIENT_ID` | Client ID registrato presso l'IdP |
| `OIDC_CLIENT_SECRET` | Client secret, da conservare solo sul server |
| `OIDC_ACR_L2` | Opzionale; default `https://www.spid.gov.it/SpidL2` |
| `OIDC_ACR_L3` | Opzionale; default `https://www.spid.gov.it/SpidL3` |

I valori `acr` devono coincidere con quelli accettati e restituiti dall'IdP.
L'issuer deve usare HTTPS; HTTP e' consentito solo su `localhost` per i test.
Non inserire segreti in variabili `NEXT_PUBLIC_*` o nel repository.
Il file di esempio delle variabili non e' incluso per le restrizioni di accesso
dell'ambiente in cui e' stata creata la PoC.

Registrare **entrambi** i redirect URI sullo stesso client OIDC:

```text
http://localhost:3000/api/auth/callback/spid-l2
http://localhost:3000/api/auth/callback/spid-l3
```

In produzione sostituire l'origine con quella HTTPS effettiva e aggiornare
`BETTER_AUTH_URL`. L'app assume un confidential client con autenticazione al token
endpoint `client_secret_basic`, Authorization Code Flow, PKCE S256 e supporto
a `prompt=login`. Richiede gli scope `openid profile email` e un claim `email`
nell'ID token, necessario per il login OAuth di Better Auth; i dati identificativi
visualizzati provengono dall'ID token verificato. Il parametro di autorizzazione
`idp` mantiene la selezione dell'IdP UAT gia' configurata in `src/auth.config.ts`.
Una configurazione SPID/CIE con client
assertion, PAR o request object firmati richiede un'integrazione specifica, non
compresa in questa PoC OIDC generica.

```sh
npm run dev
```

Aprire <http://localhost:3000>. La stessa pagina mostra lo stato di autenticazione,
i dettagli della sessione e i pulsanti **Login con SPID L2** / **Login con SPID L3**.
Per eseguire la build di produzione: `npm run build && npm start`.

### IdP con callback solo HTTPS

Nel Dev Container e' disponibile HTTPS locale con Traefik e mkcert (vedi sotto).
L'IdP deve accettare `localhost` come hostname del callback: se richiede anche un
dominio pubblico, usare invece un tunnel HTTPS verso
`http://localhost:3000`. Ad esempio, con `cloudflared` installato:

```sh
cloudflared tunnel --url http://localhost:3000
```

Impostare `BETTER_AUTH_URL` in `.env.local` all'origine HTTPS restituita dal tunnel,
ad esempio `https://bunny-controller-causes-former.trycloudflare.com`, e registrare
presso l'IdP entrambi i callback con quella stessa origine:

```text
https://bunny-controller-causes-former.trycloudflare.com/api/auth/callback/spid-l2
https://bunny-controller-causes-former.trycloudflare.com/api/auth/callback/spid-l3
```

Riavviare `npm run dev` e aprire l'app dall'URL HTTPS del tunnel, non da localhost,
per mantenere coerenti origine e cookie durante tutto il login. `next.config.ts`
ricava da `BETTER_AUTH_URL` il singolo hostname consentito per le risorse di sviluppo
Next.js, incluso HMR; non autorizza tutti i domini `*.trycloudflare.com`.
Quando cambia l'URL del tunnel, aggiornare `BETTER_AUTH_URL` e i callback dell'IdP,
quindi riavviare il server. L'`OIDC_ISSUER` resta quello dell'IdP.

Il Dev Container imposta `BETTER_AUTH_URL=https://localhost:3000` nell'ambiente, con
precedenza su `.env.local`. Per usare un tunnel in alternativa a Traefik,
puntarlo a `http://localhost:3000` dall'interno del container e avviare Next.js
con `BETTER_AUTH_URL=https://<dominio-del-tunnel> npm run dev`.

Il blocco cross-origin delle risorse di sviluppo e gli errori di login sono
problemi distinti: per questi ultimi consultare
gli errori `[auth]` / `[Better Auth]` nei log del server, verificando le variabili obbligatorie e
la configurazione OIDC. Consentire HMR non corregge una configurazione IdP errata.

## Dev Container

Richiede Docker Compose v2 e l'estensione **Dev Containers** di VS Code.
[mkcert](https://github.com/FiloSottile/mkcert) e' installato nel servizio di
inizializzazione: non occorre installarlo sull'host.
La configurazione `.devcontainer/compose.yaml` avvia tre servizi:

- `certificates`: genera i certificati prima dell'avvio degli altri servizi;
- `app`: immagine `mcr.microsoft.com/devcontainers/base:debian` fissata al digest,
  con Node.js 22 e npm installati dalle feature Dev Container;
- `traefik`: reverse proxy TLS, senza accesso al socket Docker e senza dashboard.
  Pubblica soltanto `127.0.0.1:3000` sull'host e inoltra le richieste a
  `http://app:3000` sulla rete interna Docker, inclusi WebSocket/HMR.

### Certificato HTTPS fidato

Ad ogni avvio dello stack Compose, `certificates` esegue mkcert per generare
certificato e chiave per `localhost`, `127.0.0.1` e `::1`. App e Traefik attendono
che la generazione termini correttamente; un errore blocca il loro avvio.
I file vengono scritti automaticamente in `.devcontainer/certs/`:

- `localhost.pem` e `localhost-key.pem`: certificato server e chiave privata;
- `rootCA.pem`: certificato pubblico della CA da importare sull'host.

La CA e la sua chiave privata sono conservate nel volume Docker `mkcert-ca`,
accessibile soltanto al servizio `certificates`. La stessa CA viene riutilizzata
ai successivi avvii e rebuild: viene rigenerato solo il certificato server.
La chiave della CA non viene copiata nel repository ne' montata in app/Traefik.
I file generati in `.devcontainer/certs/` sono esclusi da Git; Traefik li monta
in sola lettura.

**Una sola volta, dopo il primo avvio**, aggiungere `rootCA.pem` agli archivi
fidati del **computer host/browser**. La generazione nel container non puo'
rendere automaticamente fidato un certificato sul computer dove gira il browser.

Esempi dalla radice del repository, **in un terminale dell'host**:

Linux Debian/Ubuntu:

```sh
sudo cp .devcontainer/certs/rootCA.pem \
  /usr/local/share/ca-certificates/oi-nextjs-playground.crt
sudo update-ca-certificates
```

macOS:

```sh
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain .devcontainer/certs/rootCA.pem
```

Windows (PowerShell):

```powershell
Import-Certificate -FilePath .devcontainer/certs/rootCA.pem `
  -CertStoreLocation Cert:\CurrentUser\Root
```

Firefox e alcuni browser su Linux possono richiedere anche l'importazione
manuale della CA nelle impostazioni **Certificati / Autorita'**, autorizzandola
a identificare siti web. Riavviare il browser dopo l'importazione.
Non condividere mai `rootCA-key.pem`. Se viene eliminato il volume `mkcert-ca`,
al prossimo avvio viene creata una nuova CA: occorre importarla nuovamente
sull'host. Gli eventuali certificati generati in precedenza sull'host vengono
sostituiti da quelli della nuova CA al primo avvio del servizio.

### Avvio e callback OIDC

Aprire il progetto con **Dev Containers: Reopen in Container** oppure, se gia'
aperto, **Dev Containers: Rebuild and Reopen in Container**. Le dipendenze del
progetto vengono installate tramite `npm ci` alla creazione del container.
La porta **3000 dell'host deve essere libera**: e' pubblicata da Traefik e non
deve essere anche inoltrata da VS Code o occupata da un altro server.

Configurare `BETTER_AUTH_SECRET` e le variabili `OIDC_*` in `.env.local` come descritto
sopra. Compose imposta gia' `BETTER_AUTH_URL=https://localhost:3000` nell'ambiente;
non usare l'origine HTTP per il login. Registrare nell'IdP entrambi i callback:

```text
https://localhost:3000/api/auth/callback/spid-l2
https://localhost:3000/api/auth/callback/spid-l3
```

Nel terminale del container:

```sh
npm run dev -- --hostname 0.0.0.0
```

Aprire **<https://localhost:3000>** sul browser dell'host ed eseguire tutto il
login dalla stessa origine HTTPS. Next.js usa HTTP internamente; Traefik termina
TLS e trasmette l'host originale e gli header `X-Forwarded-*`. Better Auth usa
`BETTER_AUTH_URL` HTTPS per callback e cookie Secure. L'`OIDC_ISSUER` resta quello
dell'IdP. Questa soluzione funziona solo se l'IdP consente callback su localhost;
non rende l'app pubblicamente raggiungibile.

Per verificare dall'host, con Next.js avviato:

```sh
docker compose -f .devcontainer/compose.yaml config --quiet
docker compose -f .devcontainer/compose.yaml logs certificates traefik
curl --cacert .devcontainer/certs/rootCA.pem https://localhost:3000/
```

Un `502 Bad Gateway` indica che Next.js non e' ancora avviato o non ascolta su
`0.0.0.0:3000`; un errore di certificato richiede di controllare la fiducia della
CA nel browser. La sola riconnessione VS Code a container gia' avviati non
rigenera i file. Per rigenerarli manualmente senza cambiare CA:

```sh
docker compose -f .devcontainer/compose.yaml run --rm certificates
docker compose -f .devcontainer/compose.yaml restart traefik
```

Per i test browser, installare anche Chromium e le sue dipendenze nel container
con `npx playwright install --with-deps chromium`, poi eseguire
`npm run build && npm run test:e2e`.

## Login e step-up

- Due provider Generic OAuth di Better Auth (`spid-l2` e `spid-l3`) condividono issuer e credenziali:
  inviano rispettivamente `acr_values` L2 e L3 e `prompt=login`.
- Better Auth gestisce il flusso OIDC, la verifica della firma con JWKS,
  i controlli su issuer/audience/nonce e i controlli
  state/PKCE. Il callback verifica anche il claim **`acr` dell'ID token**:
  L3 soddisfa una richiesta L2, mentre L2 non soddisfa L3. Claim assenti o
  sconosciuti sono rifiutati. Il livello mostrato e' quello effettivamente ottenuto,
  non quello del pulsante selezionato.
- Lo step-up L2 -> L3 e' soltanto una **nuova login**. Non vengono invocati logout,
  revoche o endpoint di fine sessione dell'IdP.
- Durante il redirect la sessione corrente rimane disponibile. Al successo il
  browser riceve un nuovo cookie, che sostituisce quello precedente. Il vecchio
  JWE non viene conservato nell'interfaccia, ma resta valido se gia' posseduto da
  un altro client, fino alla sua scadenza originaria.
- Un annullamento, un errore OIDC o un livello insufficiente non revoca la
  sessione precedente. L'interfaccia mostra un errore; i dettagli diagnostici
  rimangono nei log del server.

Una nuova login L2 dopo L3 puo' sostituire la sessione con una di livello inferiore:
non e' implementata una policy che impedisca il downgrade.

## Sessione: JWE, TTL fisso, nessun rinnovo

Better Auth e' configurato senza database esterno, con cookie cache stateless
`strategy: "jwe"`. `better-auth.session_data` contiene un **JWE cifrato e autenticato**
con l'implementazione standard Better Auth (`dir` / `A256CBC-HS512`), non un JWT
in chiaro. Il cookie `better-auth.session_token` contiene un identificatore opaco
firmato: entrambi sono necessari per leggere la sessione. I cookie sono HttpOnly,
SameSite=Lax e Secure su HTTPS (con prefisso `__Secure-`).

L'istanza Better Auth e' creata per richiesta: il suo adapter in memoria
predefinito resta transitorio, senza conservare utenti/account tra login e senza
introdurre collegamenti impliciti tra L2 e L3. Di conseguenza la discovery OIDC
viene inizializzata per richiesta; questa PoC privilegia l'assenza di stato
server rispetto al caching dell'istanza.

Ogni login riuscita imposta `createdAt` ed `expiresAt` a distanza di 3.600 secondi.
`session.expiresIn` e `cookieCache.maxAge` sono di un'ora;
`disableSessionRefresh: true` e `cookieCache.refreshCache: false` impediscono
il rinnovo automatico. Un controllo aggiuntivo sulla lettura della sessione
rifiuta il secondo esatto di scadenza, anche rispetto alla tolleranza temporale
del decoder della libreria. La UI e `GET /api/auth/get-session` espongono
soltanto identita', livello, `startedAt`, `expires` e metadati di autenticazione.

Gli endpoint di modifica utente/sessione e di collegamento account non sono
esposti dalla PoC. Letture e aggiornamenti client non estendono il TTL;
solo una nuova autenticazione crea una nuova ora di validita'.
La scadenza della sessione dell'app e' indipendente da quella dei token dell'IdP:
non si eseguono refresh token o chiamate API protette.

Il JWE contiene identita' e metadati interni di sessione: access token,
refresh token e ID token non sono conservati nei cookie ne' esposti dalla UI.
`storeAccountCookie: false` disabilita il cookie Better Auth dei token IdP;
`disableProviderLogout: true` mantiene il logout locale.
**Logout locale** cancella i cookie correnti, senza Single Logout e senza
revocare eventuali copie dei JWE precedenti. E' una conseguenza intenzionale
della gestione stateless richiesta, non un meccanismo di revoca.

## Verifiche

```sh
npm run lint
npm run typecheck
npm test
npm run build
npx playwright install chromium
npm run test:e2e
```

I test unitari coprono cifratura, deadline esatta, assenza di sliding expiration
e mapping dei livelli. I test browser usano un IdP locale sintetico con discovery,
token endpoint, ID token firmati, nonce e PKCE: coprono login L2/L3, sopravvivenza
del vecchio JWE, logout locale, cancellazione dello step-up e rifiuto di `acr`
insufficiente/assente/sconosciuto, state/PKCE/nonce/firma/audience/issuer non validi,
email assente e login L2 successivo a L3. Non richiedono credenziali o connessioni a un IdP reale.
Il mock si avvia solo tramite Playwright, non fa parte dell'applicazione.

## Note

Better Auth e' fissato alla versione `1.7.12` e legge automaticamente
`BETTER_AUTH_URL` e `BETTER_AUTH_SECRET` dall'ambiente, senza opzioni
`baseURL` o `secret` nel codice ne' letture o validazioni custom nella
configurazione auth. Impostare un'origine HTTPS in produzione; HTTP e' adatto
allo sviluppo locale. La validazione del segreto e' delegata alla libreria:
in produzione il segreto predefinito viene rifiutato; un segreto sotto i 32
caratteri o a bassa entropia genera un avviso, non un errore bloccante.
I callback registrati presso l'IdP restano invariati.
Le sessioni precedentemente emesse da Auth.js non sono compatibili: dopo la
migrazione e' necessario un nuovo login. L'endpoint sessione passa da
`/api/auth/session` a `/api/auth/get-session`.

Questa PoC non e' un'implementazione completa del profilo
normativo SPID OpenID Connect e non include accreditamento o configurazione IdP.
