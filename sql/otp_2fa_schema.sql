-- ============================================================================
-- Schema per il 2FA (TOTP app / HOTP mail), integrato nel processo Auth API.
--
-- DDL da eseguire UNA TANTUM sul database db_auth (mit4medb01), a mano —
-- non applicato automaticamente dal codice applicativo (stesso principio di
-- "non validare a priori lo schema del DB dal codice", vedi CLAUDE.md).
--
-- Collocazione tabelle (decisa esplicitamente, non quella del documento di
-- riferimento originale che le raggruppava tutte in uno schema "otp"):
--   public.service_accounts   applicativi autorizzati a chiamare il WS (Basic Auth)
--   public.otp_methods        configurazione 2FA per utente (secret/counter/status)
--   config.mail_templates     template email (schema "config" gia' esistente,
--                              vedi config.provinces / config.next_working_day())
--   history.otp_requests      log delle richieste/verifiche di codice
-- ============================================================================

-- pgcrypto: necessaria per crypt()/gen_salt(), usate per l'hash (salted,
-- bcrypt) della password dei service account — permette anche un cambio
-- password diretto in SQL, senza passare da codice Python:
--   UPDATE public.service_accounts
--   SET passwd_hash = crypt('nuova-password', gen_salt('bf'))
--   WHERE client_id = 'nome-applicativo';
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ----------------------------------------------------------------------------
-- Applicativi autorizzati a chiamare gli endpoint /otp/* (HTTP Basic Auth).
-- Identifica l'APPLICATIVO chiamante, non l'utente reale (che e' invece il
-- campo 'login' nel body di ogni richiesta) — stessa logica di separazione
-- descritta nel documento di riferimento (otp.service_accounts originale).
-- ----------------------------------------------------------------------------
CREATE TABLE public.service_accounts (
    id            SERIAL PRIMARY KEY,
    client        VARCHAR(100) NOT NULL UNIQUE,   -- username in Basic Auth (rinominata da client_id)
    passwd_hash   VARCHAR(255) NOT NULL,          -- crypt(password, gen_salt('bf')) — MAI in chiaro
    descrizione   VARCHAR(255),                   -- nome/scopo dell'applicativo
	auth_type     VARCHAR(255),
    isactive      BOOLEAN NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at  TIMESTAMPTZ
);

CREATE INDEX service_accounts_client_idx ON public.service_accounts (client);

-- Esempio creazione applicativo (adatta ai tuoi valori reali):
-- INSERT INTO public.service_accounts (client, passwd_hash, descrizione)
-- VALUES ('portale-utenti', crypt('CAMBIAMI', gen_salt('bf')), 'Portale utenti MIT4ME');

-- Cambio password di un applicativo esistente (nessun codice Python coinvolto):
-- UPDATE public.service_accounts SET passwd_hash = crypt('nuova-password', gen_salt('bf'))
-- WHERE client = 'portale-utenti';

-- NOTA: la colonna si chiamava in origine client_id, rinominata in produzione
-- in client (config.yaml/operations_sql.select.otp_service_account e
-- .update.otp_service_account_last_used gia' allineate — il parametro Python
-- %(client_id)s resta invariato, e' solo il nome della colonna SQL referenziata
-- ad essere cambiato). Se hai gia' creato la tabella con client_id, rinomina:
--   ALTER TABLE public.service_accounts RENAME COLUMN client_id TO client;

-- Stessa rinomina applicata anche a history.otp_requests.client_id -> client
-- (colonna diversa, stesso nome per coincidenza — nessun legame/FK fra le
-- due). Se hai gia' creato la tabella con client_id, rinomina:
--   ALTER TABLE history.otp_requests RENAME COLUMN client_id TO client;

-- ----------------------------------------------------------------------------
-- Template dei messaggi email per il metodo 'mail' (schema "config" —
-- gia' usato in questo DB per dati di configurazione/riferimento, vedi
-- config.provinces e config.next_working_day()).
-- ----------------------------------------------------------------------------
CREATE TABLE config.mail_templates (
    id              SERIAL PRIMARY KEY,
    name            VARCHAR(100) NOT NULL UNIQUE,    -- descrittivo, es. 'login_default' — UNIQUE:
                                                       -- e' la chiave usata dal codice applicativo
                                                       -- (request /otp/setup, FK da otp_methods),
                                                       -- non piu' l'id numerico
    subject         VARCHAR(255) NOT NULL,
    body            TEXT NOT NULL,                   -- placeholder: {{LOGIN}}, {{OTP}}, {{TIMEOUT_MINUTES}},
                                                       -- {{EXPIRES_AT}} (data/ora di scadenza,
                                                       -- gg/mm/aaaa hh:mm) — semplice str.replace(),
                                                       -- un placeholder assente nel body e' un no-op
                                                       -- silenzioso, non un errore
    mailserver      VARCHAR(255) NOT NULL,
    portmailserver  INT NOT NULL,
    sender_email    VARCHAR(255) NOT NULL,
    timeout_seconds INT NOT NULL DEFAULT 300,        -- validita' del codice per questo template
    isactive        BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON COLUMN config.mail_templates.timeout_seconds IS
    'Quanto resta valido il codice inviato con questo template, indipendentemente dal counter HOTP';

-- Esempio template di partenza:
-- INSERT INTO config.mail_templates (name, subject, body, mailserver, portmailserver, sender_email, timeout_seconds)
-- VALUES ('login_default', 'Il tuo codice di accesso',
--         '<p>Ciao {{LOGIN}},</p><p>Il tuo codice OTP e'' <b>{{OTP}}</b>, valido {{TIMEOUT_MINUTES}} minuti '
--         '(scade il {{EXPIRES_AT}}).</p>',
--         'smtp.example.it', 25, 'noreply@example.it', 300);

-- ----------------------------------------------------------------------------
-- Configurazione del metodo 2FA per ogni utente (login). Storico possibile
-- (piu' righe per lo stesso login), ma un solo record 'active' alla volta
-- (indice unico parziale sotto).
-- ----------------------------------------------------------------------------
CREATE TABLE public.otp_methods (
    id            SERIAL PRIMARY KEY,
    login         VARCHAR(100) NOT NULL,
    method        VARCHAR(10)  NOT NULL CHECK (method IN ('app', 'mail')),
    secret        VARCHAR(64)  NOT NULL,              -- base32, generato da pyotp
    counter       BIGINT       NOT NULL DEFAULT 0,    -- usato solo per method='mail' (HOTP)
    last_totp_step BIGINT,                            -- usato solo per method='app' (TOTP) — ultimo
                                                        -- timestep verificato con successo, anti-replay:
                                                        -- TOTP e' altrimenti stateless, un codice valido
                                                        -- resterebbe riutilizzabile per l'intera finestra
                                                        -- di tolleranza (otp2fa.totp_valid_window) senza
                                                        -- questo controllo
    -- NESSUNA colonna template — il template email non e' piu' un attributo
    -- della configurazione 2FA: sia /otp/setup (primo codice, se
    -- otp2fa.require_mail_confirmation=true) sia /otp/sendmailotp (ogni
    -- invio successivo) ricevono template_id nel body ad ogni chiamata,
    -- cosi' il messaggio puo' variare da un invio all'altro. Nessun bisogno
    -- di persisterne uno "di default" qui: il codice applicativo non lo
    -- rilegge mai da questa tabella.
    mail_to       VARCHAR(255),                       -- valorizzato solo per method='mail'
    status        VARCHAR(10)  NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending', 'active', 'disabled')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    confirmed_at  TIMESTAMPTZ,
    disabled_at   TIMESTAMPTZ,
    requested_by_login VARCHAR(100)   -- valorizzata solo su disattivazione (POST /otp/disable):
                                       -- chi l'ha richiesta (puo' coincidere con 'login' se e'
                                       -- l'utente stesso, o essere un operatore/helpdesk diverso).
                                       -- Nessun vincolo FK: e' un'annotazione di audit, non un
                                       -- riferimento a un'altra riga di otp_methods/service_accounts.
);

-- Un solo metodo ACTIVE per utente: il setup di un nuovo metodo resta
-- "pending" finche' non viene confermato (metodo app) o si attiva subito
-- (metodo mail, se otp2fa.require_mail_confirmation=false in config.yaml).
CREATE UNIQUE INDEX otp_methods_one_active_per_login
    ON public.otp_methods (login)
    WHERE status = 'active';

CREATE INDEX otp_methods_login_idx ON public.otp_methods (login);

-- ----------------------------------------------------------------------------
-- Log delle richieste/verifiche di codice:
--   purpose='register' -> primo codice inviato in fase di setup con conferma
--                          (metodo mail)
--   purpose='login'     -> ogni richiesta di /otp/sendmailotp (metodo mail)
--   purpose='verify'    -> ogni tentativo di verifica di un codice TOTP
--                          (metodo app), su /otp/verify o /otp/disable — a
--                          differenza dei due sopra, qui la riga non nasce
--                          'pending' per poi essere aggiornata: TOTP non ha
--                          un "invio" precedente (il codice lo genera
--                          l'authenticator, non lo mandiamo noi), quindi la
--                          riga viene creata gia' con lo stato finale
--                          (verified/failed), counter_used ed expires_at
--                          sempre NULL (nessun counter HOTP, nessuna
--                          scadenza di invio da tracciare)
-- Schema "history", coerente con history.auth_credential_log gia' usata
-- ----------------------------------------------------------------------------
CREATE TABLE history.otp_requests (
    id            SERIAL PRIMARY KEY,
    config_id     INT NOT NULL REFERENCES public.otp_methods(id),
    login         VARCHAR(100) NOT NULL,
    purpose       VARCHAR(10) NOT NULL CHECK (purpose IN ('register', 'login', 'verify')),
    counter_used  BIGINT,                             -- valorizzato solo per method='mail'
    request_id    VARCHAR(100),                       -- X-Request-Id, per correlazione con i log applicativi
    client        VARCHAR(100),                       -- applicativo chiamante (service_accounts.client,
                                                        -- rinominata da client_id), solo per tracciamento:
                                                        -- nessun vincolo FK, per non perdere lo storico se
                                                        -- l'applicativo viene rinominato/disattivato
    code          VARCHAR(10),                        -- codice OTP mascherato secondo otp2fa.debug_code
                                                        -- (config.yaml): "******" (default, nessuna cifra
                                                        -- reale), "****13" (ultime 2 cifre reali), o il
                                                        -- codice completo in chiaro se debug_code=2 (solo
                                                        -- debug mirato, MAI in produzione)
    status        VARCHAR(10) NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending', 'verified', 'failed', 'expired')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ,                        -- NOT NULL solo concettualmente per register/login
                                                        -- (mail): sempre NULL per purpose='verify' (app)
    verified_at   TIMESTAMPTZ
);

CREATE INDEX otp_requests_config_id_idx ON history.otp_requests (config_id);
CREATE INDEX otp_requests_login_idx     ON history.otp_requests (login);

-- Migrazione per un DB dove history.otp_requests esiste gia' senza la
-- colonna code (es. era stata creata prima di questa modifica):
--   ALTER TABLE history.otp_requests ADD COLUMN code VARCHAR(10);

-- Migrazione per un DB dove history.otp_requests esiste gia' con expires_at
-- NOT NULL e/o senza 'verify' nel CHECK di purpose (log dei tentativi di
-- verifica per metodo 'app', vedi commento sopra):
--   ALTER TABLE history.otp_requests ALTER COLUMN expires_at DROP NOT NULL;
--   ALTER TABLE history.otp_requests DROP CONSTRAINT otp_requests_purpose_check;
--   ALTER TABLE history.otp_requests ADD CONSTRAINT otp_requests_purpose_check
--     CHECK (purpose IN ('register', 'login', 'verify'));
-- (nome vincolo di default per un CHECK senza nome esplicito — verificare con
-- \d history.otp_requests se non coincide)

-- Migrazione per un DB dove public.otp_methods esiste gia' con una colonna
-- template (template_name, FK su config.mail_templates.name, o gia'
-- rinominata in template_id, FK su .id) — non serve piu': il template si
-- specifica ad ogni chiamata (/otp/setup, /otp/sendmailotp), non e' un
-- attributo persistito della configurazione 2FA:
--   ALTER TABLE public.otp_methods DROP COLUMN template_name;  -- oppure DROP COLUMN template_id;

-- Migrazione per un DB dove public.otp_methods esiste gia' senza la colonna
-- last_totp_step (protezione anti-replay TOTP, aggiunta in una sessione
-- successiva):
--   ALTER TABLE public.otp_methods ADD COLUMN last_totp_step BIGINT;
