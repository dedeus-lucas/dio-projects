# Protocol Authentication Mechanics & False-Positive Root Cause Analysis

**Language: English (EN-US)**

**Document Navigation:**

* [English Version](#protocol-authentication-mechanics--false-positive-root-cause-analysis)
* [Portuguese Version - PT-BR](#mecânica-de-autenticação-de-protocolos-e-análise-de-causa-raiz-de-falsos-positivos)

---

## 1. Multi-Threaded Authentication Auditing Engine (`Medusa v2.3`)

As verified in [`commands/01-env-baseline.log`](../commands/01-env-baseline.log) and [`commands/02-module-specs.log`](../commands/02-module-specs.log), **Medusa (`v2.3`)** separates its core POSIX thread scheduler (`pthreads`) from protocol-specific shared libraries (`/usr/lib/x86_64-linux-gnu/medusa/modules/*.mod`).

### Vertical Brute-Force vs. Horizontal Password Spraying
- **Vertical Brute-Force (1 Account $\times$ $N$ Passwords):** Concentrates high-frequency authentication attempts against a single username (e.g., `admin` or `root`). While fast over low-latency links (`0.981 ms` Layer 2 RTT), it immediately triggers account lockout thresholds (`deny = 3`) if PAM policies are active.
- **Horizontal Password Spraying ($N$ Accounts $\times$ 1 Password):** Evaluates a single common or seasonal password (e.g., `Welcome123` or `Summer2026!` from [`configs/audit-passwords.txt`](../configs/audit-passwords.txt)) across all enumerated usernames ([`configs/audit-users.txt`](../configs/audit-users.txt)). Because each account experiences only **one failed attempt per cycle**, per-user lockout counters are bypassed unless correlated at the network layer (`Fail2Ban`).

---

## 2. SMB Protocol Dissection (`TCP/445` — `smbnt.mod v3.0`)

From the empirical module specification captured in [`commands/02-module-specs.log`](../commands/02-module-specs.log#L3-L65):

1. **Dialect & Authentication Support:** `smbnt.mod (3.0)` negotiates **SMBv1 through SMBv3**, supporting both cleartext password validation (`PASS:PASSWORD`) and direct **Pass-the-Hash (`PASS:HASH`)** over LM/NTLM/LMv2/NTLMv2 challenge-response handshakes.
2. **Two-Stage Privilege Probing (`Session Setup AndX` + `Tree Connect AndX`):**
   - **Stage 1 (`Session Setup AndX`):** Authenticates the user session against the local SAM database (`GROUP:LOCAL`) or Domain Controller (`GROUP:DOMAIN`).
   - **Stage 2 (`Tree Connect AndX` to `ADMIN$`):** Immediately attempts to mount the hidden administrative share `ADMIN$` to classify the compromised credential's privilege level:
     - `[SUCCESS (ADMIN$ - Access Allowed)]`: Administrative privileges confirmed.
     - `[SUCCESS (ADMIN$ - Access Denied)]`: Valid unprivileged user account.
     - `[SUCCESS (ADMIN$ - Share Unavailable)]`: Valid account on a Linux/Samba target where the Windows-specific `ADMIN$` share is absent.
3. **Validation via `smbclient`:** In security audits, once a credential or null-session policy is identified, `smbclient` validates share visibility and ACL enforcement over `TCP/445`.

---

## 3. FTP Protocol Dissection (`TCP/21` — `ftp.mod v2.1`)

As documented in [`commands/02-module-specs.log`](../commands/02-module-specs.log#L68-L95), `ftp.mod` supports three operational modes:
- **`NORMAL`:** Transmits `USER <username>` and `PASS <password>` in cleartext over `TCP/21`, Automatically upgrading to `EXPLICIT` FTPS if demanded by the daemon.
- **`EXPLICIT` (`AUTH TLS` — RFC 4217):** Establishes a TLS session on `TCP/21` before exchanging credentials.
- **`IMPLICIT` (`TCP/990`):** Requires a full TLS handshake prior to any FTP command exchange.

> **Engineering Takeaway:** Enforcing TLS (`ssl_enable=YES`) protects credentials from passive Layer 2 packet sniffing (`tcpdump` / Wireshark), but **does not mitigate brute-force guessing**, because `ftp.mod` natively negotiates `AUTH TLS` and continues testing passwords inside the encrypted tunnel. Daemon-level rate limiting (`delay_failed_login=5`, `max_per_ip=2`) is therefore mandatory.

---

## 4. Web Form Authentication (`DVWA / HTTP`) & False-Positive Root Cause Analysis

A recurring operational challenge in Web application security testing (such as **DVWA — Damn Vulnerable Web Application**) is the occurrence of massive **false positives** during automated login auditing.

Inspection of `web-form.mod (2.1)` in [`commands/02-module-specs.log`](../commands/02-module-specs.log#L99-L115) reveals the exact engineering root causes:

| Parameter / Mechanism | Observed Behavior in `web-form.mod` | Why False Positives Occur | Engineering Remediation / Audit Fix |
| :--- | :--- | :--- | :--- |
| **`DENY-SIGNAL` Negative Matching** | Flags an attempt as `[SUCCESS]` whenever the string `"Login incorrect"` is **absent** from the HTTP response body. | If the server returns an empty `302 Found` redirect, a `403 Forbidden` WAF block, or a localized error message, `"Login incorrect"` is absent and **every wrong password is flagged as `[SUCCESS]`**. | Configure applications to return semantic HTTP status codes (`401 Unauthorized` / `429 Too Many Requests`) rather than generic `200 OK` / `302` pages. |
| **Stateful Session Cookies & CSRF (`PHPSESSID` / `user_token`)** | Submits stateless `POST` payloads unless `CUSTOM-HEADER:"Cookie: ..."` is manually supplied. | Modern web apps and DVWA (Medium/High/Impossible levels) validate dynamic per-request **CSRF tokens (`user_token`)**. Missing tokens redirect to `login.php` before checking the password. | Enforce cryptographic anti-CSRF tokens (`SameSite=Strict`) and dynamic session binding on all authentication endpoints. |
| **Hardcoded Default `USER-AGENT`** | Sends `User-Agent: "I'm not Mozilla, I'm Ming Mong"` by default ([line 102](../commands/02-module-specs.log#L102)). | Reverse proxies and WAFs immediately drop or tarpit requests matching known scanner signatures. | Deploy WAF signature inspection combined(with behavioral rate limiting (`limit_req_zone`). |

---
---

# Mecânica de Autenticação de Protocolos e Análise de Causa Raiz de Falsos-Positivos

**Idioma: Português do Brasil (PT-BR)**

**Navegação do Documento:**

* [Versão em Português - PT-BR](#mecânica-de-autenticação-de-protocolos-e-análise-de-causa-raiz-de-falsos-positivos)
* [English Version](#protocol-authentication-mechanics--false-positive-root-cause-analysis)

---

## 1. Motor de Auditoria de Autenticação Multi-Thread (`Medusa v2.3`)

Conforme verificado em [`commands/01-env-baseline.log`](../commands/01-env-baseline.log) e [`commands/02-module-specs.log`](../commands/02-module-specs.log), o **Medusa (`v2.3`)** separa seu escalonador central de POSIX threads (`pthreads`) das bibliotecas compartilhadas de protocolo (`/usr/lib/x86_64-linux-gnu/medusa/modules/*.mod`).

### Força Bruta Vertical vs. Password Spraying Horizontal
- **Força Bruta Vertical (1 Conta $\times$ $N$ Senhas):** Concentra tentativas de alta frequência contra um único usuário (ex.: `admin` ou `root`). Embora rápida em links de baixa latência (`0.981 ms` em Camada 2), aciona imediatamente o bloqueio de conta (`deny = 3`) caso políticas PAM estejam ativas.
- **Password Spraying Horizontal ($N$ Contas $\times$ 1 Senha):** Testa uma única senha comum ou sazonal (ex.: `Welcome123` ou `Summer2026!` de [`configs/audit-passwords.txt`](../configs/audit-passwords.txt)) contra uma lista de usuários enumerados ([`configs/audit-users.txt`](../configs/audit-users.txt)). Como cada conta sofre apenas **uma falha por ciclo**, contadores de bloqueio por usuário são contornados se não houver correlação por IP na camada de rede (`Fail2Ban`).

---

## 2. Dissecação do Protocolo SMB (`TCP/445` — `smbnt.mod v3.0`)

A partir da especificação empírica capturada em [`commands/02-module-specs.log`](../commands/02-module-specs.log#L3-L65):

1. **Suporte a Dialetos e Autenticação:** O módulo `smbnt.mod (3.0)` negocia desde **SMBv1 até SMBv3**, suportando tanto validação de senha em texto claro (`PASS:PASSWORD`) quanto **Pass-the-Hash (`PASS:HASH`)** direto sobre handshakes NTLMv2.
2. **Sondagem de Privilégio em Duas Etapas (`Session Setup AndX` + `Tree Connect AndX`):**
   - **Etapa 1 (`Session Setup AndX`):** Autentica a sessão do usuário contra a base local (`GROUP:LOCAL`) ou Controlador de Domínio (`GROUP:DOMAIN`).
   - **Etapa 2 (`Tree Connect AndX` em `ADMIN$`):** Tenta montar imediatamente o compartilhamento oculto `ADMIN$` para classificar o nível de privilégio da credencial:
     - `[SUCCESS (ADMIN$ - Access Allowed)]`: Privilégio administrativo confirmado.
     - `[SUCCESS (ADMIN$ - Access Denied)]`: Conta de usuário comum válida (sem acesso admin).
     - `[SUCCESS (ADMIN$ - Share Unavailable)]`: Credencial válida em servidor Linux/Samba (onde o compartilhamento `ADMIN$` do Windows não existe).
3. **Validação via `smbclient`:** Em auditorias de segurança, o utilitário `smbclient` é utilizado para validar o acesso efetivo aos compartilhamentos e inspecionar permissões (ACLs) na porta `TCP/445`.

---

## 3. Dissecação do Protocolo FTP (`TCP/21` — `ftp.mod v2.1`)

Conforme documentado em [`commands/02-module-specs.log`](../commands/02-module-specs.log#L68-L95), o `ftp.mod` opera em três modos:
- **`NORMAL`:** Transmite `USER <usuario>` e `PASS <senha>` em texto claro na porta `TCP/21`, subindo automaticamente para `EXPLICIT` FTPS se exigido pelo servidor.
- **`EXPLICIT` (`AUTH TLS` — RFC 4217):** Negocia criptografia TLS na porta `TCP/21` antes do envio da senha.
- **`IMPLICIT` (`TCP/990`):** Exige handshake TLS completo antes de qualquer comando FTP.

> **Lição de Engenharia:** Exigir TLS (`ssl_enable=YES`) protege credenciais contra interceptação passiva na rede (`tcpdump` / Wireshark), mas **não impede ataques de força bruta**, pois o `ftp.mod` negocia `AUTH TLS` nativamente e continua testando senhas dentro do túnel criptografado. Limitação de taxa no daemon (`delay_failed_login=5`, `max_per_ip=2`) é, portanto, indispensável.

---

## 4. Autenticação em Formulários Web (`DVWA / HTTP`) e Causa Raiz de Falsos-Positivos

Um desafio operacional clássico em testes de aplicações Web (como o **DVWA — Damn Vulnerable Web Application**) é a geração massiva de **falsos-positivos** durante a automação de tentativas de login.

A inspeção do `web-form.mod (2.1)` em [`commands/02-module-specs.log`](../commands/02-module-specs.log#L99-L115) comprova tecnicamente as três causas raiz:

| Parâmetro / Mecanismo | Comportamento no `web-form.mod` | Por que Ocorrem Falsos-Positivos | Mitigação de Engenharia / Correção |
| :--- | :--- | :--- | :--- |
| **Lógica Negativa do `DENY-SIGNAL`** | Marca a tentativa como `[SUCCESS]` sempre que a string `"Login incorrect"` **não está presente** no corpo HTML da resposta. | Se o servidor responder com redirecionamento `302 Found` vazio, página de bloqueio `403` ou mensagem em outro idioma, a string `"Login incorrect"` não aparece e **todas as senhas erradas viram `[SUCCESS]`**. | Retornar códigos HTTP semânticos (`401 Unauthorized` / `429 Too Many Requests`) em vez de páginas genéricas `200 OK` ou `302`. |
| **Cookies de Sessão e CSRF (`PHPSESSID` / `user_token`)** | Envia requisições `POST` sem estado, a menos que `CUSTOM-HEADER:"Cookie: ..."` seja fixado manualmente. | Aplicações modernas e o próprio DVWA validam tokens **CSRF dinâmicos por requisição (`user_token`)**. Sem renovar o token a cada tentativa, o servidor rejeita o formulário antes mesmo de testar a senha. | Implementar tokens anti-CSRF criptográficos (`SameSite=Strict`) e validação estrita de estado de sessão. |
| **`USER-AGENT` Padrão Hardcoded** | Envia `User-Agent: "I'm not Mozilla, I'm Ming Mong"` por padrão ([linha 102](../commands/02-module-specs.log#L102)). | Proxies reversos e WAFs descartam ou retornam páginas de erro genéricas para assinaturas conhecidas de scanners. | Combinar inspeção de assinaturas no WAF com *rate limiting* comportamental (`limit_req_zone`). |
