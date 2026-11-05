# Authentication Resilience & Brute-Force Analysis Architecture

**Language: English (EN-US)**

**Document Navigation:**

* [English Version](#authentication-resilience--brute-force-analysis-architecture)
* [Portuguese Version - PT-BR](#arquitetura-de-resiliência-de-autenticação-e-análise-de-força-bruta)

---

## 1. Architectural Context & Adaptation Strategy

Rather than relying on legacy, unmaintained virtual appliances (such as *Metasploitable 2*, built on an end-of-life 2008 kernel), this laboratory leverages a modern, segmented **Dual-Node Cyber Range** running **Debian 12 (`srv-linux-base`)** and **Kali Linux 2026.2 (`kali-cyberrange`)** over an isolated Layer 2 Host-Only switch (`192.168.56.0/24`).

This architectural choice enables a **Purple Team Engineering Methodology**:
1. **Protocol & Attack-Surface Analysis:** Dissecting how parallel authentication auditors (`Medusa`) interact with **SMB (TCP/445)**, **FTP (TCP/21)**, and **HTTP Web Forms (TCP/80)** across concurrent worker threads.
2. **Telemetry & Log Correlation:** Observing authentication failures and session negotiations directly inside `journald`, `/var/log/auth.log`, and Samba/vsftpd service logs on Debian 12.
3. **Active Defensive Engineering:** Designing and verifying production-grade mitigations (`PAM pam_faillock`, `Fail2Ban` dynamic firewall jails, and `SMB3` protocol enforcement) while maintaining clean baseline rollback via hypervisor Cold Snapshots (`GOLDEN_IMAGE_BASE_CLI` and `GOLDEN_IMAGE_KALI_BASE`).

---

## 2. Integrated Logical Topology (`192.168.56.0/24`)

```text
+---------------------------------------------------------------------------------------+
|                                   WINDOWS 11 HOST                                     |
|                                                                                       |
|   +-----------------------+                   +-----------------------------------+   |
|   |   WSL2 (Ubuntu ZSH)   |                   |  VirtualBox Host-Only Adapter     |   |
|   |   Unified SSH Plane   | ----------------> |  IP: 192.168.56.1/24              |   |
|   |   (id_cyberrange)     |  (Static Route +  |  MAC: 0a:00:27:00:00:09           |   |
|   +-----------------------+   Source NAT)     +-----------------+-----------------+   |
|                                                                 |                     |
+-----------------------------------------------------------------|---------------------+
                                                                  |
               [ ISOLATED LAYER 2 vSWITCH: 192.168.56.0/24 (TTL=64 PEER LINK) ]
                                                                  |
                  +-----------------------------------------------+---------------+
                  |                                                               |
                  v                                                               v
+-----------------------------------------+     +-----------------------------------------+
| TARGET / BLUE NODE: srv-linux-base      |     | AUDITOR / RED NODE: kali-cyberrange     |
| OS: Debian 12 Minimal Headless          |     | OS: Kali Linux 2026.2 Headless          |
| IP (enp0s8): 192.168.56.10/24           |     | IP (eth1):   192.168.56.20/24           |
|                                         |     |                                         |
|  [ Target Protocol Stack ]              |     |  [ Security Auditing Stack ]            |
|  - SMB/CIFS (Samba smbd : TCP 445)      | <== |  - Medusa Parallel Engine (Modular)     |
|  - FTP Service (vsftpd  : TCP 21)       | ==> |  - Nmap Service/Version Fingerprinting  |
|  - HTTP Web Auth (Form  : TCP 80)       | L2  |  - smbclient Session Validator          |
|                                         |     |                                         |
|  [ Defensive Control Plane ]            |     |  [ Telemetry & Inspection ]             |
|  - PAM (pam_faillock.so Lockout)        |     |  - Controlled Audit Wordlists           |
|  - Fail2Ban + UFW/nftables Ban Jails    |     |  - Thread & Rate-Limit Analysis         |
+-----------------------------------------+     +-----------------------------------------+
```

---

## 3. Protocol Attack-Surface Matrix

| Protocol / Service | Transport Port | Medusa Module | Authentication Mechanism | Primary Brute-Force Weakness | Engineered Defensive Control |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **FTP (`vsftpd`)** | `TCP/21` | `ftp.mod` | Cleartext `USER` / `PASS` commands | High-speed socket reuse, lack of native account lockout, cleartext credential transit | Disable anonymous login, enforce TLS (`ssl_enable=YES`), apply `Fail2Ban` `vsftpd` jail & `pam_faillock` |
| **SMB (`Samba smbd`)** | `TCP/445` | `smbnt.mod` | NTLMv2 Challenge-Response over SMB2/SMB3 | Susceptible to **Password Spraying** across enumerated domain/local accounts | Enforce `server min protocol = SMB3`, restrict null sessions (`restrict anonymous = 2`), lock accounts via PAM |
| **Web Form (`DVWA / HTTP`)** | `TCP/80`, `443` | `http.mod` / `web-form.mod` | HTTP `POST` payload + Session Cookie (`PHPSESSID`) | Stateless automated `POST` flooding, inconsistent HTTP `200 OK` status codes causing false positives | Implement CSRF tokens, rate limiting (`limit_req`), CAPTCHA/MFA, and semantic HTTP `401`/`429` responses |

---

## 4. State Preservation & Reproducibility Guarantees

To guarantee that experimental service installations (`samba`, `vsftpd`, `fail2ban`) do not permanently alter the base Cyber Range infrastructure:
- **`srv-linux-base`** is anchored to the cold snapshot **`GOLDEN_IMAGE_BASE_CLI`**.
- **`kali-cyberrange`** is anchored to the cold snapshot **`GOLDEN_IMAGE_KALI_BASE`**.
- All configuration changes and defensive baselines are version-controlled inside [`configs/`](../configs/) and verified via raw terminal transcripts in [`commands/`](../commands/).

---
---

# Arquitetura de Resiliência de Autenticação e Análise de Força Bruta

**Idioma: Português do Brasil (PT-BR)**

**Navegação do Documento:**

* [Versão em Português - PT-BR](#arquitetura-de-resiliência-de-autenticação-e-análise-de-força-bruta)
* [English Version](#authentication-resilience--brute-force-analysis-architecture)

---

## 1. Contexto Arquitetural e Estratégia de Adaptação

Em vez de depender de máquinas virtuais legadas e descontinuadas (como o *Metasploitable 2*, baseado em um kernel de 2008 sem suporte), este laboratório utiliza um **Cyber Range Dual-Node** moderno e segmentado rodando **Debian 12 (`srv-linux-base`)** e **Kali Linux 2026.2 (`kali-cyberrange`)** sobre um switch virtual Host-Only isolado em Camada 2 (`192.168.56.0/24`).

Essa decisão arquitetural viabiliza uma **Metodologia de Engenharia Purple Team**:
1. **Análise de Protocolos e Superfície de Ataque:** Dissecação de como ferramentas paralelas de auditoria de autenticação (`Medusa`) interagem com **SMB (TCP/445)**, **FTP (TCP/21)** e **Formulários Web HTTP (TCP/80)** através de múltiplas threads concorrentes.
2. **Telemetria e Correlação de Logs:** Observação direta de falhas de autenticação e negociações de sessão no `journald`, `/var/log/auth.log` e logs de serviço do Samba/vsftpd no Debian 12.
3. **Engenharia Defensiva Ativa:** Projeto e validação de mitigações reais de produção (`PAM pam_faillock`, jails dinâmicos do `Fail2Ban` e imposição de protocolo `SMB3`), mantendo a capacidade de restauração limpa via Cold Snapshots (`GOLDEN_IMAGE_BASE_CLI` e `GOLDEN_IMAGE_KALI_BASE`).

---

## 2. Topologia Lógica Integrada (`192.168.56.0/24`)

```text
+---------------------------------------------------------------------------------------+
|                                   HOST WINDOWS 11                                     |
|                                                                                       |
|   +-----------------------+                   +-----------------------------------+   |
|   |   WSL2 (Ubuntu ZSH)   |                   |  Adaptador Host-Only VirtualBox   |   |
|   |   Plano SSH Unificado | ----------------> |  IP: 192.168.56.1/24              |   |
|   |   (id_cyberrange)     |  (Rota Estática + |  MAC: 0a:00:27:00:00:09           |   |
|   +-----------------------+   Source NAT)     +-----------------+-----------------+   |
|                                                                 |                     |
+-----------------------------------------------------------------|---------------------+
                                                                  |
             [ vSWITCH CAMADA 2 ISOLADO: 192.168.56.0/24 (LINK DIRETO TTL=64) ]
                                                                  |
                  +-----------------------------------------------+---------------+
                  |                                                               |
                  v                                                               v
+-----------------------------------------+     +-----------------------------------------+
| NÓ ALVO / BLUE TEAM: srv-linux-base     |     | NÓ AUDITOR / RED TEAM: kali-cyberrange  |
| OS: Debian 12 Minimal Headless          |     | OS: Kali Linux 2026.2 Headless          |
| IP (enp0s8): 192.168.56.10/24           |     | IP (eth1):   192.168.56.20/24           |
|                                         |     |                                         |
|  [ Pilha de Protocolos Alvo ]           |     |  [ Pilha de Auditoria de Segurança ]    |
|  - SMB/CIFS (Samba smbd : TCP 445)      | <== |  - Motor Paralelo Medusa (Modular)      |
|  - Serviço FTP (vsftpd  : TCP 21)       | ==> |  - Fingerprinting de Serviços via Nmap  |
|  - Auth Web HTTP (Form  : TCP 80)       | L2  |  - Validador de Sessão smbclient        |
|                                         |     |                                         |
|  [ Plano de Controle Defensivo ]        |     |  [ Telemetria e Inspeção ]              |
|  - PAM (Bloqueio via pam_faillock.so)   |     |  - Wordlists de Auditoria Controladas   |
|  - Jails Fail2Ban + UFW/nftables        |     |  - Análise de Threads e Rate-Limiting   |
+-----------------------------------------+     +-----------------------------------------+
```

---

## 3. Matriz de Superfície de Ataque por Protocolo

| Protocolo / Serviço | Porta | Módulo Medusa | Mecanismo de Autenticação | Fragilidade Primária a Força Bruta | Controle Defensivo de Engenharia |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **FTP (`vsftpd`)** | `TCP/21` | `ftp.mod` | Comandos `USER` / `PASS` em texto claro | Reuso rápido de sockets, ausência de bloqueio nativo, trânsito de credenciais sem criptografia | Desativar login anônimo, exigir TLS (`ssl_enable=YES`), aplicar jail `vsftpd` no `Fail2Ban` e `pam_faillock` |
| **SMB (`Samba smbd`)** | `TCP/445` | `smbnt.mod` | Desafio-Resposta NTLMv2 sobre SMB2/SMB3 | Suscetível a **Password Spraying** contra contas enumeradas | Exigir `server min protocol = SMB3`, bloquear sessões nulas (`restrict anonymous = 2`), bloqueio via PAM |
| **Web Form (`DVWA / HTTP`)** | `TCP/80`, `443` | `http.mod` / `web-form.mod` | Payload HTTP `POST` + Cookie de Sessão (`PHPSESSID`) | Inundação automatizada de `POST`, respostas HTTP `200 OK` genéricas gerando falsos-positivos | Implementar tokens CSRF, *rate limiting* (`limit_req`), CAPTCHA/MFA e códigos semânticos `401`/`429` |

---

## 4. Garantias de Preservação de Estado e Reprodutibilidade

Para assegurar que instalações experimentais de serviços (`samba`, `vsftpd`, `fail2ban`) não alterem permanentemente a infraestrutura base do Cyber Range:
- **`srv-linux-base`** permanece ancorado ao cold snapshot **`GOLDEN_IMAGE_BASE_CLI`**.
- **`kali-cyberrange`** permanece ancorado ao cold snapshot **`GOLDEN_IMAGE_KALI_BASE`**.
- Todas as alterações de configuração e baselines defensivos são versionados em [`configs/`](../configs/) e auditados por transcrições brutas de terminal em [`commands/`](../commands/).
