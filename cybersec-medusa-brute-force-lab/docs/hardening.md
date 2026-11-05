# Defense-in-Depth Hardening & Anti-Brute-Force Engineering

**Language: English (EN-US)**

**Document Navigation:**

* [English Version](#defense-in-depth-hardening--anti-brute-force-engineering)
* [Portuguese Version - PT-BR](#engenharia-de-hardening-em-profundidade-e-mitigação-de-força-bruta)

---

## 1. Baseline Vulnerability Finding on Debian 12 (`srv-linux-base`)

During the surface and PAM stack inspection recorded in [`commands/03-surface-audit.log`](../commands/03-surface-audit.log#L25-L27), the default `/etc/pam.d/common-auth` configuration on Debian 12 revealed:

```text
auth	[success=1 default=ignore]	pam_unix.so nullok
auth	requisite			pam_deny.so
auth	required			pam_permit.so
```

### Identified Security Gaps:
1. **Permissive `nullok` Flag:** Allows accounts with empty password hashes in `/etc/shadow` to pass PAM authentication checks if not explicitly blocked by the calling service daemon.
2. **Absence of `pam_faillock.so`:** By default, local and PAM-integrated network services do not enforce automatic account lockout upon consecutive authentication failures.

---

## 2. Four-Layer Defense-in-Depth Architecture

To neutralize both vertical brute-force attacks and horizontal password spraying across **SMB**, **FTP**, **SSH**, and **Web** interfaces, this laboratory implements a four-layer mitigation model backed by the configuration files in [`configs/`](../configs/):

```text
+-------------------------------------------------------------------------+
| LAYER 1: NETWORK & FIREWALL BANNING (Fail2Ban + nftables/UFW)           |
| Artifact: configs/jail.local                                            |
| -> Bans offending source IP for 1h after 3 failures across SSH/FTP/SMB  |
+------------------------------------+------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
| LAYER 2: DAEMON-LEVEL PROTOCOL HARDENING & SOCKET THROTTLING            |
| Artifacts: configs/smb-hardened.conf | configs/vsftpd-hardened.conf     |
| -> SMB: restrict anonymous = 2, server min protocol = SMB3, PAM enabled |
| -> FTP: max_per_ip = 2, delay_failed_login = 5, max_login_fails = 3     |
+------------------------------------+------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
| LAYER 3: OS IDENTITY & ACCOUNT LOCKOUT (Linux PAM pam_faillock.so)      |
| Artifact: configs/faillock.conf                                         |
| -> Locks target username for 900s (15m) after 3 invalid attempts        |
+------------------------------------+------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
| LAYER 4: CRYPTOGRAPHIC AUTHENTICATION & MFA (Ed25519 + FIDO2/TOTP)      |
| -> Eliminates shared-secret password guessing on administrative planes  |
+-------------------------------------------------------------------------+
```

---

## 3. Why Classical Auditing Remains Critical in the Era of AI & MFA

A core reflection proposed by this challenge is understanding why mastering tools like **Medusa**, **Nmap**, and **`smbclient`** remains vital despite modern **Multi-Factor Authentication (MFA)** and **AI-driven security controls**:

1. **Legacy & Non-MFA Service Protocols (`SMB`, `FTP`, `LDAP`, `MSSQL`):**
   While Web portals readily support TOTP/WebAuthn MFA, infrastructure protocols such as **SMB (`TCP/445`)**, **FTP (`TCP/21`)**, and legacy service accounts often rely exclusively on single-factor challenge-response hashes (NTLMv2) or cleartext passwords. If an attacker compromises a service account via SMB Password Spraying, MFA on the corporate SSO portal is bypassed entirely.
2. **AI-Assisted Password Generation vs. Deterministic Lockout Controls:**
   Offensive actors increasingly use Machine Learning (PassGAN, Markov models) to generate context-aware wordlists. However, mathematical entropy and **deterministic infrastructure controls** (`pam_faillock` + `Fail2Ban` socket throttling) cap an attacker's throughput at **3 attempts per 15 minutes**, rendering even AI-optimized wordlists statistically ineffective.

---
---

# Engenharia de Hardening em Profundidade e Mitigação de Força Bruta

**Idioma: Português do Brasil (PT-BR)**

**Navegação do Documento:**

* [Versão em Português - PT-BR](#engenharia-de-hardening-em-profundidade-e-mitigação-de-força-bruta)
* [English Version](#defense-in-depth-hardening--anti-brute-force-engineering)

---

## 1. Achado de Auditoria na Pilha PAM Padrão do Debian 12 (`srv-linux-base`)

Durante a inspeção de superfície e da pilha PAM registrada em [`commands/03-surface-audit.log`](../commands/03-surface-audit.log#L25-L27), a configuração padrão do arquivo `/etc/pam.d/common-auth` no Debian 12 revelou:

```text
auth	[success=1 default=ignore]	pam_unix.so nullok
auth	requisite			pam_deny.so
auth	required			pam_permit.so
```

### Lacunas de Segurança Identificadas:
1. **Parâmetro `nullok` Ativo:** Permite que contas sem hash de senha definido em `/etc/shadow` passem pela validação PAM caso o daemon do serviço não bloqueie senhas em branco explicitamente.
2. **Ausência do `pam_faillock.so`:** Por padrão, serviços locais e de rede integrados ao PAM não aplicam bloqueio automático de conta após falhas consecutivas de autenticação.

---

## 2. Arquitetura de Defesa em Profundidade em Quatro Camadas

Para neutralizar tanto ataques de força bruta vertical quanto *Password Spraying* horizontal em **SMB**, **FTP**, **SSH** e **Web**, este laboratório projeta um modelo de mitigação em quatro camadas apoiado pelos artefatos de [`configs/`](../configs/):

```text
+-------------------------------------------------------------------------+
| CAMADA 1: BANIMENTO DE REDE E FIREWALL (Fail2Ban + nftables/UFW)        |
| Artefato: configs/jail.local                                            |
| -> Bane o IP de origem por 1h após 3 falhas em SSH, FTP ou SMB          |
+------------------------------------+------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
| CAMADA 2: HARDENING DE PROTOCOLO E ESTRANGULAMENTO DE SOCKETS           |
| Artefatos: configs/smb-hardened.conf | configs/vsftpd-hardened.conf     |
| -> SMB: restrict anonymous = 2, server min protocol = SMB3, PAM ativo   |
| -> FTP: max_per_ip = 2, delay_failed_login = 5, max_login_fails = 3     |
+------------------------------------+------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
| CAMADA 3: BLOQUEIO DE IDENTIDADE NO SO (Linux PAM pam_faillock.so)      |
| Artefato: configs/faillock.conf                                         |
| -> Bloqueia o usuário alvo por 900s (15m) após 3 tentativas inválidas   |
+------------------------------------+------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
| CAMADA 4: AUTENTICAÇÃO CRIPTOGRÁFICA E MFA (Ed25519 + FIDO2/TOTP)       |
| -> Elimina senhas compartilhadas no plano de controle administrativo    |
+-------------------------------------------------------------------------+
```

---

## 3. Por que Ferramentas Clássicas Continuam Essenciais na Era da IA e do MFA?

Uma reflexão central proposta pelo desafio da DIO é compreender por que o domínio de ferramentas clássicas (**Medusa**, **Nmap**, **`smbclient`**) permanece indispensável mesmo na era da **Inteligência Artificial** e do **Múltiplo Fator de Autenticação (MFA)**:

1. **Protocolos de Infraestrutura Sem Suporte Nativo a MFA (`SMB`, `FTP`, `LDAP`):**
   Embora aplicações Web suportem MFA via TOTP ou FIDO2 facilmente, protocolos de infraestrutura como **SMB (`TCP/445`)** e **FTP (`TCP/21`)** — além de contas de serviço (`svc_backup`) — frequentemente dependem apenas de hashes NTLMv2 ou senhas estáticas. Se uma conta de serviço for comprometida via *Password Spraying* no SMB, o MFA do portal Web corporativo é contornado lateralmente.
2. **Geração de Senhas por IA vs. Controles Determinísticos de Infraestrutura:**
   Mesmo que atacantes utilizem modelos de IA para gerar *wordlists* altamente assertivas, a imposição de **controles determinísticos de infraestrutura** (`pam_faillock` + `Fail2Ban` + atraso de socket `delay_failed_login=5`) limita fisicamente a vazão de testes a **3 tentativas a cada 15 minutos**, tornando qualquer automação estatisticamente inviável.
