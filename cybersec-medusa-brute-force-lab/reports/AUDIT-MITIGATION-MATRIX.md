# Audit Traceability & MITRE ATT&CK Mitigation Matrix

**Language: English (EN-US)**

**Document Navigation:**

* [English Version](#audit-traceability--mitre-attck-mitigation-matrix)
* [Portuguese Version - PT-BR](#matriz-de-rastreabilidade-de-auditoria-e-mitigação-mitre-attck)

---

## 1. MITRE ATT&CK Mapping & Control Verification

| MITRE ATT&CK ID | Technique / Sub-Technique | Target Protocol / Vector | Analyzed Mechanism in Lab | Engineered Defensive Control | Repository Artifact / Evidence |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`T1110.001`** | Brute Force: Password Guessing | `FTP (TCP/21)` & `HTTP Form (TCP/80)` | Multi-threaded dictionary testing via `ftp.mod` & `web-form.mod` | Socket concurrency cap (`max_per_ip=2`), forced delay (`delay_failed_login=5`), and IP ban | [`configs/vsftpd-hardened.conf`](../configs/vsftpd-hardened.conf), [`commands/02-module-specs.log`](../commands/02-module-specs.log) |
| **`T1110.003`** | Brute Force: Password Spraying | `SMB (TCP/445)` (`smbnt.mod v3.0`) | Testing single seasonal password across enumerated accounts ([`audit-users.txt`](../configs/audit-users.txt)) | Mandatory `SMB3` encryption, PAM lockout enforcement (`deny=3`), and `Fail2Ban` `[samba]` jail | [`configs/smb-hardened.conf`](../configs/smb-hardened.conf), [`configs/faillock.conf`](../configs/faillock.conf), [`configs/jail.local`](../configs/jail.local) |
| **`T1087.001`** | Account Discovery: Local Account | `SMB (TCP/139, 445)` | Unauthenticated Null Session enumeration (`restrict anonymous = 0`) | Lockdown via `restrict anonymous = 2` and `map to guest = Never` | [`configs/smb-vulnerable.conf.example`](../configs/smb-vulnerable.conf.example), [`configs/smb-hardened.conf`](../configs/smb-hardened.conf) |
| **`T1550.002`** | Use Alternate Authentication Material: Pass the Hash | `SMB (TCP/445)` (`PASS:HASH`) | Direct NTLM hash authentication via `Session Setup AndX` & `ADMIN$` probing | Disable legacy NTLMv1/LanMan (`ntlm auth = disabled`) and enforce `server signing = mandatory` | [`commands/02-module-specs.log`](../commands/02-module-specs.log), [`configs/smb-hardened.conf`](../configs/smb-hardened.conf) |
| **`T1078`** | Valid Accounts (Empty/Default Passwords) | Linux PAM Stack (`/etc/pam.d/common-auth`) | Default Debian 12 `pam_unix.so nullok` permitting blank password fields | Removal of `nullok`, enforcement of `pam_faillock.so`, and SSH `Ed25519` key-only control plane | [`commands/03-surface-audit.log`](../commands/03-surface-audit.log), [`docs/hardening.md`](../docs/hardening.md) |

---

## 2. Telemetry & Artifact Verification Checklist

| Verification ID | Audited Component | Source Node | Evidence File | Status |
| :--- | :--- | :--- | :--- | :--- |
| **AUD-01** | Layer 2 Host-Only Adjacency (`ttl=64`) & Medusa `v2.3` Module Inventory | `kali-cyberrange` (`192.168.56.20`) | [`commands/01-env-baseline.log`](../commands/01-env-baseline.log) | Verified |
| **AUD-02** | Internal Specifications of `smbnt.mod`, `ftp.mod`, and `web-form.mod` (`DENY-SIGNAL`) | `kali-cyberrange` (`192.168.56.20`) | [`commands/02-module-specs.log`](../commands/02-module-specs.log) | Verified |
| **AUD-03** | Port Surface Minimize Audit (`Nmap` + `ss -tuln`) & PAM `common-auth` Inspection | `srv-linux-base` (`192.168.56.10`) | [`commands/03-surface-audit.log`](../commands/03-surface-audit.log) | Verified |
| **AUD-04** | Multi-Layer Hardening Configurations (`Samba`, `vsftpd`, `PAM faillock`, `Fail2Ban`) | Repository Baseline | [`configs/`](../configs/) | Verified |

---
---

# Matriz de Rastreabilidade de Auditoria e Mitigação MITRE ATT&CK

**Idioma: Português do Brasil (PT-BR)**

**Navegação do Documento:**

* [Versão em Português - PT-BR](#matriz-de-rastreabilidade-de-auditoria-e-mitigação-mitre-attck)
* [English Version](#audit-traceability--mitre-attck-mitigation-matrix)

---

## 1. Mapeamento MITRE ATT&CK e Verificação de Controles

| ID MITRE ATT&CK | Técnica / Subtécnica | Protocolo / Vetor Alvo | Mecanismo Analisado no Lab | Controle Defensivo de Engenharia | Artefato / Evidência no Repositório |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`T1110.001`** | Brute Force: Password Guessing | `FTP (TCP/21)` e `HTTP Form (TCP/80)` | Teste de dicionário multi-thread via `ftp.mod` e `web-form.mod` | Limite de conexões por IP (`max_per_ip=2`), atraso forçado (`delay_failed_login=5`) e banimento de IP | [`configs/vsftpd-hardened.conf`](../configs/vsftpd-hardened.conf), [`commands/02-module-specs.log`](../commands/02-module-specs.log) |
| **`T1110.003`** | Brute Force: Password Spraying | `SMB (TCP/445)` (`smbnt.mod v3.0`) | Teste de senha única sazonal contra contas enumeradas ([`audit-users.txt`](../configs/audit-users.txt)) | Criptografia `SMB3` obrigatória, bloqueio PAM (`deny=3`) e jail `[samba]` no `Fail2Ban` | [`configs/smb-hardened.conf`](../configs/smb-hardened.conf), [`configs/faillock.conf`](../configs/faillock.conf), [`configs/jail.local`](../configs/jail.local) |
| **`T1087.001`** | Account Discovery: Local Account | `SMB (TCP/139, 445)` | Enumeração via Sessão Nula não autenticada (`restrict anonymous = 0`) | Bloqueio estrito via `restrict anonymous = 2` e `map to guest = Never` | [`configs/smb-vulnerable.conf.example`](../configs/smb-vulnerable.conf.example), [`configs/smb-hardened.conf`](../configs/smb-hardened.conf) |
| **`T1550.002`** | Use Alternate Authentication Material: Pass the Hash | `SMB (TCP/445)` (`PASS:HASH`) | Autenticação direta com hash NTLM via `Session Setup AndX` e sondagem `ADMIN$` | Desativação de NTLMv1/LanMan (`ntlm auth = disabled`) e assinatura obrigatória (`server signing = mandatory`) | [`commands/02-module-specs.log`](../commands/02-module-specs.log), [`configs/smb-hardened.conf`](../configs/smb-hardened.conf) |
| **`T1078`** | Valid Accounts (Senhas Vazias/Padrão) | Pilha PAM Linux (`/etc/pam.d/common-auth`) | Diretiva padrão `pam_unix.so nullok` no Debian 12 permitindo senhas em branco | Remoção do `nullok`, ativação do `pam_faillock.so` e plano SSH exclusivo via chave `Ed25519` | [`commands/03-surface-audit.log`](../commands/03-surface-audit.log), [`docs/hardening.md`](../docs/hardening.md) |

---

## 2. Checklist de Verificação de Telemetria e Artefatos

| ID de Verificação | Componente Auditado | Nó de Origem | Arquivo de Evidência | Status |
| :--- | :--- | :--- | :--- | :--- |
| **AUD-01** | Adjacência Host-Only Camada 2 (`ttl=64`) e Inventário de Módulos do Medusa `v2.3` | `kali-cyberrange` (`192.168.56.20`) | [`commands/01-env-baseline.log`](../commands/01-env-baseline.log) | Verificado |
| **AUD-02** | Especificações Internas do `smbnt.mod`, `ftp.mod` e `web-form.mod` (`DENY-SIGNAL`) | `kali-cyberrange` (`192.168.56.20`) | [`commands/02-module-specs.log`](../commands/02-module-specs.log) | Verificado |
| **AUD-03** | Auditoria de Minimização de Superfície (`Nmap` + `ss -tuln`) e Inspeção PAM `common-auth` | `srv-linux-base` (`192.168.56.10`) | [`commands/03-surface-audit.log`](../commands/03-surface-audit.log) | Verificado |
| **AUD-04** | Configurações de Hardening Multi-Camada (`Samba`, `vsftpd`, `PAM faillock`, `Fail2Ban`) | Baseline do Repositório | [`configs/`](../configs/) | Verificado |
