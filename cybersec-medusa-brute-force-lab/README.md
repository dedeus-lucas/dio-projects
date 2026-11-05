# Authentication Resilience, Brute-Force Mechanics & Hardening Lab (`Medusa` & `Kali Linux`)

[![Status](https://img.shields.io/badge/Status-Completed-success?style=flat-square)]()
[![Platform](https://img.shields.io/badge/Platform-Kali%20Linux%202026.2%20%7C%20Debian%2012-blue?style=flat-square)]()
[![Methodology](https://img.shields.io/badge/Methodology-Purple%20Team%20%7C%20MITRE%20ATT%26CK-orange?style=flat-square)]()

---

**Document Navigation:**

* [English Version](#authentication-resilience-brute-force-mechanics--hardening-lab-medusa--kali-linux-1)
* [Portuguese Version - PT-BR](#laboratório-de-resiliência-de-autenticação-mecânica-de-força-bruta-e-hardening-medusa--kali-linux)

---

# Authentication Resilience, Brute-Force Mechanics & Hardening Lab (`Medusa` & `Kali Linux`)

**Language: English (EN-US)**

## 1. Executive Overview

This laboratory implements an end-to-end **Purple Team Authentication Resilience & Anti-Brute-Force Engineering study** for the **DIO.me Cybersecurity Track**. Operating across an isolated Layer 2 Host-Only Cyber Range (`192.168.56.0/24`) connecting **Kali Linux 2026.2 (`kali-cyberrange`)** and **Debian 12 (`srv-linux-base`)**, the project dissects the internal mechanics of **Medusa (`v2.3`)** across **SMB (`TCP/445`)**, **FTP (`TCP/21`)**, and **HTTP Web Forms (`TCP/80` / DVWA)**, while engineering four layers of deterministic defensive controls (`Fail2Ban`, daemon socket throttling, `PAM faillock`, and `SMB3` cryptographic hardening).

---

## 2. Dual-Node Cyber Range Topology (`192.168.56.0/24`)

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
|  enp0s8: 192.168.56.10/24 (Debian 12)   | <==> |  eth1: 192.168.56.20/24 (Kali 2026.2)   |
|  Role: PAM, Samba, vsftpd, Fail2Ban     | L2  |  Role: Medusa v2.3, smbclient, Nmap     |
+-----------------------------------------+     +-----------------------------------------+
```

---

## 3. Key Technical Deliverables & Engineering Findings

| Domain | Technical Analysis / Implementation | Verified Evidence & Artifact |
| :--- | :--- | :--- |
| **Layer 2 Baseline & Tooling Inventory** | Confirmed direct Layer 2 adjacency (`ttl=64`, `0.981 ms` cached ARP RTT) and audited all 25 dynamic `.mod` plugins in **Medusa v2.3**, **Samba `smbclient` 4.24.3**, and **Nmap 7.99**. | [`commands/01-env-baseline.log`](commands/01-env-baseline.log) |
| **SMB Password Spraying & Privilege Probing** | Dissected `smbnt.mod (3.0)` SMBv1–SMBv3 support, `PASS:HASH` capabilities, and two-stage `Session Setup AndX` + `Tree Connect AndX` (`ADMIN$`) privilege classification. | [`commands/02-module-specs.log`](commands/02-module-specs.log), [`configs/smb-hardened.conf`](configs/smb-hardened.conf) |
| **Web Form (DVWA) False-Positive RCA** | Proved why `web-form.mod (2.1)` generates mass false positives on modern web apps due to negative substring matching (`DENY-SIGNAL:"Login incorrect"`), `302 Found` redirects, and dynamic CSRF tokens. | [`docs/protocol-mechanics.md`](docs/protocol-mechanics.md), [`commands/02-module-specs.log`](commands/02-module-specs.log) |
| **Linux PAM Audit & Lockout Engineering** | Identified permissive `pam_unix.so nullok` and missing lockout policies in default Debian 12 `/etc/pam.d/common-auth`; engineered `pam_faillock.so` (`deny=3`, `unlock_time=900`). | [`commands/03-surface-audit.log`](commands/03-surface-audit.log), [`configs/faillock.conf`](configs/faillock.conf) |
| **Multi-Service Intrusion Prevention** | Engineered daemon socket throttling for FTP (`max_per_ip=2`, `delay_failed_login=5`) and dynamic IP banning across `[sshd]`, `[vsftpd]`, and `[samba]` jails. | [`configs/vsftpd-hardened.conf`](configs/vsftpd-hardened.conf), [`configs/jail.local`](configs/jail.local) |

---

## 4. Technical Documentation Pipeline

* **Architecture & Attack-Surface Specification:** [`docs/arquitetura.md`](docs/arquitetura.md)
* **Protocol Mechanics & False-Positive Root Cause Analysis:** [`docs/protocol-mechanics.md`](docs/protocol-mechanics.md)
* **Defense-in-Depth Hardening & AI/MFA Engineering Analysis:** [`docs/hardening.md`](docs/hardening.md)
* **MITRE ATT&CK Traceability & Verification Matrix:** [`reports/AUDIT-MITIGATION-MATRIX.md`](reports/AUDIT-MITIGATION-MATRIX.md)

---

## 5. Module Directory Structure

```text
cybersec-medusa-brute-force-lab/
|-- commands/
|   |-- 01-env-baseline.log
|   |-- 02-module-specs.log
|   `-- 03-surface-audit.log
|-- configs/
|   |-- audit-passwords.txt
|   |-- audit-users.txt
|   |-- faillock.conf
|   |-- jail.local
|   |-- smb-hardened.conf
|   |-- smb-vulnerable.conf.example
|   `-- vsftpd-hardened.conf
|-- docs/
|   |-- arquitetura.md
|   |-- hardening.md
|   `-- protocol-mechanics.md
|-- evidence/
|-- reports/
|   `-- AUDIT-MITIGATION-MATRIX.md
`-- README.md
```

---
---

# Laboratório de Resiliência de Autenticação, Mecânica de Força Bruta e Hardening (`Medusa` & `Kali Linux`)

**Idioma: Português do Brasil (PT-BR)**

## 1. Visão Executiva

Este laboratório implementa um estudo prático completo de **Engenharia Purple Team para Resiliência de Autenticação e Mitigação de Força Bruta** na trilha de Cibersegurança da **DIO.me**. Operando sobre um Cyber Range isolado em Camada 2 (`192.168.56.0/24`) que conecta o **Kali Linux 2026.2 (`kali-cyberrange`)** ao **Debian 12 (`srv-linux-base`)**, o projeto disseca a arquitetura interna do **Medusa (`v2.3`)** nos protocolos **SMB (`TCP/445`)**, **FTP (`TCP/21`)** e **Formulários Web HTTP (`TCP/80` / DVWA)**, projetando quatro camadas determinísticas de defesa (`Fail2Ban`, estrangulamento de sockets no daemon, `PAM faillock` e criptografia `SMB3`).

---

## 2. Topologia Dual-Node do Cyber Range (`192.168.56.0/24`)

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
|  enp0s8: 192.168.56.10/24 (Debian 12)   | <==> |  eth1: 192.168.56.20/24 (Kali 2026.2)   |
|  Papel: PAM, Samba, vsftpd, Fail2Ban    | L2  |  Papel: Medusa v2.3, smbclient, Nmap    |
+-----------------------------------------+     +-----------------------------------------+
```

---

## 3. Entregas Técnicas e Descobertas de Engenharia

| Domínio | Análise Técnica / Implementação | Evidência e Artefato Verificado |
| :--- | :--- | :--- |
| **Baseline Camada 2 e Inventário** | Confirmação de adjacência direta em Camada 2 (`ttl=64`, RTT de `0.981 ms` após cache ARP) e auditoria dos 25 módulos `.mod` do **Medusa v2.3**, **Samba `smbclient` 4.24.3** e **Nmap 7.99**. | [`commands/01-env-baseline.log`](commands/01-env-baseline.log) |
| **Password Spraying SMB e Sondagem `ADMIN$`** | Dissecação do suporte SMBv1–SMBv3 no `smbnt.mod (3.0)`, uso de `PASS:HASH` e classificação de privilégio em duas etapas (`Session Setup AndX` + `Tree Connect AndX` em `ADMIN$`). | [`commands/02-module-specs.log`](commands/02-module-specs.log), [`configs/smb-hardened.conf`](configs/smb-hardened.conf) |
| **RCA de Falsos-Positivos em Web Forms (DVWA)** | Comprovação técnica de por que o `web-form.mod (2.1)` gera falsos-positivos em massa devido à busca negativa (`DENY-SIGNAL:"Login incorrect"`), redirecionamentos `302 Found` e tokens CSRF. | [`docs/protocol-mechanics.md`](docs/protocol-mechanics.md), [`commands/02-module-specs.log`](commands/02-module-specs.log) |
| **Auditoria PAM Linux e Políticas de Lockout** | Identificação da flag permissiva `pam_unix.so nullok` no `/etc/pam.d/common-auth` padrão do Debian 12 e engenharia de bloqueio automático via `pam_faillock.so` (`deny=3`, `unlock_time=900`). | [`commands/03-surface-audit.log`](commands/03-surface-audit.log), [`configs/faillock.conf`](configs/faillock.conf) |
| **Prevenção de Intrusão Multi-Serviço** | Engenharia de estrangulamento de threads no FTP (`max_per_ip=2`, `delay_failed_login=5`) e banimento dinâmico de IP nos jails `[sshd]`, `[vsftpd]` e `[samba]`. | [`configs/vsftpd-hardened.conf`](configs/vsftpd-hardened.conf), [`configs/jail.local`](configs/jail.local) |

---

## 4. Pipeline de Documentação Técnica

* **Especificação de Arquitetura e Superfície de Ataque:** [`docs/arquitetura.md`](docs/arquitetura.md)
* **Mecânica de Protocolos e Causa Raiz de Falsos-Positivos:** [`docs/protocol-mechanics.md`](docs/protocol-mechanics.md)
* **Hardening em Profundidade e Reflexão sobre IA/MFA:** [`docs/hardening.md`](docs/hardening.md)
* **Matriz de Rastreabilidade e Mitigação MITRE ATT&CK:** [`reports/AUDIT-MITIGATION-MATRIX.md`](reports/AUDIT-MITIGATION-MATRIX.md)

---

## 5. Estrutura de Diretórios do Módulo

```text
cybersec-medusa-brute-force-lab/
|-- commands/
|   |-- 01-env-baseline.log
|   |-- 02-module-specs.log
|   `-- 03-surface-audit.log
|-- configs/
|   |-- audit-passwords.txt
|   |-- audit-users.txt
|   |-- faillock.conf
|   |-- jail.local
|   |-- smb-hardened.conf
|   |-- smb-vulnerable.conf.example
|   `-- vsftpd-hardened.conf
|-- docs/
|   |-- arquitetura.md
|   |-- hardening.md
|   `-- protocol-mechanics.md
|-- evidence/
|-- reports/
|   `-- AUDIT-MITIGATION-MATRIX.md
`-- README.md
```
