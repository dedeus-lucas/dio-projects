# DIO.me Technical Projects & Engineering Laboratories

[![Repository Status](https://img.shields.io/badge/Repository-Active%20Monorepo-blue?style=flat-square)]()
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20WSL2%20%7C%20Cyber%20Range-orange?style=flat-square)]()
[![Documentation Standard](https://img.shields.io/badge/Standard-Bilingual%20EN%20%7C%20PT--BR-success?style=flat-square)]()

---

**Document Navigation:**

* [English Version](#diome-technical-projects--engineering-laboratories)
* [Versão em Português - PT-BR](#laboratórios-de-engenharia-e-projetos-técnicos-diome)

---

## 1. Monorepo Overview & Engineering Philosophy

This repository centralizes practical engineering challenges, cybersecurity laboratories, and technical projects developed across **DIO.me** bootcamps and tracks. Instead of fragmenting educational deliverables across dozens of isolated repositories, this **Monorepo** consolidates each challenge into a dedicated, self-contained module following an evidence-based engineering standard.

When an individual project matures into a full-scale production system or standalone tool, it follows a **Graduation Pattern** and is promoted to its own dedicated repository while keeping an indexed reference here.

---

## 2. Domain Prefix Taxonomy & Project Index

To allow seamless migration of historical laboratories without chronological numbering collisions—and to guarantee automatic alphabetical clustering on GitHub—all modules use a **Flat Domain Prefix Taxonomy**:

- **`cybersec-*`**: Cybersecurity, Red/Blue/Purple Team, Network & Linux Security
- **`ai-*`**: Artificial Intelligence, LLMs, Prompt Engineering & AI Agents
- **`cloud-*`**: Cloud Computing (AWS, Azure, GCP) & Infrastructure as Code
- **`dev-*`**: Software Engineering, APIs, Backend & Frontend Applications
- **`devops-*`**: CI/CD, Containers, Kubernetes & Observability

| Domain | Project Directory | Technical Scope | Primary Focus | Status |
| :--- | :--- | :--- | :--- | :--- |
| **CyberSec** | [`cybersec-medusa-brute-force-lab`](cybersec-medusa-brute-force-lab/) | Authentication Resilience, Brute-Force Mechanics & Hardening | Kali Linux, Debian 12, Medusa, SMB/FTP/Web Auth, PAM & Fail2Ban Mitigation | Completed |

---

## 3. Five-Tier Quality & Documentation Standard

Every laboratory inside this repository adheres to a strict five-tier bilingual (**EN-US** & **PT-BR**) structure:

- **Executive Module Overview (`README.md`):** Bilingual gateway summarizing the challenge objectives, architecture topology, execution workflow, and mitigation takeaways.
- **Technical Deep-Dive & Analysis (`docs/`):** Comprehensive engineering documentation covering protocol mechanics, attack-surface analysis, and defensive architecture.
- **Configuration & Wordlist Baselines (`configs/`):** Sanitized service configurations (`smb.conf`, `vsftpd.conf`, `jail.local`, PAM policies) and controlled test datasets.
- **Raw Telemetry & Audit Logs (`commands/`):** Plain-text terminal outputs, service verification logs, and network socket inspections.
- **Verification & Mitigation Matrix (`reports/`):** Traceability records mapping identified vulnerabilities to verified defensive controls and MITRE ATT&CK techniques.

---

## 4. Repository Structure

```text
dio-projects/
|-- cybersec-medusa-brute-force-lab/
|   |-- commands/
|   |-- configs/
|   |-- docs/
|   |-- evidence/
|   |-- reports/
|   `-- README.md
|-- .gitignore
`-- README.md
```

---
---

# Laboratórios de Engenharia e Projetos Técnicos DIO.me

[![Status do Repositório](https://img.shields.io/badge/Repositorio-Monorepo%20Ativo-blue?style=flat-square)]()
[![Plataforma](https://img.shields.io/badge/Plataforma-Linux%20%7C%20WSL2%20%7C%20Cyber%20Range-orange?style=flat-square)]()
[![Padrão de Documentação](https://img.shields.io/badge/Padrao-Bilingue%20EN%20%7C%20PT--BR-success?style=flat-square)]()

---

**Navegação do Documento:**

* [Versão em Português - PT-BR](#laboratórios-de-engenharia-e-projetos-técnicos-diome)
* [English Version](#diome-technical-projects--engineering-laboratories)

---

## 1. Visão Geral do Monorepo e Filosofia de Engenharia

Este repositório centraliza desafios práticos de engenharia, laboratórios de cibersegurança e projetos técnicos desenvolvidos ao longo de bootcamps e formações da **DIO.me**. Em vez de fragmentar entregas educacionais em dezenas de repositórios isolados, este **Monorepo** consolida cada desafio em um módulo próprio e autocontido, seguindo um rigoroso padrão de engenharia baseada em evidências.

Quando um projeto individual evolui para um sistema de nível de produção ou ferramenta autônoma, ele segue o **Padrão de Graduação (*Graduation Pattern*)**, sendo promovido para um repositório exclusivo enquanto mantém sua referência indexada neste catálogo.

---

## 2. Taxonomia de Prefixos por Domínio e Índice de Projetos

Para permitir a incorporação contínua de projetos anteriores sem colisão de numeração cronológica — e garantir agrupamento alfabético automático na interface do GitHub — todos os módulos utilizam uma **Taxonomia Plana de Prefixos por Domínio**:

- **`cybersec-*`**: Cibersegurança, Red/Blue/Purple Team, Segurança de Redes e Linux
- **`ai-*`**: Inteligência Artificial, LLMs, Engenharia de Prompt e Agentes de IA
- **`cloud-*`**: Computação em Nuvem (AWS, Azure, GCP) e Infraestrutura como Código
- **`dev-*`**: Engenharia de Software, APIs, Aplicações Backend e Frontend
- **`devops-*`**: CI/CD, Containers, Kubernetes e Observabilidade

| Domínio | Diretório do Projeto | Escopo Técnico | Foco Principal | Status |
| :--- | :--- | :--- | :--- | :--- |
| **CyberSec** | [`cybersec-medusa-brute-force-lab`](cybersec-medusa-brute-force-lab/) | Resiliência de Autenticação, Mecânica de Força Bruta e Hardening | Kali Linux, Debian 12, Medusa, Auth SMB/FTP/Web, Mitigação com PAM & Fail2Ban | Concluído |

---

## 3. Padrão de Qualidade e Documentação em Cinco Camadas

Cada laboratório dentro deste repositório segue uma estrutura bilíngue (**EN-US** e **PT-BR**) dividida em cinco camadas:

- **Visão Executiva do Módulo (`README.md`):** Porta de entrada bilíngue resumindo objetivos do desafio, topologia arquitetural, fluxo de execução e conclusões de mitigação.
- **Análise Técnica Profunda (`docs/`):** Documentação de engenharia detalhando mecânicas de protocolo, superfície de ataque e arquitetura defensiva.
- **Baselines de Configuração e Wordlists (`configs/`):** Arquivos de configuração higienizados (`smb.conf`, `vsftpd.conf`, `jail.local`, políticas PAM) e conjuntos de dados de teste controlados.
- **Telemetria Bruta e Logs de Auditoria (`commands/`):** Transcrições de terminal em texto puro, validação de serviços e inspeção de sockets de rede.
- **Matriz de Verificação e Mitigação (`reports/`):** Registros de rastreabilidade conectando vulnerabilidades identificadas a controles defensivos verificados e técnicas do MITRE ATT&CK.

---

## 4. Estrutura do Repositório

```text
dio-projects/
|-- cybersec-medusa-brute-force-lab/
|   |-- commands/
|   |-- configs/
|   |-- docs/
|   |-- evidence/
|   |-- reports/
|   `-- README.md
|-- .gitignore
`-- README.md
```
