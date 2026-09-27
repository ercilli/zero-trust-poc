# Zero Trust M2M: PoC de Defensa en Profundidad (mTLS + OAuth 2.0)

Este repositorio implementa una arquitectura **Zero Trust** para comunicaciones máquina a máquina (M2M) utilizando **ASP.NET Core**, **mTLS (Mutual TLS)**, y **OAuth 2.0 (Client Credentials Grant)** sobre una red interna simulada con Docker.

zero-trust-poc/
├── README.md                 # Documentación arquitectónica, propósito y guía de escenarios
├── SPEC.md                   # System Prompt / Spec técnica para desarrollo asistido por IA
├── docker-compose.yml        # Orquestación de toda la topología de red y servicios
├── Makefile                  # Automatización de tareas (setup, run, test, teardown)
├── scripts/
│   ├── generate-certs.sh     # Generación automatizada de CA, servidores y clientes (legítimo y rogue)
│   └── run-scenarios.sh      # Suite de pruebas CLI para simular los escenarios A, B, C, D y E
├── certs/                    # Almacén de llaves y certificados x509 (.gitignore para *.key)
├── config/
│   ├── nginx.conf            # Configuración de terminación mTLS y reverse proxy
│   └── keycloak/
│       └── realm-export.json # Realm preconfigurado con clientes, roles y scopes
├── src/
│   ├── PaymentsApi/          # Resource Server en .NET 8 / Minimal API con JwtBearer
│   │   ├── PaymentsApi.csproj
│   │   ├── Program.cs
│   │   └── Dockerfile
│   └── Dashboard/            # Web UI interactiva para ejecutar ataques y visualizar el flujo
│       ├── package.json
│       ├── server.js         # Backend ligero en Node.js que ejecuta los curls contra la red interna
│       ├── public/
│       │   └── index.html    # Visualizador interactivo de tráfico L4/L7 y logs de auditoría
│       └── Dockerfile

---

## 1. Arquitectura de Alto Nivel

+-------------------------------------------------------------------------------+
|                                                                               |
|  +-------------------+       +---------------------+                          |
|  |     Keycloak      |       |      Dashboard      |                          |
|  | (Auth Server/IdP) |       |  (Consola de Tests) |                          |
|  |    Port: 8081     |       |     Port: 3000      |                          |
|  +---------^---------+       +----------+----------+                          |
|            |                            |                                     |
|            | Token Request              | Triggers Escenarios                 |
|            | (OAuth 2.0)                |                                     |
|            +-------------+              |                                     |
|                          |              v                                     |
|                   +------+----------------------+                             |
|                   |  Attacker / Test Runner Bot |                             |
|                   +--------------+--------------+                             |
|                                  |                                            |
|                                  | Tráfico HTTPS / mTLS                       |
|                                  v                                            |
|                    +---------------------------+                              |
|                    |     Proxy NGINX (mTLS)    |                              |
|                    |         Port: 8443        |                              |
|                    +-------------+-------------+                              |
|                                  |                                            |
|                                  | HTTP Plano (Interno)                       |
|                                  v                                            |
|                    +---------------------------+                              |
|                    |   Payments API (.NET 8)   |                              |
|                    |     (Resource Server)     |                              |
|                    +---------------------------+                              |
|                                                                               |
+-------------------------------------------------------------------------------+

---

## 2. Propósito de Cada Componente

* **Keycloak (Identity Provider):** Emite Access Tokens (JWT) mediante el flujo `client_credentials`. Configurado con roles granulares (`Payments.Write`, `Reports.Read`).
* **NGINX (mTLS Gateway):** Actúa como guardián perimetral L4/L7. Exige y valida criptográficamente que el cliente presente un certificado firmado por la Autoridad Certificadora interna (`PoC-Internal-CA`).
* **Payments API (ASP.NET Core):** Resource Server. No maneja sesiones ni base de datos de usuarios; valida la firma criptográfica del JWT emitido por Keycloak y evalúa políticas de autorización por scopes/roles.
* **Dashboard / Runner:** Interfaz de control para disparar solicitudes HTTP manipulando certificados y cabeceras de autorización en tiempo real.

---

## 3. Matriz de Escenarios de Penetración

| Escenario | Certificado TLS Cliente | Access Token JWT | Capa Evaluada | Resultado Esperado | Explicación Técnica |
|---|---|---|---|---|---|
| **A: Intrusión Directa** | Ninguno | Ninguno | Transporte (L4/L7) | `400 Bad Request` | NGINX rechaza el handshake TLS antes de rutear la petición. La API jamás se entera. |
| **B: Certificado Falsificado** | Firmado por CA Externa | Ninguno | Transporte (L4/L7) | `400 Bad Request` | Fallo de validación en la cadena de confianza (`certificate verify failed`). |
| **C: Máquina Comprometida** | Certificado Legítimo | Ninguno | Aplicación (L7) | `401 Unauthorized` | El túnel TLS es válido, pero el middleware `JwtBearer` en .NET bloquea la llamada por falta de token. |
| **D: Privilegios Insuficientes** | Certificado Legítimo | Token con `Reports.Read` | Aplicación (L7) | `403 Forbidden` | Identidad de aplicación válida, pero el endpoint exige la política `RequirePaymentsWrite`. |
| **E: Flujo Legítimo** | Certificado Legítimo | Token con `Payments.Write` | Transporte + App | `200 OK / 201 Created` | Ambos anillos de seguridad superados exitosamente. |

---

## 4. Requisitos Previos

* **Docker** y **Docker Compose** (`docker compose version`).
* **OpenSSL** — genera los certificados en el host antes de levantar los contenedores.
* **jq** y **curl** — solo necesarios para `make test` (la suite CLI). El Dashboard web no los requiere en el host.

## 5. Guía Rápida de Ejecución

```bash
# 1. Clonar el repositorio
git clone <repo-url> && cd zero-trust-poc

# 2. Generar certificados e iniciar todos los servicios
make setup
make up

# 3. Acceder al Dashboard Interactivo
open http://localhost:3000

# 4. O ejecutar las pruebas vía CLI
make test