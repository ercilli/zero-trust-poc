# SYSTEM SPECIFICATION: Zero Trust M2M Implementation

Actúa como un Ingeniero de Software Principal y Especialista en Ciberseguridad. Tu objetivo es implementar, configurar o auditar los componentes de este monorepo respetando los siguientes requerimientos arquitectónicos deterministas.

## 1. Requisitos Criptográficos y de Infraestructura (PKI)
* La Autoridad Certificadora (CA) debe ser autofirmada con RSA 4096 bits y SHA-256.
* Los certificados de servidor y cliente deben usar RSA 2048 bits con un periodo de validez de 365 días.
* NGINX debe configurarse con:
  * `ssl_verify_client on;`
  * `ssl_client_certificate /etc/nginx/certs/ca.crt;`
  * El proxy debe pasar al upstream el header `X-Client-Cert-DN $ssl_client_s_dn` para fines de trazabilidad.

## 2. Requisitos de Identidad (Keycloak)
* Realm: `zero-trust-realm`.
* Clientes configurados con `Access Type = Confidential`, flujo `Service Accounts Enabled = true` (Client Credentials Grant):
  * `facturacion-service`: Rol `Payments.Write`. Secret: `secret-facturacion-123`.
  * `reportes-service`: Rol `Reports.Read`. Secret: `secret-reportes-123`.
* Audiencia (`aud`) configurada estrictamente hacia `payments-api`.

## 3. Requisitos de Implementación ASP.NET Core
* Minimal APIs con .NET 8.
* Middleware `Microsoft.AspNetCore.Authentication.JwtBearer`:
  * `Authority`: `http://keycloak:8080/realms/zero-trust-realm`.
  * `Audience`: `payments-api`.
  * `RequireHttpsMetadata`: `false` (solo dentro de la red Docker).
* Definición de Política:
  * `RequirePaymentsWrite`: exige el claim `roles` conteniendo `Payments.Write`.
* Endpoints:
  * `POST /api/v1/pagos`: protegido con `.RequireAuthorization("RequirePaymentsWrite")`.
  * `GET /health`: anónimo.

## 4. Requisitos del Dashboard
* Debe ofrecer 5 botones correspondientes a los Escenarios A, B, C, D y E.
* Para cada request ejecutado, debe mostrar:
  1. Comando `curl` equivalente ejecutado.
  2. Estado del Handshake TLS (Aceptado / Rechazado).
  3. Código HTTP devuelto.
  4. Payload o error devuelto.
  5. Diagrama visual que resalte en rojo o verde dónde se detuvo la petición.