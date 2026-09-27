#!/usr/bin/env bash
set -eo pipefail

# Constantes de red y certificados
KEYCLOAK_URL="http://localhost:8081/realms/zero-trust-realm/protocol/openid-connect/token"
API_URL="https://localhost:8443/api/v1/pagos"
CERTS_DIR="./certs"

CA_CERT="${CERTS_DIR}/ca.crt"
CLIENT_VALID_CERT="${CERTS_DIR}/client-valid.crt"
CLIENT_VALID_KEY="${CERTS_DIR}/client-valid.key"
CLIENT_ROGUE_CERT="${CERTS_DIR}/client-rogue.crt"
CLIENT_ROGUE_KEY="${CERTS_DIR}/client-rogue.key"

# Colores ANSI para formateo en terminal
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Verificación de dependencias previas
command -v curl >/dev/null 2>&1 || { echo -e "${RED}Error: curl no está instalado.${NC}"; exit 1; }
command -v jq >/dev/null 2>&1 || { echo -e "${RED}Error: jq no está instalado. Ejecutá 'brew install jq'.${NC}"; exit 1; }

if [ ! -f "$CLIENT_VALID_CERT" ] || [ ! -f "$CLIENT_ROGUE_CERT" ]; then
    echo -e "${RED}Error: No se encuentran los certificados en ${CERTS_DIR}. Ejecutá 'make setup' primero.${NC}"
    exit 1
fi

echo -e "${CYAN}================================================================${NC}"
echo -e "${CYAN}      SUITE DE PRUEBAS ZERO TRUST: mTLS + OAUTH 2.0 (M2M)       ${NC}"
echo -e "${CYAN}================================================================${NC}\n"

# Helper para obtener Access Token de Keycloak
get_token() {
    local client_id=$1
    local client_secret=$2

    curl -s -X POST "$KEYCLOAK_URL" \
        -d "grant_type=client_credentials" \
        -d "client_id=${client_id}" \
        -d "client_secret=${client_secret}" | jq -r .access_token
}

# Helper para evaluar resultado
evaluate_result() {
    local http_code=$1
    local expected_code=$2
    local layer=$3

    if [ "$http_code" -eq "$expected_code" ]; then
        echo -e "  ${GREEN}✔ Resultado esperado:${NC} HTTP ${http_code}"
        echo -e "  ${GREEN}✔ Bloqueo/Paso exitoso en la capa:${NC} ${layer}\n"
    else
        echo -e "  ${RED}✘ Fallo en la prueba:${NC} Se esperaba HTTP ${expected_code} pero se obtuvo HTTP ${http_code}\n"
    fi
}

# ------------------------------------------------------------------------------
# ESCENARIO A: Intrusión directa sin certificado (L4/L7 Handshake)
# ------------------------------------------------------------------------------
echo -e "${YELLOW}[ESCENARIO A] Intrusión Directa en Red Interna${NC}"
echo -e "  Detalle: Solicitud sin certificado TLS de cliente ni credenciales."
echo -e "  Comando: curl --cacert "$CA_CERT" -X POST $API_URL"

HTTP_CODE=$(curl --cacert "$CA_CERT" -s -o /dev/null -w "%{http_code}" -X POST "$API_URL" || true)
evaluate_result "$HTTP_CODE" 400 "mTLS / Transporte (NGINX rechazó handshake)"

# ------------------------------------------------------------------------------
# ESCENARIO B: Certificado Falsificado / Untrusted CA
# ------------------------------------------------------------------------------
echo -e "${YELLOW}[ESCENARIO B] Certificado Falsificado (Untrusted CA)${NC}"
echo -e "  Detalle: Cliente presenta certificado firmado por una CA externa no autorizada."
echo -e "  Comando: curl --cacert "$CA_CERT" --cert client-rogue.crt --key client-rogue.key -X POST $API_URL"

HTTP_CODE=$(curl --cacert "$CA_CERT" -s -o /dev/null -w "%{http_code}" \
    --cert "$CLIENT_ROGUE_CERT" \
    --key "$CLIENT_ROGUE_KEY" \
    -X POST "$API_URL" || true)
evaluate_result "$HTTP_CODE" 400 "mTLS / Validación de Cadena de Confianza"

# ------------------------------------------------------------------------------
# ESCENARIO C: Máquina Comprometida sin Token OAuth
# ------------------------------------------------------------------------------
echo -e "${YELLOW}[ESCENARIO C] Máquina con mTLS Válido pero SIN Token OAuth${NC}"
echo -e "  Detalle: Pasa el túnel mTLS pero no presenta cabecera Authorization."
echo -e "  Comando: curl --cacert "$CA_CERT" --cert client-valid.crt --key client-valid.key -X POST $API_URL"

HTTP_CODE=$(curl --cacert "$CA_CERT" -s -o /dev/null -w "%{http_code}" \
    --cert "$CLIENT_VALID_CERT" \
    --key "$CLIENT_VALID_KEY" \
    -X POST "$API_URL" || true)
evaluate_result "$HTTP_CODE" 401 "OAuth 2.0 / Capa de Aplicación (ASP.NET Core JwtBearer)"

# ------------------------------------------------------------------------------
# ESCENARIO D: Token con Privilegios Insuficientes (RBAC/Scopes)
# ------------------------------------------------------------------------------
echo -e "${YELLOW}[ESCENARIO D] Token con Privilegios Insuficientes (Rol Incorrecto)${NC}"
echo -e "  Detalle: Cliente obtiene token como 'reportes-service' (solo Reports.Read)."

TOKEN_REPORTS=$(get_token "reportes-service" "secret-reportes-123")

if [ "$TOKEN_REPORTS" == "null" ] || [ -z "$TOKEN_REPORTS" ]; then
    echo -e "  ${RED}Error: No se pudo obtener el token de Keycloak para reportes-service.${NC}\n"
else
    echo -e "  Token JWT emitido exitosamente. Invocando API..."
    HTTP_CODE=$(curl --cacert "$CA_CERT" -s -o /dev/null -w "%{http_code}" \
        --cert "$CLIENT_VALID_CERT" \
        --key "$CLIENT_VALID_KEY" \
        -H "Authorization: Bearer $TOKEN_REPORTS" \
        -X POST "$API_URL" || true)
    evaluate_result "$HTTP_CODE" 403 "Autorización ASP.NET Core (Falta política RequirePaymentsWrite)"
fi

# ------------------------------------------------------------------------------
# ESCENARIO E: Flujo Legítimo (mTLS Válido + Token con Payments.Write)
# ------------------------------------------------------------------------------
echo -e "${YELLOW}[ESCENARIO E] Flujo Legítimo (Zero Trust Completado)${NC}"
echo -e "  Detalle: mTLS corporativo + Token emitido para 'facturacion-service' con rol Payments.Write."

TOKEN_PAYMENTS=$(get_token "facturacion-service" "secret-facturacion-123")

if [ "$TOKEN_PAYMENTS" == "null" ] || [ -z "$TOKEN_PAYMENTS" ]; then
    echo -e "  ${RED}Error: No se pudo obtener el token de Keycloak para facturacion-service.${NC}\n"
else
    echo -e "  Token JWT emitido exitosamente. Invocando API..."
    RESPONSE=$(curl --cacert "$CA_CERT" -s \
        --cert "$CLIENT_VALID_CERT" \
        --key "$CLIENT_VALID_KEY" \
        -H "Authorization: Bearer $TOKEN_PAYMENTS" \
        -X POST "$API_URL")

    HTTP_CODE=$(curl --cacert "$CA_CERT" -s -o /dev/null -w "%{http_code}" \
        --cert "$CLIENT_VALID_CERT" \
        --key "$CLIENT_VALID_KEY" \
        -H "Authorization: Bearer $TOKEN_PAYMENTS" \
        -X POST "$API_URL" || true)

    evaluate_result "$HTTP_CODE" 200 "Ambas capas (mTLS L4/L7 + OAuth RBAC L7)"
    echo -e "  ${BLUE}Respuesta JSON del Resource Server (.NET 8):${NC}"
    echo "  $RESPONSE" | jq . 2>/dev/null || echo "  $RESPONSE"
fi

echo -e "\n${CYAN}================================================================${NC}"
echo -e "${CYAN}                    SUITE FINALIZADA CON ÉXITO                  ${NC}"
echo -e "${CYAN}================================================================${NC}"