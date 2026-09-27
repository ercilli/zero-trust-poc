const express = require('express');
const { execFile } = require('child_process');
const path = require('path');

const app = express();
app.use(express.static(path.join(__dirname, 'public')));

const PROXY_URL = process.env.PROXY_URL || 'https://proxy-servicio-b:443';
const API_URL = `${PROXY_URL}/api/v1/pagos`;
const KEYCLOAK_TOKEN_URL =
  process.env.KEYCLOAK_TOKEN_URL ||
  'http://keycloak:8080/realms/zero-trust-realm/protocol/openid-connect/token';
const CERTS_DIR = process.env.CERTS_DIR || '/certs';

const CA_CERT = `${CERTS_DIR}/ca.crt`;
const CLIENT_VALID_CERT = `${CERTS_DIR}/client-valid.crt`;
const CLIENT_VALID_KEY = `${CERTS_DIR}/client-valid.key`;
const CLIENT_ROGUE_CERT = `${CERTS_DIR}/client-rogue.crt`;
const CLIENT_ROGUE_KEY = `${CERTS_DIR}/client-rogue.key`;

// Códigos de salida de curl asociados a fallos de capa TLS/SSL.
const SSL_CURL_ERROR_CODES = new Set([35, 51, 52, 55, 56, 58, 59, 60, 77, 82, 83, 90, 91]);

const HTTP_CODE_MARKER = '__HTTP_CODE__:';

function runCurl(args) {
  return new Promise((resolve) => {
    const fullArgs = ['-s', '-w', `\n${HTTP_CODE_MARKER}%{http_code}`, ...args];
    execFile('curl', fullArgs, { timeout: 10000 }, (error, stdout) => {
      const idx = stdout.lastIndexOf(HTTP_CODE_MARKER);
      let body = stdout;
      let httpCode = '000';
      if (idx !== -1) {
        body = stdout.slice(0, idx).replace(/\n$/, '');
        httpCode = stdout.slice(idx + HTTP_CODE_MARKER.length).trim() || '000';
      }
      resolve({
        exitCode: error ? error.code ?? 1 : 0,
        body,
        httpCode,
      });
    });
  });
}

async function getToken(clientId, clientSecret) {
  try {
    const res = await fetch(KEYCLOAK_TOKEN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: clientId,
        client_secret: clientSecret,
      }),
    });
    const data = await res.json().catch(() => ({}));
    return data.access_token || null;
  } catch {
    return null;
  }
}

function tlsStatusFrom(httpCode, exitCode) {
  // Un 400 de NGINX ("No required SSL certificate was sent" o cadena de
  // confianza inválida) es la capa mTLS rechazando la conexión, aunque el
  // handshake criptográfico en sí haya completado.
  if (httpCode === '400') return 'Rechazado';
  if (httpCode && httpCode !== '000') return 'Aceptado';
  if (SSL_CURL_ERROR_CODES.has(exitCode)) return 'Rechazado';
  return 'Rechazado';
}

// steps: 0 cliente, 1 nginx (mTLS), 2 payments-api authN (JWT), 3 payments-api authZ (RBAC), 4 éxito
const STEP_DEFS = [
  { id: 'cliente', label: 'Cliente' },
  { id: 'nginx_mtls', label: 'NGINX · mTLS' },
  { id: 'payments_api_authn', label: 'Payments API · AuthN (JWT)' },
  { id: 'payments_api_authz', label: 'Payments API · AuthZ (RBAC)' },
  { id: 'success', label: 'Pago Procesado' },
];

function buildDiagram(stopIndex, stopIsSuccess) {
  return STEP_DEFS.map((step, i) => {
    let status;
    if (i < stopIndex) status = 'ok';
    else if (i === stopIndex) status = stopIsSuccess ? 'ok' : 'blocked';
    else status = 'unreached';
    return { ...step, status };
  });
}

function diagramForResult(httpCode, tls) {
  if (tls === 'Rechazado') return buildDiagram(1, false);
  if (httpCode === '401') return buildDiagram(2, false);
  if (httpCode === '403') return buildDiagram(3, false);
  if (httpCode === '200' || httpCode === '201') return buildDiagram(4, true);
  // Cualquier otro código: se asume que llegó hasta la API pero no se pudo clasificar con precisión.
  return buildDiagram(2, false);
}

const SCENARIOS = {
  A: {
    title: 'Escenario A: Intrusión Directa',
    description: 'Solicitud sin certificado TLS de cliente ni credenciales.',
    async run() {
      const args = ['--cacert', CA_CERT, '-X', 'POST', API_URL];
      const curlCmd = `curl --cacert ca.crt -X POST ${API_URL}`;
      const { httpCode, exitCode, body } = await runCurl(args);
      const tls = tlsStatusFrom(httpCode, exitCode);
      return { curlCmd, httpCode, body, tls, diagram: diagramForResult(httpCode, tls) };
    },
  },
  B: {
    title: 'Escenario B: Certificado Falsificado',
    description: 'Cliente presenta certificado firmado por una CA externa no autorizada (untrusted CA).',
    async run() {
      const args = [
        '--cacert', CA_CERT,
        '--cert', CLIENT_ROGUE_CERT,
        '--key', CLIENT_ROGUE_KEY,
        '-X', 'POST', API_URL,
      ];
      const curlCmd = `curl --cacert ca.crt --cert client-rogue.crt --key client-rogue.key -X POST ${API_URL}`;
      const { httpCode, exitCode, body } = await runCurl(args);
      const tls = tlsStatusFrom(httpCode, exitCode);
      return { curlCmd, httpCode, body, tls, diagram: diagramForResult(httpCode, tls) };
    },
  },
  C: {
    title: 'Escenario C: Máquina Comprometida (sin token)',
    description: 'mTLS válido pero sin cabecera Authorization.',
    async run() {
      const args = [
        '--cacert', CA_CERT,
        '--cert', CLIENT_VALID_CERT,
        '--key', CLIENT_VALID_KEY,
        '-X', 'POST', API_URL,
      ];
      const curlCmd = `curl --cacert ca.crt --cert client-valid.crt --key client-valid.key -X POST ${API_URL}`;
      const { httpCode, exitCode, body } = await runCurl(args);
      const tls = tlsStatusFrom(httpCode, exitCode);
      return { curlCmd, httpCode, body, tls, diagram: diagramForResult(httpCode, tls) };
    },
  },
  D: {
    title: 'Escenario D: Privilegios Insuficientes',
    description: "Token válido de 'reportes-service' (solo Reports.Read) contra un endpoint que exige Payments.Write.",
    async run() {
      const token = await getToken('reportes-service', 'secret-reportes-123');
      if (!token) {
        return {
          curlCmd: '(no se pudo obtener el token de Keycloak para reportes-service)',
          httpCode: '000',
          body: '',
          tls: 'N/A',
          diagram: diagramForResult('000', 'Rechazado'),
        };
      }
      const args = [
        '--cacert', CA_CERT,
        '--cert', CLIENT_VALID_CERT,
        '--key', CLIENT_VALID_KEY,
        '-H', `Authorization: Bearer ${token}`,
        '-X', 'POST', API_URL,
      ];
      const curlCmd = `curl --cacert ca.crt --cert client-valid.crt --key client-valid.key -H "Authorization: Bearer <token-reportes-service>" -X POST ${API_URL}`;
      const { httpCode, exitCode, body } = await runCurl(args);
      const tls = tlsStatusFrom(httpCode, exitCode);
      return { curlCmd, httpCode, body, tls, diagram: diagramForResult(httpCode, tls) };
    },
  },
  E: {
    title: 'Escenario E: Flujo Legítimo',
    description: "mTLS corporativo + token de 'facturacion-service' con rol Payments.Write.",
    async run() {
      const token = await getToken('facturacion-service', 'secret-facturacion-123');
      if (!token) {
        return {
          curlCmd: '(no se pudo obtener el token de Keycloak para facturacion-service)',
          httpCode: '000',
          body: '',
          tls: 'N/A',
          diagram: diagramForResult('000', 'Rechazado'),
        };
      }
      const args = [
        '--cacert', CA_CERT,
        '--cert', CLIENT_VALID_CERT,
        '--key', CLIENT_VALID_KEY,
        '-H', `Authorization: Bearer ${token}`,
        '-X', 'POST', API_URL,
      ];
      const curlCmd = `curl --cacert ca.crt --cert client-valid.crt --key client-valid.key -H "Authorization: Bearer <token-facturacion-service>" -X POST ${API_URL}`;
      const { httpCode, exitCode, body } = await runCurl(args);
      const tls = tlsStatusFrom(httpCode, exitCode);
      return { curlCmd, httpCode, body, tls, diagram: diagramForResult(httpCode, tls) };
    },
  },
};

app.get('/api/scenarios', (req, res) => {
  res.json(
    Object.entries(SCENARIOS).map(([key, s]) => ({ key, title: s.title, description: s.description }))
  );
});

app.post('/api/run/:key', async (req, res) => {
  const scenario = SCENARIOS[req.params.key];
  if (!scenario) return res.status(404).json({ error: 'Escenario desconocido' });
  console.log(`[run] Escenario ${req.params.key}: ${scenario.title}`);
  try {
    const result = await scenario.run();
    console.log(`[run] Escenario ${req.params.key} -> TLS: ${result.tls}, HTTP: ${result.httpCode}`);
    res.json(result);
  } catch (err) {
    console.error(`[run] Escenario ${req.params.key} error: ${err.message}`);
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Dashboard escuchando en :${PORT}`));
