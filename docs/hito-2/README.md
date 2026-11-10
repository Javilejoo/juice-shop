# Hito 2 · Pipeline y ataque

> Pipeline: **Javier Prado** · Umbral del gate y este documento: **Bryan España** · PoC: **Luis Pedro Montenegro**.

## Pipeline

- Workflow: [`.github/workflows/devsecops.yml`](../../.github/workflows/devsecops.yml) — corre en cada `push` y `pull_request`.
- Workflows originales de Juice Shop: deshabilitados (movidos fuera de `.github/workflows/`).
- Corrida de evidencia: [42892293620](https://github.com/Javilejoo/juice-shop/actions/runs/42892293620)
- Modo del gate: **`reporte`** (`SECURITY_GATE: "reporte"`)

### Artefactos de la corrida

| Artefacto | Archivo | Control |
|---|---|---|
| SBOM CycloneDX (Syft) | `sbom.cdx.json` | SBOM |
| Reporte Semgrep | `semgrep.json` / salida del job | SAST |
| Reporte npm audit | `npm-audit.json` / salida del job | SCA |
| Reporte ZAP baseline | `reporte-zap.html`, `reporte-zap.json` | DAST |

*(Ajustar los nombres a los que publica el workflow de Javier y agregar captura de la corrida en `img/`.)*

### Umbral del security gate y su justificación

| Control | Herramienta | Umbral (falla el gate si…) | Qué hicimos con los hallazgos |
|---|---|---|---|
| SAST | Semgrep (`p/default` + `p/owasp-top-ten`) | Hay al menos un hallazgo de severidad **ERROR** | **Supera el umbral.** Semgrep marca como ERROR la inyección SQL de `routes/login.ts:34` y `routes/search.ts:23` (`express-sequelize-injection`) → RS-01, PoC-01/02. La llave JWT (`insecurity.ts:54`) y los listados de directorio (`server.ts`) salen como WARNING: se registran, no disparan el gate. El MD5 de `insecurity.ts:41` **no** lo detecta Semgrep (brecha cubierta por revisión de código, RS-06) |
| SCA | `npm audit --omit=dev --audit-level=high` | Hay al menos una vulnerabilidad **high** o **critical** en dependencias de producción | **Supera el umbral: 6 critical, 12 high** (más 7 moderate, 2 low). Critical: `jsonwebtoken` (*verification bypass*), `marsdb` (*command injection*, sin versión corregida), `crypto-js`, `lodash`, `tar`. Se mapean a RS-05, RS-01, RS-06, RS-07 y RS-11; candidatos a actualizar en H4 |
| SBOM | Syft, CycloneDX | No es un control de bloqueo: el artefacto `sbom.cdx.json` **siempre** se publica | `sbom.cdx.json` CycloneDX 1.6 con 539 componentes (533 npm). Inventario oficial de versiones; base para SCA y para responder a un nuevo CVE |
| DAST | ZAP baseline (`zap-baseline.py -I`) | Alguna alerta de **riesgo alto** (FAIL) | **No supera el umbral: 0 altas**, 2 medias (falta de CSP 10038 → RS-03; CORS permisivo 10098), 4 bajas, 3 informativas. ZAP baseline es pasivo y corre por HTTP: no prueba errores (RS-08) ni HSTS (RS-06); eso lo cubren los PoC y la revisión de código |

**Por qué este umbral**

1. **Sale del apetito de riesgo del H1 (PASTA etapa 1).** Definimos como no aceptable el acceso a datos de otros clientes, la toma de cuenta admin y la ejecución de código: eso corresponde a severidad Critical/High. Media se acepta con control compensatorio (WAF + SIEM) y fecha de corrección. Por eso el gate corta en **ERROR** (Semgrep), **high/critical** (npm audit) y **riesgo alto** (ZAP), y deja Medium/Low como registro.
2. **Coincide con la política de gates del curso:** Critical bloquea sin excepción, High bloquea salvo excepción aprobada con expiración, Medium genera seguimiento, Low/Info solo se registra.
3. **Evita ruido:** con `WARNING`/`moderate` como umbral, el gate fallaría también por hallazgos de baja severidad y el equipo dejaría de leerlo. `--omit=dev` limita SCA a lo que llega a producción.
4. **Resultado de la corrida 42892293620:** SAST y SCA superan el umbral y DAST no. En modo `bloqueo` el pipeline habría fallado, lo cual confirma que el umbral detecta lo que el H1 clasificó como no aceptable (SQLi, dependencias JWT críticas).
5. **Modo `reporte` y no `bloqueo`.** Juice Shop es **vulnerable a propósito**: en modo bloqueo el pipeline fallaría en cada push desde el primer día y no tendríamos un pipeline "verde" donde comparar. Siguiendo la adopción incremental vista en clase (reporte → umbrales → primer gate), el pipeline corre los 4 controles, publica todo y marca qué superó el umbral, pero no detiene la integración. En el **H4** cambiamos a `SECURITY_GATE: "bloqueo"` sobre las vulnerabilidades corregidas para demostrar que el gate pasa después de la corrección.
6. **Excepciones:** un hallazgo High que no se corrija en el proyecto queda documentado como riesgo residual (PASTA etapa 7, informe final) con su control compensatorio (regla del WAF o del SIEM).

## PoC del Equipo rojo

WAF en `DetectionOnly`, proxy apuntando a `http://localhost:8080`. ZAP → Burp Repeater → clasificación → repetición en Postman con hora. Fichas completas en [`poc/`](poc/).

- Reporte de ZAP: `poc/<archivo-reporte-zap>.html`

| # | Vulnerabilidad | Endpoint | OWASP Top 10:2025 | CWE | CVSS v3.1 (vector) | Evidencia |
|---|---|---|---|---|---|---|
| PoC-01 | *(Luis Pedro)* | | | | | `poc/01-...` |
| PoC-02 | | | | | | `poc/02-...` |
| PoC-03 | | | | | | `poc/03-...` |
| PoC-04 | | | | | | `poc/04-...` |

> Relación con el H1: cada PoC debe corresponder a un caso de abuso (CA-01..CA-07) y a una amenaza (T-xx).
> Sugeridas: PoC-01 ↔ CA-01 (SQLi login), PoC-02 ↔ CA-02 (SQLi búsqueda), PoC-03 ↔ CA-03 (XSS), PoC-04 ↔ CA-04 (IDOR).

### Relación PoC ↔ pipeline (inicio de la matriz de trazabilidad)

| PoC | Caso de abuso | ¿Lo detectó el pipeline? | Control |
|---|---|---|---|
| PoC-01 | CA-01 | *(Sí/No)* | *(regla Semgrep)* |
| PoC-02 | CA-02 | | |
| PoC-03 | CA-03 | | |
| PoC-04 | CA-04 | *(se espera No: lógica de negocio)* | |

## Registro de ataques

Una fila por intento. Solo cuentas de prueba y solo `localhost:8080`.

| Fecha | Hora | Quién | Herramienta | Método y ruta | Payload | Respuesta |
|---|---|---|---|---|---|---|
| | | | | | | |

---

*Uso de IA:* se usó Claude (Anthropic) para redactar la justificación del umbral a partir de la discusión del equipo. Revisado por el grupo.
