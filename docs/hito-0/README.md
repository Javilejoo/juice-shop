# Hito 0 · Arranque — OWASP Juice Shop

Proyecto Final Integrador · Desarrollo Seguro · UVG · Ciclo 2 2026

## Aplicación objetivo
| Dato | Valor |
| --- | --- |
| Aplicación | OWASP Juice Shop (fork público del grupo) |
| Repositorio | https://github.com/Javilejoo/juice-shop — rama `proyecto-final`, topic `proyecto-final` |
| Ejecución | Servicio `juice-shop` en `waf-siem/docker-compose.yml` (Opción B, sin puerto publicado) |
| A través del WAF | http://localhost:8080 |
| Cuentas | Solo cuentas de prueba de Juice Shop |

## Roles
> El enunciado pide grupos de 4 (2 Red / 2 Blue). Este grupo es de **3 integrantes**. Aprobado por el docente: ☐ sí ☐ pendiente

| Integrante | Rol | Equipo | Responsabilidades |
| --- | --- | --- | --- |
| Javier | Blue Team (líder del repo) | Mac | Repo, entorno, H3: reglas Kibana, dashboard, WAF en On, falsos positivos |
| Bryan | Blue Team | Mac | H1: control por requisito · H2: umbral del gate · H3: reglas y exclusiones |
| Luispe | Red Team | Windows | H1: reconocimiento · H2: ZAP + Burp por `:8080`, ≥3 PoC clasificados · H3/H4: repetir PoC |
| Los 3 | Todo el grupo | — | Pipeline DevSecOps, remediación con IA, informe, presentación |

## Arquitectura
```
Navegador / Postman / ZAP / Burp ──► WAF :8080 (ModSecurity + OWASP CRS) ──► juice-shop:3000 (red interna de Docker)
                                         │ access.log / modsec_audit.json
                                         ▼
                                     Filebeat ──► Elasticsearch :9200 ──► Kibana :5601
```

## Estado del entorno por integrante
| Integrante | Equipo | Juice Shop + WAF | SIEM | Fecha |
| --- | --- | --- | --- | --- |
| Javier | Mac | ☐ | ☐ | |
| Bryan | Mac | ☑ | ☑ | 2026-11-10 |
| Luispe | Windows | ☐ | n/a | |

## Evidencias (`docs/hito-0/img/`)
- [x] `01-docker-compose-ps.png` (Bryan)
- [ ] `02-postman-health-waf.png`
- [ ] `03-postman-login.png`
- [x] `04-kibana-discover.png` (Bryan)
- [x] `05-kibana-documento-modsec.png` (Bryan)

## Verificación de bypass
| Prueba | Resultado esperado | Resultado obtenido |
| --- | --- | --- |
| `http://localhost:3000` (directo a Juice Shop) | No responde (Opción B) | Bryan, 2026-11-10: no responde. `docker compose ps` muestra `3000/tcp` sin puerto publicado al host (ver `img/01-docker-compose-ps.png`). Por `:8080` responde HTTP 200 |

## Modo del WAF
`MODSEC_RULE_ENGINE=DetectionOnly` (H0–H2). Pasa a `On` en el H3.

## Checklist H0
- [ ] Roles escritos
- [ ] Topic `proyecto-final` en el repositorio
- [ ] Workflows originales de Juice Shop desactivados/eliminados
- [ ] Juice Shop responde por `:8080`
- [ ] Eventos del WAF en Kibana
- [x] Bypass verificado y anotado

### Evidencia de Bryan (2026-11-10)
- `verificar.sh todo`: Elasticsearch, Kibana, WAF (HTTP 200) y Filebeat en OK; data stream `.ds-filebeat-9.3.3-2026.11.10-000001`.
- Prueba del CRS a las 16:20:32 (hora local): `GET /rest/products/search?q=' OR 1=1--` → el WAF en DetectionOnly la registra con una regla de `REQUEST-942-APPLICATION-ATTACK-SQLI` (`fields.fuente : "waf-audit"`, ver `img/04` y `img/05`) y la deja pasar (HTTP 500 de la app).
- Nota: Filebeat 9 no lee un archivo hasta que pasa de 1024 bytes; con poco tráfico `verificar.sh filebeat` falla aunque todo esté bien. Ajuste propuesto: `prospector.scanner.fingerprint.length: 64` en los inputs de `waf-siem/filebeat.yml`.
