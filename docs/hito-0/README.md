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
| Bryan | Mac | ☐ | ☐ | |
| Luispe | Windows | ☐ | n/a | |

## Evidencias (`docs/hito-0/img/`)
- [ ] `01-docker-compose-ps.png`
- [ ] `02-postman-health-waf.png`
- [ ] `03-postman-login.png`
- [ ] `04-kibana-discover.png`
- [ ] `05-kibana-documento-modsec.png`

## Verificación de bypass
| Prueba | Resultado esperado | Resultado obtenido |
| --- | --- | --- |
| `http://localhost:3000` (directo a Juice Shop) | No responde (Opción B) | |

## Modo del WAF
`MODSEC_RULE_ENGINE=DetectionOnly` (H0–H2). Pasa a `On` en el H3.

## Checklist H0
- [ ] Roles escritos
- [ ] Topic `proyecto-final` en el repositorio
- [ ] Workflows originales de Juice Shop desactivados/eliminados
- [ ] Juice Shop responde por `:8080`
- [ ] Eventos del WAF en Kibana
- [ ] Bypass verificado y anotado
