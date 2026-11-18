# Hito 2 · Pruebas de concepto del Equipo Rojo

> Alcance: únicamente la instancia local del equipo a través de `http://localhost:8080` (WAF en modo `DetectionOnly`). Las pruebas se realizaron con Burp Suite y un navegador configurado para pasar por el proxy.

## Resumen y trazabilidad

| PoC | Caso de abuso | Hallazgo | Endpoint o vector | Resultado observado | OWASP 2025 | CWE | CVSS v3.1 |
|---|---|---|---|---|---|---|---|
| PoC-01 | CA-01 / T-01 | SQLi en login | `POST /rest/user/login` | El payload emitió una autenticación con `umail: admin@juice-sh.op` | A05 Injection | CWE-89 | 9.1 Critical |
| PoC-02 | CA-02 / T-05 | SQLi en búsqueda | `GET /rest/products/search?q=` | La alteración de `q` devolvió el catálogo completo en vez de limitarse a la búsqueda | A05 Injection | CWE-89 | 7.5 High |
| PoC-03 | CA-03 / T-08 | DOM XSS en búsqueda | `/#/search?q=` | Se ejecutó `alert('xss')` en el navegador | A05 Injection | CWE-79 | 6.1 Medium |
| PoC-04 | CA-04 / T-11 | Acceso directo a objeto (IDOR) | `GET /rest/basket/:id` | La respuesta devolvió el carrito `id: 7` asociado a `UserId: 27` | A01 Broken Access Control | CWE-639 | 6.5 Medium |

## Reglas de evidencia

- Las horas se toman de la cabecera HTTP `Date` y se expresan en UTC.
- Los JWT de laboratorio que aparecen en las capturas **no se transcriben** aquí. Antes de compartir este documento fuera del equipo, deben redactarse de las imágenes.
- Una alerta del WAF o un HTTP 500 demuestra detección o error, pero no por sí sola una extracción de datos. La conclusión de cada PoC se limita a lo que muestran sus evidencias.

---

## PoC-01 · SQL injection en el login

**Caso de abuso:** CA-01 · **Amenaza:** T-01 · **Endpoint:** `POST /rest/user/login`.

### Procedimiento y resultado

Se configuró Burp Intruder en modo *Sniper* sobre los campos de inicio de sesión y se ensayó un conjunto reducido de entradas. El payload de SQLi del caso de abuso produjo una respuesta `200 OK` con un objeto `authentication`, incluyendo `umail: admin@juice-sh.op`. Esto confirma que un atacante no autenticado puede eludir el control de credenciales y obtener una sesión administrativa.

- **Hora observada:** `2026-11-17 01:01:10 GMT`.
- **Impacto demostrado:** suplantación de administrador y emisión de JWT.
- **Evidencia:** [configuración de Intruder](../img/h2-burp/burp-configuration.png) y [resultado de autenticación](../img/h2-burp/burp-intruder-result2.png).

### Clasificación

- **OWASP Top 10:2025:** A05 — Injection.
- **CWE:** CWE-89 — Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection').
- **CVSS v3.1:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` — **9.1 Critical**.

| Métrica | Valor | Justificación |
|---|---|---|
| AV | N | La solicitud se envía por HTTP. |
| AC | L | Basta enviar el valor controlado en el campo de email. |
| PR | N | No requiere sesión previa. |
| UI | N | No interviene otra víctima. |
| S | U | El impacto ocurre dentro de la misma aplicación. |
| C | H | La sesión administrativa permite acceder a información protegida. |
| I | H | La cuenta administrativa permite modificar recursos de la aplicación. |
| A | N | La PoC no degrada la disponibilidad. |

---

## PoC-02 · SQL injection en la búsqueda

**Caso de abuso:** CA-02 · **Amenaza:** T-05 · **Endpoint:** `GET /rest/products/search?q=`.

### Procedimiento y resultado

En Burp Repeater se sustituyó el valor de `q` por una entrada de terminación de consulta. La respuesta `200 OK` devolvió el catálogo completo de productos, en vez de un resultado restringido a un término de búsqueda. Este cambio de comportamiento confirma que `q` llega a la consulta SQL sin una parametrización adecuada.

- **Hora observada:** `2026-11-17 04:14:48 GMT`.
- **Impacto demostrado:** alteración de la consulta de búsqueda.
- **Límite de la evidencia:** la captura actual no incluye una respuesta que contenga emails o hashes de `Users`; por lo tanto, este informe no afirma que esa extracción se haya demostrado en esta ejecución.
- **Evidencia:** [petición y respuesta en Repeater](../img/h2-burp/burp-repeater-sqli1.png) y [respuesta guardada](../img/h2-burp/response.txt).

### Clasificación

- **OWASP Top 10:2025:** A05 — Injection.
- **CWE:** CWE-89 — Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection').
- **CVSS v3.1:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` — **7.5 High**.

| Métrica | Valor | Justificación |
|---|---|---|
| AV | N | El vector es un parámetro HTTP público. |
| AC | L | La modificación de un parámetro basta para alterar la consulta. |
| PR | N | La búsqueda no requiere autenticación. |
| UI | N | No depende de que otra persona actúe. |
| S | U | La base de datos pertenece a la misma autoridad de seguridad. |
| C | H | La vulnerabilidad permite construir consultas que pueden exponer datos de `Users`; la extracción concreta queda pendiente de una evidencia adicional. |
| I | N | Esta PoC fue de lectura y no modificó datos. |
| A | N | No se afectó la disponibilidad. |

---

## PoC-03 · DOM XSS en búsqueda

**Caso de abuso:** CA-03 · **Amenaza:** T-08 · **Vector:** parámetro `q` en la ruta Angular `/#/search`.

### Procedimiento y resultado

Se cargó la búsqueda con un payload HTML que crea un `iframe` cuyo origen JavaScript muestra `alert('xss')`. El navegador ejecutó la alerta y mostró el texto `xss`, por lo que el contenido controlado por el usuario alcanzó un *sink* HTML ejecutable.

- **Hora:** no quedó registrada en la captura; debe anotarse al repetir la prueba para la correlación del H3.
- **Impacto demostrado:** ejecución de JavaScript en el contexto de `localhost:8080`.
- **Nota WAF:** al ser un DOM XSS con el payload en el fragmento después de `#`, ese fragmento no viaja al servidor por HTTP. Por ello el WAF puede no registrar el payload aunque la ejecución esté confirmada en el navegador.
- **Evidencia:** [alerta XSS en la búsqueda](../img/h2-burp/poc-xss-search.png).

### Clasificación

- **OWASP Top 10:2025:** A05 — Injection.
- **CWE:** CWE-79 — Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting').
- **CVSS v3.1:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` — **6.1 Medium**.

| Métrica | Valor | Justificación |
|---|---|---|
| AV | N | El payload llega mediante una URL abierta en el navegador. |
| AC | L | Solo requiere formar la URL o escribir el valor en la búsqueda. |
| PR | N | No requiere una cuenta para la prueba mostrada. |
| UI | R | Una víctima debe abrir la URL o visualizar el contenido. |
| S | C | El script se ejecuta en el contexto del navegador de la víctima. |
| C | L | Puede acceder a información expuesta a la sesión de la víctima. |
| I | L | Puede modificar la interfaz o realizar acciones como la víctima. |
| A | N | La PoC no afecta disponibilidad. |

---

## PoC-04 · IDOR en el carrito

**Caso de abuso:** CA-04 · **Amenaza:** T-11 · **Endpoint:** `GET /rest/basket/:id`.

### Procedimiento y resultado

Desde Burp Repeater se capturó una petición autenticada a un carrito y se cambió únicamente el identificador de la ruta. La respuesta fue `200 OK` y devolvió el objeto del carrito `id: 7`, asociado a `UserId: 27`, además de su producto e información de compra. La ruta consulta el carrito por el identificador recibido sin imponer en esa operación la pertenencia del objeto al usuario autenticado.

- **Hora observada:** `2026-11-17 05:34:18 GMT`.
- **Impacto demostrado:** exposición de los datos de un carrito identificado por un ID modificable.
- **Limitación de la captura:** para una demostración concluyente en la presentación, acompañar la repetición con el `bid` propio y el `bid` ajeno visibles —sin revelar JWT— para probar que el token no pertenece a `UserId: 27`.
- **Evidencia:** [petición original modificable](../img/h2-burp/broken-access1.png), [respuesta del carrito ajeno](../img/h2-burp/broken-access2.png) y [respuesta guardada](../img/h2-burp/response-broken-access.txt).

### Clasificación

- **OWASP Top 10:2025:** A01 — Broken Access Control.
- **CWE:** CWE-639 — Authorization Bypass Through User-Controlled Key.
- **CVSS v3.1:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` — **6.5 Medium**.

| Métrica | Valor | Justificación |
|---|---|---|
| AV | N | Se invoca mediante una petición HTTP. |
| AC | L | Solo se sustituye el ID en la ruta. |
| PR | L | Requiere una cuenta autenticada. |
| UI | N | No requiere interacción de otra persona. |
| S | U | El acceso indebido ocurre dentro de Juice Shop. |
| C | H | Expone contenido y metadatos de compras de otro usuario. |
| I | N | Esta PoC solo leyó información. |
| A | N | Esta PoC no afectó disponibilidad. |

---

## Cobertura y trabajo pendiente

Las cuatro PoC cubren los casos de abuso priorizados del H1. Para cerrar el H2 aún se debe:

1. Exportar y añadir el reporte del Spider y Active Scan de ZAP.
2. Repetir PoC-03 con hora UTC registrada.
3. Repetir PoC-04 mostrando el `bid` de ambas cuentas de prueba y ocultando el JWT.
4. Repetir las PoC seleccionadas desde Postman contra la instancia de Javier, registrar las horas y entregarlas al Blue Team para la correlación en Kibana.

## Referencias

- [OWASP Top 10:2025](https://top10.owasp.org/2025/0x00_2025-Introduction/)
- [FIRST CVSS v3.1](https://www.first.org/cvss/v3-1/specification-document)
- [CWE-89](https://cwe.mitre.org/data/definitions/89.html), [CWE-79](https://cwe.mitre.org/data/definitions/79.html) y [CWE-639](https://cwe.mitre.org/data/definitions/639.html)
