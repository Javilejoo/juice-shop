# Hallazgos de la revisión de las correcciones (FIX-01, FIX-02, FIX-03)

Revisión hecha por Bryan España el 2026-11-19 sobre el código que generó la IA, antes de pasarlo a la revisión cruzada de Javier. Sirve de insumo para la auditoría del README del hito.

| # | Hallazgo | Evidencia | Decisión |
|---|---|---|---|
| A-01 | La IA no agregó dependencias | `git diff origin/proyecto-final -- package.json package-lock.json` sin cambios | Nada que verificar en npmjs.com |
| A-02 | Sin secretos en el diff | Búsqueda de `secret`, `password`, `token`, `apikey`, `key =` en las líneas agregadas. Coincidencias: el nombre de columna `password` y `security.hash(...)` en el SQL, la palabra "token" en un comentario y el uso del token de una sesión de prueba, y `admin123`, que es la contraseña pública del usuario semilla de Juice Shop, ya usada en otras pruebas | Ninguna es una credencial real |
| A-03 | La solución "correcta" de referencia de Juice Shop para la búsqueda rompe la búsqueda legítima | `data/static/codefixes/unionSqlInjectionChallenge_2_correct.ts` usa `'%:criteria%'` dentro de comillas. Probado con Sequelize 6.37.8: buscar "apple" devuelve `[]`. La versión de la IA, con los `%` en el valor, devuelve "Apple Juice" | Se mantiene la versión de la IA |
| A-04 | `parseInt` es laxo: `parseInt('2abc', 10)` da 2 | La comprobación que ya existía en el código del reto usaba `parseInt` y `!=`. La IA agregó `/^\d+$/` y comparación estricta. Prueba de regresión "el id con texto agregado no engaña la comparación" | Aceptado |
| A-05 | FIX-03 también bloquea, en esta ruta, el acceso con un JWT falsificado sin firma (`alg: none`) | La prueba vieja "GET basket should accept forged JWTs" esperaba 200 y ahora da 403, porque ese token no está entre los usuarios autenticados | Efecto positivo, pero la falsificación de JWT sigue abierta en otras rutas: riesgo residual |
| A-06 | La IDOR sigue en el checkout | `POST /rest/basket/:id/checkout` no se tocó. En `basket.test.ts`, Jim hace checkout del carrito 1 del admin y recibe 200 | Fuera de alcance, riesgo residual |
| A-07 | 18 pruebas viejas esperaban que los ataques funcionaran | Invertidas: 5 en `login.test.ts`, 9 en `search.test.ts` y 4 en `basket.test.ts`. Todas quedan marcadas en su título con "(H4 FIX-0x)". La de productos del carrito se cambió para que la pida su dueño | Aceptado |
| A-08 | Una variante de regresión no fallaba antes de corregir | `q='` (comilla suelta) produce SQL válido incluso en el código vulnerable, así que la prueba pasaba sin demostrar nada. Se reemplazó por `q=';`, que sí falla antes | Corregido antes del commit de las pruebas |
| A-09 | Las correcciones no rompen nada más | Suite completa de API antes y después en la misma copia: 0 fallas nuevas. Las 28 fallas que quedan existen también en el código sin corregir y se deben al entorno de prueba (frontend sin compilar y sin acceso a internet) | Aceptado |
| A-10 | Se conservan los marcadores `// vuln-code-snippet` | `vuln-code-snippet.test.ts` y `vuln-code-fixes.test.ts` pasan completas | Aceptado |
| A-11 | El reto `basketAccessChallenge` ya no se puede resolver | El `solveIf` queda en el código pero nunca se cumple, porque el 403 corta antes | Esperado: el reto existía por la vulnerabilidad |

**Pendiente para la revisión de Javier:** Semgrep "después" sobre `routes/login.ts` y `routes/search.ts`, que debería quedar sin los dos ERROR, y la aprobación final.
