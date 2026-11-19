# Uso de IA · FIX-01 y FIX-02 (inyección SQL en login y búsqueda)

| | |
|---|---|
| **Herramienta** | Claude (Anthropic), app de Claude con acceso a la copia de trabajo del repositorio |
| **Modelo** | Claude Opus 5.5 |
| **Fecha** | 2026-11-19, hora de Guatemala |
| **Quién lo usó** | Bryan España. El texto del prompt lo revisó y aprobó Javier Prado antes de usarlo |
| **Rama** | `h4-remediacion` |

## Prompt (tal como se envió)

> En OWASP Juice Shop hay dos inyecciones SQL. En `routes/login.ts` línea 34, el email se concatena dentro de `models.sequelize.query`. En `routes/search.ts` línea 23, el parámetro `q` se concatena dentro del `LIKE`. Corrígelas con consultas parametrizadas de Sequelize: `bind` en el login y `replacements` en la búsqueda. No agregues dependencias nuevas, no cambies el comportamiento para usuarios legítimos, no borres los comentarios `// vuln-code-snippet` y explica cada cambio.

## Respuesta de la IA

**FIX-01, `routes/login.ts` línea 34.** Antes, el email y el hash de la contraseña se pegaban dentro del texto SQL con `${...}`. Con `' OR 1=1--` en el email, la condición quedaba siempre verdadera y el resto se comentaba, así que la base devolvía el primer usuario (el admin) sin validar la contraseña. Ahora la consulta usa marcadores posicionales `$1` y `$2`, y los valores viajan aparte en `bind`. SQLite los recibe como datos, nunca como parte del SQL, así que una comilla en el email es solo un carácter más del correo que se busca.

```ts
models.sequelize.query('SELECT * FROM Users WHERE email = $1 AND password = $2 AND deletedAt IS NULL', { bind: [String(req.body.email ?? ''), security.hash(req.body.password || '')], model: UserModel, plain: true }) // vuln-code-snippet vuln-line loginAdminChallenge loginBenderChallenge loginJimChallenge
```

- La plantilla pasa a ser una cadena fija con comillas simples: ya no hay ninguna interpolación posible.
- `String(req.body.email ?? '')` asegura que se envíe texto aunque el cliente mande un número, un arreglo o nada. Antes `|| ''` cubría el caso vacío; `??` lo mantiene y `String()` evita que un objeto JSON llegue tal cual al driver.
- La contraseña se sigue hasheando igual que antes, así que el login legítimo no cambia.
- El comentario `// vuln-code-snippet` se conserva en la misma línea porque las pruebas de los retos de código lo leen.

**FIX-02, `routes/search.ts` línea 23.** Antes, `criteria` se pegaba dos veces dentro de `LIKE '%...%'`. Con `'))--` se cerraban los paréntesis y se comentaba `deletedAt IS NULL`, y con `UNION SELECT` se podía leer la tabla Users. Ahora se usa un marcador con nombre `:pattern` y el valor va en `replacements`.

```ts
models.sequelize.query('SELECT * FROM Products WHERE ((name LIKE :pattern OR description LIKE :pattern) AND deletedAt IS NULL) ORDER BY name', { replacements: { pattern: `%${String(criteria)}%` } }) // vuln-code-snippet vuln-line unionSqlInjectionChallenge dbSchemaChallenge
```

- Los comodines `%` se agregan al valor y no al SQL. Si se escribieran como `'%:criteria%'` dentro de comillas, Sequelize no reemplaza el marcador y la búsqueda deja de encontrar productos.
- Sequelize escapa el valor de `replacements` como texto, así que `'))--` o un `UNION SELECT` se buscan literalmente en el nombre y la descripción y no devuelven nada.
- Se usa un solo marcador para las dos columnas; Sequelize lo reemplaza en ambos lugares.
- `String(criteria)` evita que un `q` repetido en la URL, que Express convierte en arreglo, se expanda como lista.
- El límite de 200 caracteres y el resto de la función no cambian.

**Dependencias:** ninguna. `bind` y `replacements` son parte de Sequelize, que ya está en el proyecto.

**Pruebas que van a cambiar:** las de `test/api/login.test.ts` y `test/api/search.test.ts` que esperan que la inyección funcione dejarán de pasar y hay que invertirlas para que esperen el comportamiento seguro.

## Revisión y cambios del grupo

- Se comparó con las soluciones de referencia de Juice Shop. El login coincide con `data/static/codefixes/loginJimChallenge_1_correct.ts`. La búsqueda **difiere a propósito** de `unionSqlInjectionChallenge_2_correct.ts`: la referencia escribe `'%:criteria%'` dentro de comillas y, probado con la misma versión de Sequelize del proyecto (6.37.8), una búsqueda legítima de "apple" devuelve cero productos. La versión de la IA sí devuelve "Apple Juice". Ver hallazgo A-03 en la auditoría.
- Se verificó que el diff no agrega dependencias (`package.json` sin cambios) ni secretos.
- Se invirtieron 5 pruebas de `login.test.ts` y 9 de `search.test.ts` que esperaban que el ataque funcionara, y se quitó un import que quedó sin uso. La lista está en la auditoría.
- Resultado: las pruebas de regresión de FIX-01 y FIX-02 pasan, y `login.test.ts`, `search.test.ts`, `vuln-code-snippet.test.ts` y `vuln-code-fixes.test.ts` pasan completas.
