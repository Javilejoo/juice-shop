# Uso de IA · FIX-03 (IDOR en el carrito)

| | |
|---|---|
| **Herramienta** | Claude (Anthropic), app de Claude con acceso a la copia de trabajo del repositorio |
| **Modelo** | Claude Opus 5.5 |
| **Fecha** | 2026-11-19, hora de Guatemala |
| **Quién lo usó** | Bryan España. El texto del prompt lo revisó y aprobó Javier Prado antes de usarlo |
| **Rama** | `h4-remediacion` |

## Prompt (tal como se envió)

> En `routes/basket.ts` de OWASP Juice Shop, `retrieveBasket()` devuelve cualquier carrito por su id sin comprobar el dueño (IDOR). Corrígelo para que solo devuelva el carrito si pertenece al usuario autenticado (`security.authenticatedUsers.from(req)`, campo `bid`); si no, responde 403 sin consultar ni devolver el carrito. El control va en el servidor. No agregues dependencias nuevas, no cambies el comportamiento para el dueño del carrito y explica cada cambio.

## Respuesta de la IA

El problema es que `retrieveBasket()` busca el carrito solo con el número de la URL. La ruta exige estar logueado, pero estar logueado no es lo mismo que ser el dueño, así que cualquier usuario puede leer el carrito de otro cambiando el número (CWE-639, OWASP A01). La corrección agrega la comprobación del dueño **antes** de consultar la base:

```ts
const id = req.params.id
// H4 FIX-03: solo el dueño puede leer su carrito. El id debe ser un número entero
// y coincidir con el carrito (bid) del usuario del token; si no, 403 sin consultar.
const user = security.authenticatedUsers.from(req)
if (!user?.bid || !/^\d+$/.test(String(id)) || user.bid !== parseInt(String(id), 10)) {
  res.status(403).json({ status: 'error', error: 'Forbidden' })
  return
}
const basket = await BasketModel.findOne({ where: { id }, include: [{ model: ProductModel, paranoid: false, as: 'Products' }] })
```

- `security.authenticatedUsers.from(req)` toma el token de la petición y devuelve el usuario que inició sesión con él. En el login se guarda como `{ data: usuario, bid: id del carrito }`, por eso se compara `user.bid` y no `user.data.bid`.
- Si no hay usuario registrado para ese token, la petición se rechaza. Esto cubre también un token falsificado que pasó la validación del JWT pero que nunca se emitió desde el login.
- `/^\d+$/` exige que el id sea solo dígitos. Sin esto, `parseInt('2abc', 10)` devuelve 2 y un id con texto agregado pasaría la comparación aunque la consulta use el texto completo.
- La comparación es estricta (`!==`) entre números, en lugar del `!=` que usaba el código del reto.
- El 403 se responde antes de `findOne`, así que no se consulta ni se devuelve nada del carrito ajeno. Tampoco se distingue entre "carrito ajeno" y "carrito inexistente", y así no se filtra qué ids existen.
- Para el dueño no cambia nada: la consulta, la traducción de nombres de productos y la respuesta siguen iguales.
- El control está en el servidor. No se toca el frontend.

**Dependencias:** ninguna.

**Efectos a revisar:**
- El bloque `challengeUtils.solveIf(challenges.basketAccessChallenge, ...)` queda, pero ya no puede cumplirse porque las peticiones a carritos ajenos se cortan antes. Es lo esperado: el reto existía porque la vulnerabilidad existía.
- Las pruebas de `test/api/basket.test.ts` que piden un carrito ajeno, uno inexistente o usan un JWT falsificado y esperan 200 dejarán de pasar y hay que invertirlas.
- `POST /rest/basket/:id/checkout` también recibe el id por la URL y no se cambió.

## Revisión y cambios del grupo

- Se invirtieron 4 pruebas de `basket.test.ts`. La que comprobaba que un carrito devuelve sus productos se cambió para que la pida su dueño, el admin, y así siga probando el caso legítimo en lugar de solo esperar un 403.
- Se verificó que no hay dependencias nuevas ni secretos en el diff.
- Se confirmó que el checkout sigue aceptando el carrito de otro usuario: en `basket.test.ts`, Jim hace checkout del carrito 1 del admin y recibe 200. Queda como riesgo residual (hallazgo A-06 en la auditoría).
- Resultado: las 4 pruebas de regresión de FIX-03 pasan, incluido el control de que Jim sigue viendo su propio carrito, y `basket.test.ts` pasa completa.
