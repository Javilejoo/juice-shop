/*
 * H4 · Pruebas de regresión de FIX-01 (PoC-01, SQLi en el login) y FIX-02 (PoC-02, SQLi en la búsqueda).
 * Cada prueba describe el comportamiento SEGURO: falla sobre el código vulnerable y pasa con la corrección.
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'

let app: Express

before(
  async () => {
    const result = await createTestApp()
    app = result.app
  },
  { timeout: 60000 }
)

void describe('FIX-01 · PoC-01 SQLi en POST /rest/user/login', () => {
  void it('el payload del PoC-01 en el email no inicia sesión (401, sin token)', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set('content-type', 'application/json')
      .send({ email: "' OR 1=1--", password: 'cualquiera' })
    assert.equal(res.status, 401)
    assert.equal(res.body?.authentication, undefined)
  })

  void it('variante: comentar la contraseña con un email conocido no inicia sesión', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set('content-type', 'application/json')
      .send({ email: "admin@juice-sh.op'--", password: 'cualquiera' })
    assert.equal(res.status, 401)
    assert.equal(res.body?.authentication, undefined)
  })

  void it('control: el login legítimo sigue funcionando (200 con token)', async () => {
    const res = await request(app)
      .post('/rest/user/login')
      .set('content-type', 'application/json')
      .send({ email: 'jim@juice-sh.op', password: 'ncc-1701' })
    assert.equal(res.status, 200)
    assert.ok(res.body.authentication.token)
  })
})

void describe('FIX-02 · PoC-02 SQLi en GET /rest/products/search', () => {
  void it("el payload del PoC-02 q='))-- se trata como texto y no devuelve productos", async () => {
    const res = await request(app).get("/rest/products/search?q='))--")
    assert.equal(res.status, 200)
    assert.deepEqual(res.body.data, [])
  })

  void it('variante: UNION SELECT contra Users no filtra correos ni hashes', async () => {
    const payload = "qwert')) UNION SELECT id, email, password, '4', '5', '6', '7', '8', '9' FROM Users--"
    const res = await request(app).get('/rest/products/search?q=' + encodeURIComponent(payload))
    assert.equal(res.status, 200)
    assert.deepEqual(res.body.data, [])
    assert.ok(!JSON.stringify(res.body).includes('admin@juice-sh.op'))
  })

  void it("variante: q='; no rompe la consulta ni expone el error de SQLite", async () => {
    const res = await request(app).get("/rest/products/search?q=';")
    assert.equal(res.status, 200)
    assert.ok(!res.text.includes('SQLITE_ERROR'))
  })

  void it('control: la búsqueda legítima sigue funcionando', async () => {
    const res = await request(app).get('/rest/products/search?q=apple')
    assert.equal(res.status, 200)
    assert.ok(res.body.data.length > 0)
    assert.ok(res.body.data.every((p: { name: string, description: string }) => (p.name + p.description).toLowerCase().includes('apple')))
  })
})
