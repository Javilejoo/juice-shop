/*
 * H4 · Prueba de regresión de FIX-03 (PoC-04, IDOR en GET /rest/basket/:id).
 * Jim (jim@juice-sh.op) es el usuario A y su carrito es el 2. El carrito 1 es del admin (usuario B).
 * Cada prueba describe el comportamiento SEGURO: falla sobre el código vulnerable y pasa con la corrección.
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'

let app: Express
let jimHeader: { Authorization: string }
let jimBid: number

before(
  async () => {
    const result = await createTestApp()
    app = result.app
    const { token, bid } = await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })
    jimHeader = { Authorization: 'Bearer ' + token }
    jimBid = bid
  },
  { timeout: 60000 }
)

void describe('FIX-03 · PoC-04 IDOR en GET /rest/basket/:id', () => {
  void it('el usuario A no puede leer el carrito del usuario B (403, sin datos)', async () => {
    const res = await request(app).get('/rest/basket/1').set(jimHeader)
    assert.equal(res.status, 403)
    assert.equal(res.body?.data, undefined)
  })

  void it('variante: un carrito que no existe también responde 403', async () => {
    const res = await request(app).get('/rest/basket/4711').set(jimHeader)
    assert.equal(res.status, 403)
  })

  void it('variante: el id con texto agregado no engaña la comparación', async () => {
    const res = await request(app).get('/rest/basket/1abc').set(jimHeader)
    assert.equal(res.status, 403)
  })

  void it('control: el usuario A sigue viendo su propio carrito (200)', async () => {
    const res = await request(app).get('/rest/basket/' + jimBid).set(jimHeader)
    assert.equal(res.status, 200)
    assert.equal(res.body.data.id, jimBid)
  })
})
