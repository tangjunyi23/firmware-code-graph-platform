/**
 * Repair empty tool-call names that the DeepSeek / OpenAI-compat gateway
 * emits on later argument-only deltas (id="" / name=null).
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { sanitizeChunk, sanitizeToolStream } from '../dsh/plugin-events/src/sanitize.js'

test('keeps id+name when a later delta sends empty id and null name', () => {
  const seen = new Map()
  const first = sanitizeChunk({
    type: 'tool-call-delta', index: 1,
    id: 'call_f4fe0215128f4457bff01544', name: 'fw_get_identification',
    argumentsDelta: '',
  }, seen)
  const second = sanitizeChunk({
    type: 'tool-call-delta', index: 1,
    id: '', name: null, argumentsDelta: '{}',
  }, seen)
  const end = sanitizeChunk({
    type: 'block-end', index: 1,
    block: { type: 'tool-call', id: '', name: '', arguments: '{}' },
  }, seen)
  assert.equal(first.name, 'fw_get_identification')
  assert.equal(second.id, 'call_f4fe0215128f4457bff01544')
  assert.equal(second.name, 'fw_get_identification')
  assert.equal(second.argumentsDelta, '{}')
  assert.equal(end.block.id, 'call_f4fe0215128f4457bff01544')
  assert.equal(end.block.name, 'fw_get_identification')
})

test('does not mix parallel tool calls', () => {
  const seen = new Map()
  sanitizeChunk({
    type: 'tool-call-delta', index: 1,
    id: 'a', name: 'fw_get_identification', argumentsDelta: '',
  }, seen)
  sanitizeChunk({
    type: 'tool-call-delta', index: 2,
    id: 'b', name: 'fw_list_surfaces', argumentsDelta: '',
  }, seen)
  const a = sanitizeChunk({
    type: 'block-end', index: 1,
    block: { type: 'tool-call', id: '', name: '', arguments: '{}' },
  }, seen)
  const b = sanitizeChunk({
    type: 'block-end', index: 2,
    block: { type: 'tool-call', id: '', name: '', arguments: '{}' },
  }, seen)
  assert.equal(a.block.name, 'fw_get_identification')
  assert.equal(b.block.name, 'fw_list_surfaces')
})

test('sanitizeToolStream yields repaired block-end', async () => {
  async function* src() {
    yield { type: 'block-start', index: 0, blockType: 'tool-call' }
    yield {
      type: 'tool-call-delta', index: 0,
      id: 'call_x', name: 'fw_list_binaries', argumentsDelta: '',
    }
    yield {
      type: 'tool-call-delta', index: 0,
      id: '', name: null, argumentsDelta: '{}',
    }
    yield {
      type: 'block-end', index: 0,
      block: { type: 'tool-call', id: '', name: '', arguments: '{}' },
    }
  }
  const out = []
  for await (const chunk of sanitizeToolStream(src())) out.push(chunk)
  const end = out.at(-1)
  assert.equal(end.block.name, 'fw_list_binaries')
  assert.equal(end.block.id, 'call_x')
})
