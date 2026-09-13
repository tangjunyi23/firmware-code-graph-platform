/**
 * Repair DeepSeek / OpenAI-compat tool-call streams that send a first
 * delta with id+name and a later delta with id="" / name=null.
 *
 * BlockAssembler treats block-end as authoritative, so an empty close
 * overwrites the good name and the agent executes unknown tool "".
 */

function nonempty(value) {
  return typeof value === 'string' && value.length > 0 ? value : ''
}

/** Fold one chunk. `seen` is index -> {id, name} for this LLM request. */
export function sanitizeChunk(chunk, seen) {
  if (!chunk || typeof chunk !== 'object') return chunk
  if (chunk.type === 'tool-call-delta') {
    const prev = seen.get(chunk.index) || { id: '', name: '' }
    const id = nonempty(chunk.id) || prev.id
    const name = nonempty(chunk.name) || prev.name
    if (id || name) seen.set(chunk.index, { id, name })
    const out = { ...chunk, id }
    if (name) out.name = name
    else delete out.name
    return out
  }
  if (chunk.type === 'block-end' && chunk.block && chunk.block.type === 'tool-call') {
    const prev = seen.get(chunk.index) || { id: '', name: '' }
    const id = nonempty(chunk.block.id) || prev.id
    const name = nonempty(chunk.block.name) || prev.name
    if (id || name) seen.set(chunk.index, { id, name })
    return { ...chunk, block: { ...chunk.block, id, name } }
  }
  return chunk
}

/** Async iterable wrapper used on the llm/stream waterfall. */
export function sanitizeToolStream(iter) {
  const seen = new Map()
  return (async function* () {
    for await (const chunk of iter) {
      yield sanitizeChunk(chunk, seen)
    }
  })()
}
