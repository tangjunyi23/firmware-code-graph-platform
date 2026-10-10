const fs = require('node:fs')
const vm = require('node:vm')
const assert = require('node:assert/strict')
const test = require('node:test')
const source = fs.readFileSync('src/workbench/dshClient.js', 'utf8')
function deferred() { let resolve; const promise = new Promise(r => { resolve = r }); return { promise, resolve } }
async function harness(api, streamSse = async () => {}) {
  const ctx = vm.createContext({
    console, Date, Math, Map, Set, JSON, String, Number, Object, Array, RegExp, Intl,
    AbortController, setTimeout, clearTimeout, setInterval, clearInterval,
    requestAnimationFrame: fn => setTimeout(() => fn(performance.now()), 1),
    cancelAnimationFrame: clearTimeout, performance,
    localStorage: { getItem: () => null, setItem: () => {} },
    document: { hidden: false }, navigator: {},
  })
  const modules = {
    vue: { reactive: x => x, computed: fn => ({ get value() { return fn() } }), markRaw: x => x },
    '../api.js': { api, streamSse },
    '../highlight.js': { highlightText: x => x },
  }
  const module = new vm.SourceTextModule(source, { context: ctx })
  await module.link(name => {
    const exports = modules[name]
    return new vm.SyntheticModule(Object.keys(exports), function() {
      for (const [key, value] of Object.entries(exports)) this.setExport(key, value)
    }, { context: ctx })
  })
  await module.evaluate()
  return module.namespace.createDshSession()
}
const summary = sid => ({ session_id: sid, status: 'done', turns: 3, findings: [], finding_objects: [] })
const history = text => ({ events: [{ event: { type: 'user/message', seq: 1, data: { text } } }], hasMore: false })
test('late summary from A cannot overwrite selected session B', async () => {
  const gate = deferred()
  const s = await harness(path => path.endsWith('/A') ? gate.promise : Promise.resolve(path.includes('/rpc/') ? history('B history') : summary('B')))
  const a = s.attach('A'); await s.attach('B'); gate.resolve({ ...summary('A'), turns: 99 }); await a
  assert.equal(s.state.sid, 'B'); assert.equal(s.state.turns, 3); assert.deepEqual(Array.from(s.state.nodes, n => n.text), ['B history']); s.detach()
})
test('late history from A cannot merge into B even after A summary loaded', async () => {
  const gate = deferred(); let requested
  const ready = new Promise(r => { requested = r })
  const s = await harness(path => {
    if (path.includes('/A/rpc/')) { requested(); return gate.promise }
    return Promise.resolve(path.includes('/rpc/') ? history('B history') : summary(path.endsWith('/A') ? 'A' : 'B'))
  })
  const a = s.attach('A'); await ready; await s.attach('B'); gate.resolve(history('A history')); await a
  assert.deepEqual(Array.from(s.state.nodes, n => n.text), ['B history']); s.detach()
})
test('resuming a finished session opens its live event subscription', async () => {
  const streams = []
  const s = await harness(path => Promise.resolve(path.endsWith('/resume') ? { status: 'running', turns: 4, max_turns: 80 } : path.includes('/rpc/') ? history('old') : summary('A')),
    (path, { signal }) => { streams.push(path); return new Promise(resolve => signal.addEventListener('abort', resolve, { once: true })) })
  await s.attach('A'); await s.resumeHunt('continue'); assert.ok(streams[0].endsWith('/A/mux')); assert.equal(s.state.running, true); s.detach()
})
test('failed optimistic message is removed while confirmed messages remain', async () => {
  const s = await harness(async () => ({}))
  const pending = s.pushLocalUser('failed'); s.removeLocalUser(pending); assert.equal(s.state.nodes.length, 0)
  const confirmed = s.pushLocalUser('accepted'); s.foldEvent({ type: 'user/message', seq: 1, data: { text: 'accepted' } }); s.removeLocalUser(confirmed)
  assert.equal(s.state.nodes.length, 1); assert.equal(s.state.nodes[0].text, 'accepted'); s.detach()
})
