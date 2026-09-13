<template>
  <div v-loading="loading" class="code-viewer" :data-lang="language">
    <pre v-if="code"><code class="hljs" :class="'language-' + language" v-html="highlighted"></code></pre>
    <el-empty v-else description="暂无代码" :image-size="60" />
  </div>
</template>

<script setup>
import { computed } from 'vue'
import hljs from 'highlight.js/lib/core'
import c from 'highlight.js/lib/languages/c'

hljs.registerLanguage('c', c)
hljs.registerLanguage('fwasm', firmwareAsm)

const props = defineProps({
  code: { type: String, default: '' },
  loading: { type: Boolean, default: false },
  language: { type: String, default: 'c' }
})

function firmwareAsm () {
  const mnemonic =
    'lui addiu addu subu andi ori xori sll srl sra sllv srlv srav ' +
    'lw sw lh sh lb sb lbu lhu ll sc lwpc ' +
    'jal jalr jr j jalx b beq bne beqz bnez bgez blez bgtz bltz bal ' +
    'nop move li la mfhi mflo mthi mtlo mult multu div divu ' +
    'slt sltu slti sltiu syscall break teq tne ' +
    'bl blx bx b.w b.n cbz cbnz tbb tbh ' +
    'ldr str ldm stm ldmia stmia ldmfd stmfd push pop ' +
    'add sub rsb mul mla umull smull ' +
    'and orr eor bic mvn mov cmp cmn tst teq ' +
    'mrs msr svc swi cpsie cpsid ' +
    'beq bne bcs bcc bhs blo bmi bpl bvs bvc bhi bls bge blt bgt ble ' +
    'ret call jmp je jne ja jb jg jl jae jbe jge jle jo js jp ' +
    'push pop mov lea nop int syscall leave ' +
    'xor or not neg inc dec shl shr sar rol ror test cmp ' +
    'ldp stp adrp adr svc br blr cbnz tbz tbnz'
  const register =
    'zero at v0 v1 a0 a1 a2 a3 t0 t1 t2 t3 t4 t5 t6 t7 t8 t9 ' +
    's0 s1 s2 s3 s4 s5 s6 s7 k0 k1 gp sp fp ra hi lo pc lr ' +
    'r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 ' +
    'w0 w1 w2 w3 w4 w5 w6 w7 w8 w9 w10 w11 w12 w13 w14 w15 ' +
    'x0 x1 x2 x3 x4 x5 x6 x7 x8 x9 x10 x11 x12 x13 x14 x15 ' +
    'x16 x17 x18 x19 x20 x21 x22 x23 x24 x25 x26 x27 x28 x29 x30 xzr wzr ' +
    'eax ebx ecx edx esi edi ebp esp rax rbx rcx rdx rsi rdi rbp rsp ' +
    'rip eip ip cs ds es fs gs ss ' +
    'al ah ax bl bh bx cl ch cx dl dh dx sil dil bpl spl'
  return {
    name: 'Firmware assembly',
    case_insensitive: true,
    aliases: ['asm', 'fwasm'],
    keywords: {
      $pattern: '\\$?[A-Za-z_.$][A-Za-z0-9_.$]*',
      keyword: mnemonic,
      built_in: register
    },
    contains: [
      { className: 'comment', begin: '//', end: '$' },
      { className: 'comment', begin: '#', end: '$' },
      { className: 'comment', begin: ';', end: '$' },
      {
        className: 'symbol',
        begin: '^\\s*(?:0x)?[0-9a-fA-F]{4,}\\s*:'
      },
      {
        className: 'number',
        begin: '\\b0x[0-9a-fA-F]+\\b|#?-?\\d+\\b'
      },
      {
        className: 'built_in',
        begin: '\\$(?:zero|at|v[01]|a[0-3]|t[0-9]|s[0-8]|k[01]|gp|sp|fp|ra|\\d{1,2})\\b'
      }
    ]
  }
}

const highlighted = computed(() => {
  if (!props.code) return ''
  const lang = props.language === 'asm' ? 'fwasm' : 'c'
  try {
    return hljs.highlight(props.code, { language: lang, ignoreIllegals: true }).value
  } catch {
    return props.code.replace(/&/g, '&amp;').replace(/</g, '&lt;')
  }
})
</script>

<style scoped>
.code-viewer pre {
  margin: 0;
  background: #0f172a;
  border: 1px solid var(--fw-line);
  border-radius: 8px;
  padding: 14px 16px;
  overflow: auto;
  max-height: 72vh;
  font-size: 13.5px;
  line-height: 1.62;
  color: #e2e8f0;
}
.code-viewer code {
  font-family: 'JetBrains Mono', ui-monospace, Consolas, 'Courier New', monospace;
  font-weight: 500;
  color: #e2e8f0;
}
.code-viewer pre :deep(.hljs) {
  background: transparent;
  color: #e2e8f0;
}

/* 伪代码 */
.code-viewer :deep(.hljs-keyword),
.code-viewer :deep(.hljs-built_in),
.code-viewer :deep(.hljs-type) { color: #7dd3fc; font-weight: 600; }
.code-viewer :deep(.hljs-title),
.code-viewer :deep(.hljs-title.function_),
.code-viewer :deep(.hljs-function .hljs-title) { color: #f9a8d4; font-weight: 600; }
.code-viewer :deep(.hljs-string),
.code-viewer :deep(.hljs-meta .hljs-string) { color: #86efac; }
.code-viewer :deep(.hljs-number),
.code-viewer :deep(.hljs-literal) { color: #fdba74; }
.code-viewer :deep(.hljs-comment),
.code-viewer :deep(.hljs-quote) { color: #94a3b8; font-style: italic; }
.code-viewer :deep(.hljs-meta),
.code-viewer :deep(.hljs-meta .hljs-keyword) { color: #c4b5fd; }
.code-viewer :deep(.hljs-variable),
.code-viewer :deep(.hljs-params),
.code-viewer :deep(.hljs-attr) { color: #fde68a; }
.code-viewer :deep(.hljs-symbol),
.code-viewer :deep(.hljs-bullet) { color: #67e8f9; }
.code-viewer :deep(.hljs-operator),
.code-viewer :deep(.hljs-punctuation) { color: #cbd5e1; }
.code-viewer :deep(.hljs-subst) { color: #e8eef8; }

/* 汇编：地址 / 助记符 / 寄存器再提亮 */
.code-viewer[data-lang='asm'] :deep(.hljs-symbol) { color: #38bdf8; font-weight: 600; }
.code-viewer[data-lang='asm'] :deep(.hljs-keyword) { color: #f472b6; font-weight: 700; }
.code-viewer[data-lang='asm'] :deep(.hljs-built_in) { color: #34d399; font-weight: 600; }
.code-viewer[data-lang='asm'] :deep(.hljs-number) { color: #fbbf24; }
.code-viewer[data-lang='asm'] :deep(.hljs-comment) { color: #a5b4c8; font-style: italic; }
</style>
