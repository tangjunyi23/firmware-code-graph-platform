/*
 * fwgraph generic function-level fuzz hook for AFL++ QEMU persistent mode.
 *
 * One host .so per guest arch, fully driven by env vars — no per-target
 * recompilation:
 *
 *   FUZZHOOK_ARCH        (compile-time via -D__FWHOOK_*__)
 *   FUZZHOOK_ARGS        positional arg spec, comma separated:
 *                          buf      -> arg register = pointer to input buffer
 *                          len      -> arg register = input length
 *                          const:N  -> arg register = constant N (dec/0x..)
 *                          none     -> leave register untouched
 *      (register order: arm r0-r3, arm64 x0-x7, mips a0-a3,
 *       x86_64 rdi,rsi,rdx,rcx,r8,r9)
 *   FUZZHOOK_RET_VALUE   sentinel written to the link register (lr/ra/x30);
 *                        must equal AFL_QEMU_PERSISTENT_RET
 *
 * The input buffer lives on the guest stack: the hook moves SP down by
 * STACK_ZONE and places the input there — no ELF layout math, and only the
 * target function executes (AFL_ENTRYPOINT + PERSISTENT_ADDR jump straight
 * to it); the firmware is never "fully emulated".
 */

#include <qemuafl/api.h>   /* -I <AFLplusplus>/qemu_mode/qemuafl */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define g2h(x) ((void *)((unsigned long)(x) + guest_base))
#define h2g(x) ((uint64_t)(x) - guest_base)

#define MAX_ARGS 8
#define STACK_ZONE 0x2000
#define MAX_INPUT 4096

static char g_argspec[256];
static uint64_t g_ret;
static int g_inited = 0;

static uint64_t parse_num(const char *s) { return strtoull(s, NULL, 0); }

static void lazy_init(void) {
  if (g_inited) return;
  const char *spec = getenv("FUZZHOOK_ARGS");
  const char *ret = getenv("FUZZHOOK_RET_VALUE");
  snprintf(g_argspec, sizeof(g_argspec), "%s", spec ? spec : "buf,len");
  g_ret = ret ? parse_num(ret) : 0;
  g_inited = 1;
}

static uint64_t arg_value(const char *tok, uint64_t buf_addr,
                          uint64_t buflen) {
  if (!strcmp(tok, "buf")) return buf_addr;
  if (!strcmp(tok, "len")) return buflen;
  if (!strncmp(tok, "const:", 6)) return parse_num(tok + 6);
  return ~0ULL;  /* "none" or unknown: leave register untouched */
}

#define APPLY_ARGS(assign)                                             \
  {                                                                    \
    char spec[sizeof(g_argspec)];                                      \
    memcpy(spec, g_argspec, sizeof(g_argspec));                        \
    char *save = NULL;                                                 \
    char *tok = strtok_r(spec, ",", &save);                            \
    int i = 0;                                                         \
    while (tok && i < MAX_ARGS) {                                      \
      uint64_t v = arg_value(tok, buf_addr, buflen);                   \
      if (v != ~0ULL) { assign; }                                      \
      i++;                                                             \
      tok = strtok_r(NULL, ",", &save);                                \
    }                                                                  \
  }

#define PLACE_INPUT(sp_expr)                                           \
  uint64_t new_sp = ((sp_expr) - STACK_ZONE) & ~0xFULL;                \
  uint64_t buf_addr = new_sp;                                          \
  if (buflen > MAX_INPUT) buflen = MAX_INPUT;                          \
  memcpy(g2h(buf_addr), input_buf, buflen);                            \
  (sp_expr) = new_sp;

#if defined(__FWHOOK_ARM__)
void afl_persistent_hook(struct arm_regs *regs, uint64_t guest_base,
                         uint8_t *input_buf, uint32_t input_buf_len) {
  lazy_init();
  uint64_t buflen = input_buf_len;
  PLACE_INPUT(regs->sp);
  uint32_t *argregs = &regs->r0;
  APPLY_ARGS({ if (i < 4) argregs[i] = (uint32_t)v; });
  if (g_ret) regs->lr = (uint32_t)g_ret;
}

#elif defined(__FWHOOK_ARM64__)
void afl_persistent_hook(struct arm64_regs *regs, uint64_t guest_base,
                         uint8_t *input_buf, uint32_t input_buf_len) {
  lazy_init();
  uint64_t buflen = input_buf_len;
  PLACE_INPUT(regs->sp);
  uint64_t *argregs = &regs->x0;
  APPLY_ARGS({ if (i < 8) argregs[i] = v; });
  if (g_ret) regs->x30 = g_ret;
}

#elif defined(__FWHOOK_MIPS__)
void afl_persistent_hook(struct mips_regs *regs, uint64_t guest_base,
                         uint8_t *input_buf, uint32_t input_buf_len) {
  lazy_init();
  uint64_t buflen = input_buf_len;
  PLACE_INPUT(regs->sp);
  uint64_t *argregs = &regs->a0;
  APPLY_ARGS({ if (i < 4) argregs[i] = v; });
  if (g_ret) regs->ra = g_ret;
}

#else  /* x86_64 — for host-side harness validation */
void afl_persistent_hook(struct x86_64_regs *regs, uint64_t guest_base,
                         uint8_t *input_buf, uint32_t input_buf_len) {
  lazy_init();
  uint64_t buflen = input_buf_len;
  PLACE_INPUT(regs->rsp);
  uint64_t *argregs[6] = {&regs->rdi, &regs->rsi, &regs->rdx,
                          &regs->rcx, &regs->r8, &regs->r9};
  APPLY_ARGS({ if (i < 6) *argregs[i] = v; });
  if (g_ret) *(uint64_t *)g2h(regs->rsp) = g_ret;
}
#endif

int afl_persistent_hook_init(void) {
  return 1;  /* shared-memory input */
}
