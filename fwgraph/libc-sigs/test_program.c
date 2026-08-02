/* M2b demo: static binary that links the same libc objects the demo FLIRT
 * signature is built from. If the sig works, IDA should name the pulled-in
 * libc functions (memcpy, strcpy, ...) in this binary.
 *
 * Build (done by build_sig.sh):
 *   <triplet>-gcc -O2 -static -o test_<arch> test_program.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* keep everything reachable; -O2 must not const-fold the calls away */
static volatile int sink_int;
static volatile char sink_buf[512];

__attribute__((noinline)) static void use_string(char *dst, const char *src)
{
    strcpy(dst, src);
    strcat(dst, "-tail");
    sink_int = strlen(dst);
    sink_int = strcmp(dst, src);
    sink_int = strncmp(dst, src, 4);
    sink_int = (int)(size_t)strchr(dst, '-');
    sink_int = (int)(size_t)strstr(dst, "tail");
    sink_int = strspn(dst, "abc");
    sink_int = atoi("42");
    sink_int = (int)strtol("123", NULL, 10);
}

__attribute__((noinline)) static void use_memory(void)
{
    char a[128], b[128];
    memset(a, 0x5a, sizeof(a));
    memcpy(b, a, sizeof(a));
    memmove(b + 1, b, sizeof(b) - 1);
    sink_int = memcmp(a, b, sizeof(a));
    sink_int = (int)(size_t)memchr(a, 0x5a, sizeof(a));
}

__attribute__((noinline)) static void use_stdio(void)
{
    char buf[256];
    snprintf(buf, sizeof(buf), "value=%d str=%s", 7, "seven");
    puts(buf);
    sprintf(buf, "%x", 255);
    sink_int = sscanf("10 20", "%d %d", (int *)&sink_int, (int *)&sink_int);
}

static int cmp_int(const void *a, const void *b)
{
    return *(const int *)a - *(const int *)b;
}

__attribute__((noinline)) static void use_stdlib(void)
{
    int v[8] = { 5, 3, 8, 1, 9, 2, 7, 4 };
    void *p = malloc(64);
    void *q = calloc(4, 16);
    p = realloc(p, 128);
    qsort(v, 8, sizeof(int), cmp_int);
    int key = 7;
    sink_int = (int)(size_t)bsearch(&key, v, 8, sizeof(int), cmp_int);
    sink_int = abs(-3) + labs(-4);
    free(p);
    free(q);
}

int main(void)
{
    char dst[256];
    use_string(dst, "hello-fwgraph");
    use_memory();
    use_stdio();
    use_stdlib();
    return (int)((char *)sink_buf - (char *)sink_buf) + (sink_int & 1);
}
