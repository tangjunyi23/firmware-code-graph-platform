"""Zero-token libc_equiv backfill for existing registries (M3 companion).

The LLM only sees a funnel-selected subset of functions, and rows recorded
before the libc_equiv field existed carry no libc information at all. This
module recovers the obvious cases for free: an AI name of the form
<domain>_<libc symbol> (util_strcpy, sys_memcpy, net_socket, ...) is almost
certainly that libc implementation inside a statically linked stripped
binary, so libc_equiv is filled from a built-in table of common
libc/POSIX/compiler built-in symbols.

Rows touched are marked source='backfill' so the provenance stays visible;
rows that already carry a libc_equiv (from the LLM or a previous backfill)
are never overwritten.

CLI: python -m pipeline.ailift.backfill <job_id>
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from pipeline.ailift.registry import GENERIC_FIRSTS, Registry
from pipeline.decompile.annotate import load_spec

FWGRAPH_ROOT = Path(__file__).resolve().parents[2]

# Common libc / POSIX / compiler built-in symbols (~250). Deliberately
# exact-match only: "util_free_mem" or "sys_close_fd" must NOT match;
# "util_free" and "sys_close" must.
LIBC_SYMBOLS = frozenset({
    # str*
    "strcpy", "strncpy", "strcat", "strncat", "strcmp", "strncmp",
    "strcasecmp", "strncasecmp", "strchr", "strrchr", "strstr",
    "strlen", "strnlen", "strdup", "strndup", "strspn", "strcspn",
    "strtok", "strtok_r", "strtol", "strtoul", "strtoll", "strtoull",
    "strtod", "strerror", "stpcpy",
    # mem*
    "memcpy", "memmove", "memset", "memcmp", "memchr", "memrchr",
    "memccpy", "memmem", "bcopy", "bzero", "bcmp",
    # stdio
    "printf", "fprintf", "sprintf", "snprintf", "vsprintf", "vsnprintf",
    "scanf", "fscanf", "sscanf", "vsscanf", "puts", "putchar", "fputs",
    "fputc", "fgets", "gets", "fopen", "fdopen", "fclose", "fread",
    "fwrite", "fseek", "ftell", "rewind", "fflush", "feof", "ferror",
    "fileno", "popen", "pclose", "perror", "remove", "rename", "tmpnam",
    "mktemp", "mkstemp",
    # stdlib / alloc / env / process
    "malloc", "calloc", "realloc", "free", "exit", "_exit", "abort",
    "atexit", "getenv", "setenv", "unsetenv", "putenv", "clearenv",
    "system", "qsort", "bsearch", "rand", "srand", "random", "srandom",
    "realpath", "daemon", "err", "errx",
    # unistd / fs
    "open", "close", "read", "write", "lseek", "dup", "dup2", "pipe",
    "fork", "vfork", "execve", "execl", "execlp", "execle", "execv",
    "execvp", "wait", "waitpid", "getpid", "getppid", "getuid", "geteuid",
    "getgid", "getegid", "setuid", "setgid", "chdir", "getcwd", "chown",
    "chmod", "access", "unlink", "rmdir", "mkdir", "symlink", "readlink",
    "truncate", "ftruncate", "fsync", "ioctl", "fcntl", "stat", "fstat",
    "lstat", "opendir", "readdir", "closedir",
    # signals / select
    "kill", "signal", "sigaction", "sigprocmask", "sigsuspend",
    "sigemptyset", "sigfillset", "sigaddset", "select", "poll",
    "epoll_create", "epoll_ctl", "epoll_wait", "sleep", "usleep",
    "nanosleep", "alarm",
    # sockets / netdb
    "socket", "bind", "listen", "accept", "connect", "shutdown", "send",
    "recv", "sendto", "recvfrom", "sendmsg", "recvmsg", "setsockopt",
    "getsockopt", "getpeername", "gethostname", "gethostbyname",
    "getaddrinfo", "inet_addr", "inet_ntoa", "inet_ntop", "inet_pton",
    "htons", "ntohs", "htonl", "ntohl",
    # time
    "time", "gettimeofday", "settimeofday", "localtime", "gmtime",
    "mktime", "strftime",
    # pthread
    "pthread_create", "pthread_join", "pthread_mutex_init",
    "pthread_mutex_lock", "pthread_mutex_unlock", "pthread_mutex_destroy",
    "pthread_cond_init", "pthread_cond_wait", "pthread_cond_signal",
    "pthread_cond_broadcast",
    # misc
    "syslog", "basename", "dirname", "fnmatch", "dlopen", "dlsym",
    "dlclose", "dlerror", "mmap", "munmap", "sysconf", "getopt",
    "getopt_long", "isatty", "tcgetattr", "tcsetattr", "crypt",
    # ctype
    "isalpha", "isdigit", "isalnum", "isspace", "isupper", "islower",
    "isxdigit", "isprint", "toupper", "tolower",
    # compiler built-ins (libgcc / fortify)
    "__divdi3", "__moddi3", "__udivdi3", "__umoddi3", "__ashldi3",
    "__ashrdi3", "__lshrdi3", "__muldi3", "__fixdfdi", "__stack_chk_fail",
    "__memcpy_chk", "__memset_chk", "__strcpy_chk", "__sprintf_chk",
    "__snprintf_chk",
})

# Fallback domain prefixes when naming_spec.yaml cannot be loaded.
_FALLBACK_PREFIXES = frozenset({
    "http", "cgi", "nvram", "auth", "net", "crypto", "fw", "upnp", "dns",
    "wifi", "sys", "util", "db", "log", "proto", "hal", "misc",
})

_prefixes_cache = None


def default_prefixes():
    """Domain prefixes an AI name may carry (naming_spec domains + the
    validator's generic first segments)."""
    global _prefixes_cache
    if _prefixes_cache is None:
        try:
            domains = set(load_spec().get("domains", []))
        except Exception:  # noqa: BLE001 - spec unreadable: fall back
            domains = set()
        _prefixes_cache = frozenset(domains | GENERIC_FIRSTS
                                    | set(_FALLBACK_PREFIXES))
    return _prefixes_cache


def guess_libc_equiv(name, prefixes=None):
    """Map an AI name to a libc symbol, or None.

    Matches when the full name is itself a libc symbol (rare: rule names or
    single-segment leftovers) or when stripping exactly one domain prefix
    (<domain>_<symbol>) leaves an exact table hit. "util_strcpy" -> "strcpy";
    "util_strcpy_impl" / "util_free_mem" / "http_parse_config" -> None.
    """
    if not name:
        return None
    name = name.strip()
    if name in LIBC_SYMBOLS:
        return name
    if "_" not in name:
        return None
    prefix, tail = name.split("_", 1)
    if tail in LIBC_SYMBOLS and prefix in (prefixes or default_prefixes()):
        return tail
    return None


def backfill_registry(registry, md5=None):
    """Fill empty libc_equiv on accepted/done rows; never overwrites.

    Returns {"checked": N, "updated": M, "hits": {name: equiv}}.
    """
    sql = ("SELECT md5, addr, new_name FROM name_registry "
           "WHERE status IN ('accepted','done') "
           "AND (libc_equiv IS NULL OR libc_equiv='')")
    args = ()
    if md5:
        sql += " AND md5=?"
        args = (md5,)
    rows = registry.conn.execute(sql, args).fetchall()
    prefixes = default_prefixes()
    updates, hits = [], {}
    for row in rows:
        equiv = guess_libc_equiv(row["new_name"], prefixes)
        if equiv:
            updates.append((equiv, row["md5"], row["addr"]))
            hits[row["new_name"]] = equiv
    updated = registry.backfill_libc_equiv(updates) if updates else 0
    return {"checked": len(rows), "updated": updated, "hits": hits}


def patch_symbols_json(symbols, libc_rows):
    """Attach libc_equiv to symbols.json function entries (in place).
    libc_rows: registry rows with md5/addr/libc_equiv. Returns patch count."""
    by_md5 = {}
    for row in libc_rows:
        by_md5.setdefault(row["md5"], {})[row["addr"]] = row["libc_equiv"]
    patched = 0
    for md5, rows in by_md5.items():
        entry = symbols.get("binaries", {}).get(md5)
        if not entry:
            continue
        for func in entry.get("functions", []):
            equiv = rows.get(func.get("addr"))
            if equiv and func.get("libc_equiv") != equiv:
                func["libc_equiv"] = equiv
                patched += 1
    return patched


def backfill_job(job_id, data_dir):
    """Backfill one job's registry and mirror libc_equiv into symbols.json."""
    data_dir = Path(data_dir)
    pseudo_root = data_dir / "pseudocode" / job_id
    symbols_path = pseudo_root / "symbols.json"
    registry = Registry(pseudo_root / "name_registry.db")
    try:
        result = backfill_registry(registry)
        libc_rows = [dict(r) for r in registry.conn.execute(
            "SELECT md5, addr, libc_equiv FROM name_registry "
            "WHERE status IN ('accepted','done') "
            "AND libc_equiv IS NOT NULL AND libc_equiv != ''").fetchall()]
        symbols = json.loads(symbols_path.read_text(encoding="utf-8"))
        result["symbols_patched"] = patch_symbols_json(symbols, libc_rows)
        if result["symbols_patched"]:
            symbols_path.write_text(json.dumps(symbols, indent=1),
                                    encoding="utf-8")
        result["job_id"] = job_id
        result["ts"] = datetime.now(timezone.utc).isoformat()
        return result
    finally:
        registry.close()


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 1
    from dotenv import load_dotenv
    load_dotenv(FWGRAPH_ROOT / ".env")
    data_dir = Path(os.getenv("FWGRAPH_DATA", str(FWGRAPH_ROOT / "data")))
    print(json.dumps(backfill_job(argv[1], data_dir), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
