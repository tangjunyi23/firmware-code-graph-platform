"""变异引擎：从协议模板生成确定性测试用例（M-ICS-1）。

每个用例 = (模板, 字段, 策略, 变体) → 变异后的报文字节。
全部确定性生成（random 策略用种子 PRNG），保证故障可复现。
"""

import random

_BOUNDARY_BYTES = [0x00, 0x01, 0x7F, 0x80, 0xFF]
_OVERFLOW_SIZES = [64, 256, 1024]


def _int_variants(length: int) -> list:
    """length 字节大端整型的边界值集合。"""
    maxv = (1 << (8 * length)) - 1
    vals = {0, 1, maxv, maxv - 1, maxv // 2}
    return [v.to_bytes(length, "big") for v in sorted(vals)]


def mutate(packet: bytes, field: dict, variant) -> bytes:
    """对 packet 的 field 应用一种变异。variant 语义随策略而定。"""
    offset = field["offset"]
    length = field["length"]
    strategy = field["strategy"]
    buf = bytearray(packet)
    if strategy == "overflow":
        # 在字段起始处插入长串 'A'（不改变原字节；长度前缀随之失真）
        return bytes(buf[:offset] + b"A" * variant + buf[offset:])
    if offset + length > len(buf):
        return bytes(buf)
    if strategy == "boundary":
        buf[offset:offset + length] = variant
    elif strategy == "bitflip":
        buf[offset:offset + length] = bytes([variant] * length)
    elif strategy == "fill":
        buf[offset:offset + length] = bytes([variant] * length)
    elif strategy == "random":
        buf[offset:offset + length] = variant
    return bytes(buf)


def _field_variants(field: dict, rng: random.Random) -> list:
    strategy = field["strategy"]
    length = field["length"]
    if strategy == "boundary":
        return [(f"0x{v.hex()}", v) for v in _int_variants(length)]
    if strategy == "bitflip":
        out = [("0x00", 0x00), ("0xff", 0xFF)]
        out += [(f"bit{i}", 1 << i) for i in (0, 3, 7)]
        return out
    if strategy == "fill":
        return [("0x00", 0x00), ("0xff", 0xFF), ("0x41", 0x41)]
    if strategy == "overflow":
        return [(f"{n}B", n) for n in _OVERFLOW_SIZES]
    if strategy == "random":
        count = max(4, min(8, length))
        return [(f"rand{i}",
                 bytes(rng.randrange(256) for _ in range(length)))
                for i in range(count)]
    return []


def generate_cases(protocol: dict, seed: int = 0xC0DE,
                   max_cases: int = 300) -> list:
    """展开协议全部模板的所有字段变异，按 seq 编号，max_cases 截断。

    返回 [{seq, template, template_desc, field, strategy, variant, payload}]，
    payload 为 bytes。首部总是各模板的未变异种子（基线连通性自检用）。
    """
    rng = random.Random(seed)
    cases = []
    seq = 0
    for tpl in protocol["templates"]:
        cases.append({
            "seq": seq, "template": tpl["name"],
            "template_desc": tpl.get("desc", ""),
            "field": "(seed)", "strategy": "baseline", "variant": "-",
            "payload": bytes(tpl["packet"]),
        })
        seq += 1
    for tpl in protocol["templates"]:
        for field in tpl["fields"]:
            for label, variant in _field_variants(field, rng):
                cases.append({
                    "seq": seq, "template": tpl["name"],
                    "template_desc": tpl.get("desc", ""),
                    "field": field["name"], "strategy": field["strategy"],
                    "variant": label,
                    "payload": mutate(tpl["packet"], field, variant),
                })
                seq += 1
    return cases[:max_cases]
