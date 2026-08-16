"""工控/物联网协议模板库（M-ICS-1）。

每个协议定义若干种子报文模板（template），模板携带可变字段描述：
  {"name", "offset", "length", "strategy"}
strategy 取值：
  boundary  —— 整型字段边界值（0/1/max/max-1/中间值）
  bitflip   —— 字节级位翻转（0xFF/0x00/单比特）
  fill      —— 填充 0x00 / 0xFF / 'A'
  overflow  —— 在字段起始处插入 64/256/1024 字节 'A'（长度前缀协议必备）
  random    —— 种子化伪随机替换（每模板 8 个）

偏移仅作变异锚点，不追求语义精确——fuzz 的目的就是制造畸形报文。
"""

# ---------------------------------------------------------------------------
# Modbus TCP（MBAP + PDU）
# ---------------------------------------------------------------------------

_MODBUS_READ_HOLDING = bytes.fromhex("0001" "0000" "0006" "01" "03" "0000" "000a")
_MODBUS_WRITE_SINGLE = bytes.fromhex("0001" "0000" "0006" "01" "06" "0000" "1234")
_MODBUS_READ_DEV_ID = bytes.fromhex("0001" "0000" "0005" "01" "2b" "0e" "01" "00")

# ---------------------------------------------------------------------------
# S7comm（TPKT + COTP CR / S7 Read Var）
# ---------------------------------------------------------------------------

_S7_COTP_CR = bytes.fromhex(
    "03000016"          # TPKT: ver3, len 22
    "11e00000 0001 00"  # COTP CR
    "c0010a"            # TPDU size
    "c1020100"          # src TSAP 0x0100
    "c2020102"          # dst TSAP 0x0102 (slot 2)
    "c00109"            # checksum-ish param
)
_S7_READ_VAR = bytes.fromhex(
    "03000021"          # TPKT
    "02f080"            # COTP DT
    "3201"              # S7: protocol id 0x32, ROSCTR job
    "0000"              # redundancy id
    "0001"              # pdu ref
    "000e"              # param len
    "0000"              # data len
    "04"                # function: read var
    "01"                # item count
    "120a10"            # var spec
    "02"                # syntax id S7ANY
    "0001"              # transport size: byte, len 1
    "0001"              # db number 1
    "84"                # area: DB
    "000000"            # address
)

# ---------------------------------------------------------------------------
# OPC UA（二进制 Hello）
# ---------------------------------------------------------------------------

_OPCUA_HELLO = (
    b"HELF"                              # message type HEL + chunk F
    + (0x39).to_bytes(4, "little")       # message size
    + (0).to_bytes(4, "little")          # protocol version
    + (65536).to_bytes(4, "little")      # recv buffer
    + (65536).to_bytes(4, "little")      # send buffer
    + (0).to_bytes(4, "little")          # max message size
    + (0).to_bytes(4, "little")          # max chunk count
    + (0x17).to_bytes(4, "little")       # endpoint url length
    + b"opc.tcp://device:4840"
)

# ---------------------------------------------------------------------------
# DNP3（链路层帧）
# ---------------------------------------------------------------------------

_DNP3_LINK_STATUS = bytes.fromhex("0564" "05" "c4" "0100" "0004" "4f4a")
_DNP3_READ = bytes.fromhex(
    "0564" "0d" "c4" "0100" "0004" "a4a8"   # link header + crc
    "c0" "01" "3c01" "06"                   # transport/app: READ class1
    "b16e"                                  # data crc
)

# ---------------------------------------------------------------------------
# MQTT（CONNECT / PUBLISH）
# ---------------------------------------------------------------------------

_MQTT_CONNECT = (
    bytes([0x10, 0x1A])                  # CONNECT, remaining length 26
    + b"\x00\x04MQTT"                    # protocol name
    + bytes([0x04, 0x02])                # level 4, clean session
    + b"\x00\x3c"                        # keepalive 60
    + b"\x00\x0e" + b"fw-client"         # client id
)
_MQTT_PUBLISH = (
    bytes([0x30, 0x14])                  # PUBLISH qos0, remaining 20
    + b"\x00\x05" + b"t/a/b"             # topic
    + b"fuzz-payload"                    # payload (no length field)
)

# ---------------------------------------------------------------------------
# HTTP（嵌入式 Web 表单风格）
# ---------------------------------------------------------------------------

_HTTP_POST = (
    b"POST /goform/xyz HTTP/1.1\r\n"
    b"Host: target\r\n"
    b"Content-Length: 8\r\n"
    b"Content-Type: application/x-www-form-urlencoded\r\n"
    b"\r\n"
    b"AAAAAAAA"
)

PROTOCOLS = {
    "modbus_tcp": {
        "name": "modbus_tcp", "label": "Modbus TCP",
        "transport": "tcp", "default_port": 502,
        "templates": [
            {"name": "read_holding_registers", "desc": "读保持寄存器 FC03",
             "packet": _MODBUS_READ_HOLDING,
             "fields": [
                 {"name": "transaction_id", "offset": 0, "length": 2, "strategy": "boundary"},
                 {"name": "length", "offset": 4, "length": 2, "strategy": "boundary"},
                 {"name": "unit_id", "offset": 6, "length": 1, "strategy": "bitflip"},
                 {"name": "function_code", "offset": 7, "length": 1, "strategy": "boundary"},
                 {"name": "start_address", "offset": 8, "length": 2, "strategy": "boundary"},
                 {"name": "quantity", "offset": 10, "length": 2, "strategy": "boundary"},
             ]},
            {"name": "write_single_register", "desc": "写单寄存器 FC06",
             "packet": _MODBUS_WRITE_SINGLE,
             "fields": [
                 {"name": "function_code", "offset": 7, "length": 1, "strategy": "bitflip"},
                 {"name": "address", "offset": 8, "length": 2, "strategy": "boundary"},
                 {"name": "value", "offset": 10, "length": 2, "strategy": "bitflip"},
             ]},
            {"name": "read_device_id", "desc": "读设备标识 FC2B",
             "packet": _MODBUS_READ_DEV_ID,
             "fields": [
                 {"name": "function_code", "offset": 7, "length": 1, "strategy": "boundary"},
                 {"name": "mei_type", "offset": 8, "length": 1, "strategy": "bitflip"},
                 {"name": "object_id", "offset": 10, "length": 1, "strategy": "boundary"},
             ]},
        ],
    },
    "s7": {
        "name": "s7", "label": "Siemens S7comm",
        "transport": "tcp", "default_port": 102,
        "templates": [
            {"name": "cotp_connect", "desc": "COTP 连接请求",
             "packet": _S7_COTP_CR,
             "fields": [
                 {"name": "tpkt_length", "offset": 2, "length": 2, "strategy": "boundary"},
                 {"name": "src_tsap", "offset": 17, "length": 2, "strategy": "boundary"},
                 {"name": "dst_tsap", "offset": 21, "length": 2, "strategy": "boundary"},
             ]},
            {"name": "s7_read_var", "desc": "S7 读变量",
             "packet": _S7_READ_VAR,
             "fields": [
                 {"name": "pdu_ref", "offset": 11, "length": 2, "strategy": "boundary"},
                 {"name": "param_len", "offset": 13, "length": 2, "strategy": "boundary"},
                 {"name": "db_number", "offset": 24, "length": 2, "strategy": "boundary"},
                 {"name": "area", "offset": 26, "length": 1, "strategy": "bitflip"},
                 {"name": "address", "offset": 27, "length": 3, "strategy": "random"},
             ]},
        ],
    },
    "opc_ua": {
        "name": "opc_ua", "label": "OPC UA (IEC 62541)",
        "transport": "tcp", "default_port": 4840,
        "templates": [
            {"name": "hello", "desc": "HEL 握手报文",
             "packet": _OPCUA_HELLO,
             "fields": [
                 {"name": "message_size", "offset": 4, "length": 4, "strategy": "boundary"},
                 {"name": "recv_buffer", "offset": 12, "length": 4, "strategy": "boundary"},
                 {"name": "url_length", "offset": 28, "length": 4, "strategy": "boundary"},
                 {"name": "endpoint_url", "offset": 32, "length": 23, "strategy": "random"},
             ]},
        ],
    },
    "dnp3": {
        "name": "dnp3", "label": "DNP3",
        "transport": "tcp", "default_port": 20000,
        "templates": [
            {"name": "link_status", "desc": "链路状态请求",
             "packet": _DNP3_LINK_STATUS,
             "fields": [
                 {"name": "length", "offset": 2, "length": 1, "strategy": "boundary"},
                 {"name": "control", "offset": 3, "length": 1, "strategy": "bitflip"},
                 {"name": "dest_addr", "offset": 4, "length": 2, "strategy": "boundary"},
                 {"name": "src_addr", "offset": 6, "length": 2, "strategy": "boundary"},
                 {"name": "crc", "offset": 8, "length": 2, "strategy": "random"},
             ]},
            {"name": "app_read", "desc": "应用层 READ",
             "packet": _DNP3_READ,
             "fields": [
                 {"name": "app_control", "offset": 10, "length": 1, "strategy": "bitflip"},
                 {"name": "function_code", "offset": 11, "length": 1, "strategy": "boundary"},
                 {"name": "object_group", "offset": 12, "length": 1, "strategy": "boundary"},
             ]},
        ],
    },
    "mqtt": {
        "name": "mqtt", "label": "MQTT",
        "transport": "tcp", "default_port": 1883,
        "templates": [
            {"name": "connect", "desc": "CONNECT 连接报文",
             "packet": _MQTT_CONNECT,
             "fields": [
                 {"name": "remaining_length", "offset": 1, "length": 1, "strategy": "boundary"},
                 {"name": "proto_name_len", "offset": 2, "length": 2, "strategy": "boundary"},
                 {"name": "keepalive", "offset": 10, "length": 2, "strategy": "boundary"},
                 {"name": "client_id_len", "offset": 12, "length": 2, "strategy": "boundary"},
                 {"name": "client_id", "offset": 14, "length": 0, "strategy": "overflow"},
             ]},
            {"name": "publish", "desc": "PUBLISH 发布报文",
             "packet": _MQTT_PUBLISH,
             "fields": [
                 {"name": "remaining_length", "offset": 1, "length": 1, "strategy": "boundary"},
                 {"name": "topic_len", "offset": 2, "length": 2, "strategy": "boundary"},
                 {"name": "payload", "offset": 9, "length": 0, "strategy": "overflow"},
             ]},
        ],
    },
    "http": {
        "name": "http", "label": "HTTP (嵌入式 Web)",
        "transport": "tcp", "default_port": 80,
        "templates": [
            {"name": "post_form", "desc": "POST 表单",
             "packet": _HTTP_POST,
             "fields": [
                 {"name": "path", "offset": 5, "length": 11, "strategy": "fill"},
                 {"name": "path_overflow", "offset": 16, "length": 0, "strategy": "overflow"},
                 {"name": "content_length", "offset": 56, "length": 1, "strategy": "boundary"},
                 {"name": "body", "offset": 117, "length": 8, "strategy": "fill"},
                 {"name": "body_overflow", "offset": 125, "length": 0, "strategy": "overflow"},
             ]},
        ],
    },
}


def list_protocols() -> list:
    """UI 用的协议清单（不含报文字节）。"""
    out = []
    for p in PROTOCOLS.values():
        out.append({
            "name": p["name"], "label": p["label"],
            "transport": p["transport"], "default_port": p["default_port"],
            "templates": [{"name": t["name"], "desc": t["desc"]}
                          for t in p["templates"]],
        })
    return out


def get_protocol(name: str) -> dict | None:
    return PROTOCOLS.get(name)
