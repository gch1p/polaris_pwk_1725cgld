# Polaris PWK 1725CGLD "smart" kettle python library
# --------------------------------------------------
# Copyright (C) Evgeny Zinoviev, 2022
# License: BSD-3c

from __future__ import annotations

import logging
import socket
import random
import struct
import threading
import time

from abc import abstractmethod, ABC
from enum import Enum, auto
from typing import Union, Optional, Dict, Tuple, List
from ipaddress import IPv4Address, IPv6Address

import cryptography.hazmat.primitives._serialization as srlz

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import ciphers, padding, hashes
from cryptography.hazmat.primitives.ciphers import algorithms, modes

ReprDict = Dict[str, Union[str, int, float, bool]]
_logger = logging.getLogger(__name__)

PING_FREQUENCY = 3
RESEND_ATTEMPTS = 5
ERROR_TIMEOUT = 15
MESSAGE_QUEUE_REMOVE_DELAY = 13  # after what time to delete (and pass False to handlers, if needed) messages with phase=DONE from queue
DISCONNECT_TIMEOUT = 15


def safe_callback_call(f: callable,
                       *args,
                       logger: logging.Logger = None,
                       error_message: str = None):
    try:
        return f(*args)
    except Exception as exc:
        logger.error(f'{error_message}, see exception below:')
        logger.exception(exc)
    return None


# drop-in replacement for java.lang.System.arraycopy
# TODO: rewrite
def arraycopy(src, src_pos, dest, dest_pos, length):
    for i in range(length):
        dest[i + dest_pos] = src[i + src_pos]


# "convert" unsigned byte to signed
def u8_to_s8(b: int) -> int:
    return struct.unpack('b', bytes([b]))[0]


class PowerType(Enum):
    OFF = 0  # turn off
    ON = 1  # turn on, set target temperature to 100
    CUSTOM = 3  # turn on, allows custom target temperature
    # MYSTERY_MODE = 2  # don't know what 2 means, needs testing
    # update: if I set it to '2', it just resets to '0'


# low-level protocol structures
# -----------------------------

class FrameType(Enum):
    ACK = 0
    CMD = 1
    AUX = 2
    NAK = 3


class FrameHead:
    seq: Optional[int]  # u8
    type: FrameType  # u8
    length: int  # u16. This is the length of FrameItem's payload

    @staticmethod
    def from_bytes(buf: bytes) -> FrameHead:
        seq, ft, length = struct.unpack('<BBH', buf)
        return FrameHead(seq, FrameType(ft), length)

    def __init__(self,
                 seq: Optional[int],
                 frame_type: FrameType,
                 length: Optional[int] = None):
        self.seq = seq
        self.type = frame_type
        self.length = length or 0

    def pack(self) -> bytes:
        assert self.length != 0, "FrameHead.length has not been set"
        assert self.seq is not None, "FrameHead.seq has not been set"
        return struct.pack('<BBH', self.seq, self.type.value, self.length)


class FrameItem:
    head: FrameHead
    payload: bytes

    def __init__(self, head: FrameHead, payload: Optional[bytes] = None):
        self.head = head
        self.payload = payload

    def setpayload(self, payload: Union[bytes, bytearray]):
        if isinstance(payload, bytearray):
            payload = bytes(payload)
        self.payload = payload
        self.head.length = len(payload)

    def pack(self) -> bytes:
        ba = bytearray(self.head.pack())
        ba.extend(self.payload)
        return bytes(ba)


# high-level wrappers around FrameItem
# ------------------------------------

class MessagePhase(Enum):
    WAITING = 0
    SENT = 1
    DONE = 2


class Message:
    frame: Optional[FrameItem]
    id: int

    _global_id = 0

    def __init__(self):
        self.frame = None

        # global internal message id, only useful for debugging purposes
        self.id = self.next_id()

    def __repr__(self):
        return f'<{self.__class__.__name__} id={self.id} seq={self.frame.head.seq}>'

    @staticmethod
    def next_id():
        _id = Message._global_id
        Message._global_id = (Message._global_id + 1) % 100000
        return _id

    @staticmethod
    def from_encrypted(buf: bytes, inkey: bytes, outkey: bytes) -> Message:
        _logger.debug(f'Message:from_encrypted: buf={buf.hex()}')

        assert len(buf) >= 4, 'invalid size'
        head = FrameHead.from_bytes(buf[:4])

        assert len(buf) == head.length + 4, f'invalid buf size ({len(buf)} != {head.length})'
        payload = buf[4:]
        b = head.seq

        j = b & 0xF
        k = b >> 4 & 0xF

        key = bytearray(len(inkey))
        arraycopy(inkey, j, key, 0, len(inkey) - j)
        arraycopy(inkey, 0, key, len(inkey) - j, j)

        iv = bytearray(len(outkey))
        arraycopy(outkey, k, iv, 0, len(outkey) - k)
        arraycopy(outkey, 0, iv, len(outkey) - k, k)

        cipher = ciphers.Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(payload) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = unpadder.update(decrypted_data)
        decrypted_data += unpadder.finalize()

        assert len(decrypted_data) != 0, 'decrypted data is null'
        assert head.seq == decrypted_data[0], f'decrypted seq mismatch {head.seq} != {decrypted_data[0]}'

        # _logger.debug('Message.from_encrypted: plaintext: '+decrypted_data.hex())

        if head.type == FrameType.ACK:
            return AckMessage(head.seq)

        elif head.type == FrameType.NAK:
            return NakMessage(head.seq)

        elif head.type == FrameType.AUX:
            # TODO implement AUX
            raise NotImplementedError('FrameType AUX is not yet implemented')

        elif head.type == FrameType.CMD:
            type = decrypted_data[1]
            data = decrypted_data[2:]

            cl = UnknownMessage

            subclasses = [cl for cl in CmdIncomingMessage.__subclasses__() if cl is not SimpleBooleanMessage]
            subclasses.extend(SimpleBooleanMessage.__subclasses__())

            for _cl in subclasses:
                # `UnknownMessage` is a special class that holds a packed command that we don't recognize.
                # It will be used anyway if we don't find a match, so skip it here
                if _cl == UnknownMessage:
                    continue

                if _cl.TYPE == type:
                    cl = _cl
                    break

            m = cl.from_packed_data(data, seq=head.seq)
            if isinstance(m, UnknownMessage):
                m.set_type(type)
            return m

        else:
            raise NotImplementedError(f'Unexpected frame type: {head.type}')

    def pack_data(self) -> bytes:
        return b''

    @property
    def seq(self) -> Union[int, None]:
        try:
            return self.frame.head.seq
        except:
            return None

    @seq.setter
    def seq(self, seq: int):
        self.frame.head.seq = seq

    def encrypt(self, outkey: bytes, inkey: bytes, token: bytes, pubkey: bytes):
        assert self.frame is not None

        data = self._get_data_to_encrypt()
        assert data is not None

        b = self.frame.head.seq
        i = b & 0xf
        j = b >> 4 & 0xf

        outkey = bytearray(outkey)

        l = len(outkey)
        key = bytearray(l)

        arraycopy(outkey, i, key, 0, l-i)
        arraycopy(outkey, 0, key, l-i, i)

        inkey = bytearray(inkey)

        l = len(inkey)
        iv = bytearray(l)

        arraycopy(inkey, j, iv, 0, l-j)
        arraycopy(inkey, 0, iv, l-j, j)

        cipher = ciphers.Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()

        newdata = bytearray(len(data)+1)
        newdata[0] = b

        arraycopy(data, 0, newdata, 1, len(data))

        newdata = bytes(newdata)
        _logger.debug('frame payload to be encrypted: ' + newdata.hex())

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        ciphertext = bytearray()
        ciphertext.extend(encryptor.update(padder.update(newdata) + padder.finalize()))
        ciphertext.extend(encryptor.finalize())

        self.frame.setpayload(ciphertext)

    def _get_data_to_encrypt(self) -> bytes:
        return self.pack_data()


class AckMessage(Message, ABC):
    def __init__(self, seq: Optional[int] = None):
        super().__init__()
        self.frame = FrameItem(FrameHead(seq, FrameType.ACK, None))


class NakMessage(Message, ABC):
    def __init__(self, seq: Optional[int] = None):
        super().__init__()
        self.frame = FrameItem(FrameHead(seq, FrameType.NAK, None))


class CmdMessage(Message):
    type: Optional[int]
    data: bytes

    TYPE = None

    def _get_data_to_encrypt(self) -> bytes:
        buf = bytearray()
        buf.append(self.get_type())
        buf.extend(self.pack_data())
        return bytes(buf)

    def __init__(self, seq: Optional[int] = None):
        super().__init__()
        self.frame = FrameItem(FrameHead(seq, FrameType.CMD))
        self.data = b''

    def _repr_fields(self) -> ReprDict:
        return {
            'cmd': self.get_type()
        }

    def __repr__(self):
        params = [
            __name__+'.'+self.__class__.__name__,
            f'id={self.id}',
            f'seq={self.seq}'
        ]
        fields = self._repr_fields()
        if fields:
            for k, v in fields.items():
                params.append(f'{k}={v}')
        elif self.data:
            params.append(f'data={self.data.hex()}')
        return '<'+' '.join(params)+'>'

    def get_type(self) -> int:
        return self.__class__.TYPE


class CmdIncomingMessage(CmdMessage):
    @staticmethod
    @abstractmethod
    def from_packed_data(cls, data: bytes, seq: Optional[int] = None):
        pass

    @abstractmethod
    def _repr_fields(self) -> ReprDict:
        pass


class CmdOutgoingMessage(CmdMessage):
    @abstractmethod
    def pack_data(self) -> bytes:
        return b''


class ModeMessage(CmdOutgoingMessage, CmdIncomingMessage):
    TYPE = 1

    pt: PowerType

    def __init__(self, power_type: PowerType, seq: Optional[int] = None):
        super().__init__(seq)
        self.pt = power_type

    @classmethod
    def from_packed_data(cls, data: bytes, seq=0) -> ModeMessage:
        assert len(data) == 1, 'data size expected to be 1'
        mode, = struct.unpack('B', data)
        return ModeMessage(PowerType(mode), seq=seq)

    def pack_data(self) -> bytes:
        return self.pt.value.to_bytes(1, byteorder='little')

    def _repr_fields(self) -> ReprDict:
        return {'mode': self.pt.name}


class TargetTemperatureMessage(CmdOutgoingMessage, CmdIncomingMessage):
    temperature: int

    TYPE = 2

    def __init__(self, temp: int, seq: Optional[int] = None):
        super().__init__(seq)
        self.temperature = temp

    @classmethod
    def from_packed_data(cls, data: bytes, seq=0) -> TargetTemperatureMessage:
        assert len(data) == 2, 'data size expected to be 2'
        nat, frac = struct.unpack('BB', data)
        temp = int(nat + (frac / 100))
        return TargetTemperatureMessage(temp, seq=seq)

    def pack_data(self) -> bytes:
        return bytes([self.temperature, 0])

    def _repr_fields(self) -> ReprDict:
        return {'temperature': self.temperature}


class PingMessage(CmdIncomingMessage, CmdOutgoingMessage):
    TYPE = 255

    @classmethod
    def from_packed_data(cls, data: bytes, seq=0) -> PingMessage:
        assert len(data) == 0, 'no data expected'
        return PingMessage(seq=seq)

    def pack_data(self) -> bytes:
        return b''

    def _repr_fields(self) -> ReprDict:
        return {}


# This is the first protocol message. Sent by a client.
# Kettle usually ACKs this, but sometimes i don't get any ACK and the very next message is HandshakeResponseMessage.
class HandshakeMessage(CmdMessage):
    TYPE = 0

    def encrypt(self,
                outkey: bytes,
                inkey: bytes,
                token: bytes,
                pubkey: bytes):
        cipher = ciphers.Cipher(algorithms.AES(outkey), modes.CBC(inkey))
        encryptor = cipher.encryptor()

        ciphertext = bytearray()
        ciphertext.extend(encryptor.update(token))
        ciphertext.extend(encryptor.finalize())

        pld = bytearray()
        pld.append(0)
        pld.extend(pubkey)
        pld.extend(ciphertext)

        self.frame.setpayload(pld)


# Kettle either sends this right after the handshake, of first it ACKs the handshake then sends this.
class HandshakeResponseMessage(CmdIncomingMessage):
    TYPE = 0

    protocol: int
    fw_major: int
    fw_minor: int
    mode: int
    token: bytes

    def __init__(self,
                 protocol: int,
                 fw_major: int,
                 fw_minor: int,
                 mode: int,
                 token: bytes,
                 seq: Optional[int] = None):
        super().__init__(seq)
        self.protocol = protocol
        self.fw_major = fw_major
        self.fw_minor = fw_minor
        self.mode = mode
        self.token = token

    @classmethod
    def from_packed_data(cls, data: bytes, seq=0) -> HandshakeResponseMessage:
        protocol, fw_major, fw_minor, mode = struct.unpack('<HBBB', data[:5])
        return HandshakeResponseMessage(protocol, fw_major, fw_minor, mode, token=data[5:], seq=seq)

    def _repr_fields(self) -> ReprDict:
        return {
            'protocol': self.protocol,
            'fw': f'{self.fw_major}.{self.fw_minor}',
            'mode': self.mode,
            'token': self.token.hex()
        }


# Apparently, some hardware info.
# On the other hand, if you look at com.syncleiot.iottransport.commands.CmdHardware, its mqtt topic says "mcu_firmware".
# My device returns 1.1.1. The kettle uses on ESP8266 ESP-12F MCU under the hood (or, more precisely, under a piece of
# cheap plastic), so maybe 1.1.1 is some MCU ROM version.
class DeviceHardwareMessage(CmdIncomingMessage):
    TYPE = 143  # -113

    hw: List[int]

    def __init__(self, hw: List[int], seq: Optional[int] = None):
        super().__init__(seq)
        self.hw = hw

    @classmethod
    def from_packed_data(cls, data: bytes, seq=0) -> DeviceHardwareMessage:
        assert len(data) == 3, 'invalid data size, expected 3'
        hw = list(struct.unpack('<BBB', data))
        return DeviceHardwareMessage(hw, seq=seq)

    def _repr_fields(self) -> ReprDict:
        return {'device_hardware': '.'.join(map(str, self.hw))}


# This message is sent by kettle right after the HandshakeMessageResponse.
# The diagnostic data is supposed to be sent to vendor, which we, obviously, not going to do.
# So just ACK and skip it.
class DeviceDiagnosticMessage(CmdIncomingMessage):
    TYPE = 145  # -111

    diag_data: bytes

    def __init__(self, diag_data: bytes, seq: Optional[int] = None):
        super().__init__(seq)
        self.diag_data = diag_data

    @classmethod
    def from_packed_data(cls, data: bytes, seq=0) -> DeviceDiagnosticMessage:
        return DeviceDiagnosticMessage(diag_data=data, seq=seq)

    def _repr_fields(self) -> ReprDict:
        return {'diag_data': self.diag_data.hex()}


class SimpleBooleanMessage(ABC, CmdIncomingMessage):
    value: bool

    def __init__(self, value: bool, seq: Optional[int] = None):
        super().__init__(seq)
        self.value = value

    @classmethod
    def from_packed_data(cls, data: bytes, seq: Optional[int] = None):
        assert len(data) == 1, 'invalid data size, expected 1'
        enabled, = struct.unpack('<B', data)
        return cls(value=enabled == 1, seq=seq)

    @abstractmethod
    def _repr_fields(self) -> ReprDict:
        pass


class AccessControlMessage(SimpleBooleanMessage):
    TYPE = 133  # -123

    def _repr_fields(self) -> ReprDict:
        return {'acl_enabled': self.value}


class ErrorMessage(SimpleBooleanMessage):
    TYPE = 7

    def _repr_fields(self) -> ReprDict:
        return {'error': self.value}


class ChildLockMessage(SimpleBooleanMessage):
    TYPE = 30

    def _repr_fields(self) -> ReprDict:
        return {'child_lock': self.value}


class VolumeMessage(SimpleBooleanMessage):
    TYPE = 9

    def _repr_fields(self) -> ReprDict:
        return {'volume': self.value}


class BacklightMessage(SimpleBooleanMessage):
    TYPE = 28

    def _repr_fields(self) -> ReprDict:
        return {'backlight': self.value}


class CurrentTemperatureMessage(CmdIncomingMessage):
    TYPE = 20

    current_temperature: int

    def __init__(self, temp: int, seq: Optional[int] = None):
        super().__init__(seq)
        self.current_temperature = temp

    @classmethod
    def from_packed_data(cls, data: bytes, seq=0) -> CurrentTemperatureMessage:
        assert len(data) == 2, 'data size expected to be 2'
        nat, frac = struct.unpack('BB', data)
        temp = int(nat + (frac / 100))
        return CurrentTemperatureMessage(temp, seq=seq)

    def pack_data(self) -> bytes:
        return bytes([self.current_temperature, 0])

    def _repr_fields(self) -> ReprDict:
        return {'current_temperature': self.current_temperature}


class UnknownMessage(CmdIncomingMessage):
    type: Optional[int]
    data: bytes

    def __init__(self, data: bytes, **kwargs):
        super().__init__(**kwargs)
        self.type = None
        self.data = data

    @classmethod
    def from_packed_data(cls, data: bytes, seq=0) -> UnknownMessage:
        return UnknownMessage(data, seq=seq)

    def set_type(self, type: int):
        self.type = type

    def get_type(self) -> int:
        return self.type

    def _repr_fields(self) -> ReprDict:
        return {
            'type': self.type,
            'data': self.data.hex()
        }


class WrappedMessage:
    _message: Message
    _handler: Optional[callable]
    _validator: Optional[callable]
    _logger: Optional[logging.Logger]
    _phase: MessagePhase
    _phase_update_time: float

    def __init__(self,
                 message: Message,
                 handler: Optional[callable] = None,
                 validator: Optional[callable] = None,
                 ack=False):
        self._message = message
        self._handler = handler
        self._validator = validator
        self._logger = None
        self._phase = MessagePhase.WAITING
        self._phase_update_time = 0
        if not validator and ack:
            self._validator = lambda m: isinstance(m, AckMessage)

    def setlogger(self, logger: logging.Logger):
        self._logger = logger

    def validate(self, message: Message):
        if not self._validator:
            return True
        return self._validator(message)

    def call(self, *args, error_message: str = None) -> None:
        if not self._handler:
            return
        try:
            self._handler(*args)
        except Exception as exc:
            logger = self._logger or logging.getLogger(self.__class__.__name__)
            logger.error(f'{error_message}, see exception below:')
            logger.exception(exc)

    @property
    def phase(self) -> MessagePhase:
        return self._phase

    @phase.setter
    def phase(self, phase: MessagePhase):
        self._phase = phase
        self._phase_update_time = 0 if phase == MessagePhase.WAITING else time.time()

    @property
    def phase_update_time(self) -> float:
        return self._phase_update_time

    @property
    def message(self) -> Message:
        return self._message

    @property
    def id(self) -> int:
        return self._message.id

    @property
    def seq(self) -> int:
        return self._message.seq

    @seq.setter
    def seq(self, seq: int):
        self._message.seq = seq

    def __repr__(self):
        return f'<{__name__}.{self.__class__.__name__} message={self._message.__repr__()}>'


# Connection stuff
# Well, strictly speaking, as it's UDP, there's no connection, but who cares.
# ---------------------------------------------------------------------------

class IncomingMessageListener:
    @abstractmethod
    def incoming_message(self, message: Message) -> Optional[Message]:
        pass


class ConnectionStatus(Enum):
    NOT_CONNECTED = auto()
    CONNECTING = auto()
    CONNECTED = auto()
    RECONNECTING = auto()
    DISCONNECTED = auto()


class ConnectionStatusListener:
    @abstractmethod
    def connection_status_updated(self, status: ConnectionStatus):
        pass


class UDPConnection(threading.Thread, ConnectionStatusListener):
    inseq: int
    outseq: int
    source_port: int
    device_addr: str
    device_port: int
    device_token: bytes
    device_pubkey: bytes
    interrupted: bool
    response_handlers: Dict[int, WrappedMessage]
    outgoing_queue: List[WrappedMessage]
    pubkey: Optional[bytes]
    encinkey: Optional[bytes]
    encoutkey: Optional[bytes]
    inc_listeners: List[IncomingMessageListener]
    conn_listeners: List[ConnectionStatusListener]
    outgoing_time: float
    outgoing_time_1st: float
    incoming_time: float
    status: ConnectionStatus
    reconnect_tries: int
    read_timeout: int

    _addr_lock: threading.Lock
    _iml_lock: threading.Lock
    _csl_lock: threading.Lock
    _st_lock: threading.Lock

    def __init__(self,
                 addr: Union[IPv4Address, IPv6Address],
                 port: int,
                 device_pubkey: bytes,
                 device_token: bytes,
                 read_timeout: int = 1):
        super().__init__()
        self._logger = logging.getLogger(f'{__name__}.{self.__class__.__name__} <{hex(id(self))}>')
        self.setName(self.__class__.__name__)

        self.inseq = 0
        self.outseq = 0
        self.source_port = random.randint(1024, 65535)
        self.device_addr = str(addr)
        self.device_port = port
        self.device_token = device_token
        self.device_pubkey = device_pubkey
        self.outgoing_queue = []
        self.response_handlers = {}
        self.interrupted = False
        self.outgoing_time = 0
        self.outgoing_time_1st = 0
        self.incoming_time = 0
        self.inc_listeners = []
        self.conn_listeners = [self]
        self.status = ConnectionStatus.NOT_CONNECTED
        self.reconnect_tries = 0
        self.read_timeout = read_timeout

        self._iml_lock = threading.Lock()
        self._csl_lock = threading.Lock()
        self._addr_lock = threading.Lock()
        self._st_lock = threading.Lock()

        self.pubkey = None
        self.encinkey = None
        self.encoutkey = None

    def connection_status_updated(self, status: ConnectionStatus):
        # self._logger.info(f'connection_status_updated: status = {status}')
        with self._st_lock:
            # self._logger.debug(f'connection_status_updated: lock acquired')
            self.status = status
            if status == ConnectionStatus.RECONNECTING:
                self.reconnect_tries += 1
            if status in (ConnectionStatus.CONNECTED, ConnectionStatus.NOT_CONNECTED, ConnectionStatus.DISCONNECTED):
                self.reconnect_tries = 0

    def _cleanup(self):
        # erase outgoing queue
        for wm in self.outgoing_queue:
            wm.call(False,
                    error_message=f'_cleanup: exception while calling cb(False) on message {wm.message}')
        self.outgoing_queue = []
        self.response_handlers = {}

        # reset timestamps
        self.incoming_time = 0
        self.outgoing_time = 0
        self.outgoing_time_1st = 0

        self._logger.debug('_cleanup: done')

    def set_address(self, addr: Union[IPv4Address, IPv6Address], port: int):
        with self._addr_lock:
            if self.device_addr != str(addr) or self.device_port != port:
                self.device_addr = str(addr)
                self.device_port = port
                self._logger.info(f'updated device network address: {self.device_addr}:{self.device_port}')

    def set_device_pubkey(self, pubkey: bytes):
        if self.device_pubkey.hex() != pubkey.hex():
            self._logger.info(f'device pubkey has changed (old={self.device_pubkey.hex()}, new={pubkey.hex()})')
            self.device_pubkey = pubkey
            self._notify_cs(ConnectionStatus.RECONNECTING)

    def get_address(self) -> Tuple[str, int]:
        with self._addr_lock:
            return self.device_addr, self.device_port

    def add_incoming_message_listener(self, listener: IncomingMessageListener):
        with self._iml_lock:
            if listener not in self.inc_listeners:
                self.inc_listeners.append(listener)

    def add_connection_status_listener(self, listener: ConnectionStatusListener):
        with self._csl_lock:
            if listener not in self.conn_listeners:
                self.conn_listeners.append(listener)

    def _notify_cs(self, status: ConnectionStatus):
        # self._logger.debug(f'_notify_cs: status={status}')
        with self._csl_lock:
            for obj in self.conn_listeners:
                # self._logger.debug(f'_notify_cs: notifying {obj}')
                obj.connection_status_updated(status)

    def _prepare_keys(self):
        # generate key pair
        privkey = X25519PrivateKey.generate()

        self.pubkey = bytes(reversed(privkey.public_key().public_bytes(encoding=srlz.Encoding.Raw,
                                                                       format=srlz.PublicFormat.Raw)))

        # generate shared key
        device_pubkey = X25519PublicKey.from_public_bytes(
            bytes(reversed(self.device_pubkey))
        )
        shared_key = bytes(reversed(
            privkey.exchange(device_pubkey)
        ))

        # in/out encryption keys
        digest = hashes.Hash(hashes.SHA256())
        digest.update(shared_key)

        shared_sha256 = digest.finalize()

        self.encinkey = shared_sha256[:16]
        self.encoutkey = shared_sha256[16:]

        self._logger.info('encryption keys have been created')

    def _handshake_callback(self, r: MessageResponse):
        # if got error for our HandshakeMessage, reset everything and try again
        if r is False:
            # self._logger.debug('_handshake_callback: set status=RECONNETING')
            self._notify_cs(ConnectionStatus.RECONNECTING)
        else:
            # self._logger.debug('_handshake_callback: set status=CONNECTED')
            self._notify_cs(ConnectionStatus.CONNECTED)

    def run(self):
        self._logger.info('starting server loop')

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('0.0.0.0', self.source_port))
        sock.settimeout(self.read_timeout)

        while not self.interrupted:
            with self._st_lock:
                status = self.status

            if status in (ConnectionStatus.DISCONNECTED, ConnectionStatus.RECONNECTING):
                self._cleanup()
                if status == ConnectionStatus.DISCONNECTED:
                    break

            # no activity for some time means connection is broken
            fail = False
            fail_path = 0
            if self.incoming_time > 0 and time.time() - self.incoming_time >= DISCONNECT_TIMEOUT:
                fail = True
                fail_path = 1
            elif self.outgoing_time_1st > 0 and self.incoming_time == 0 and time.time() - self.outgoing_time_1st >= DISCONNECT_TIMEOUT:
                fail = True
                fail_path = 2

            if fail:
                self._logger.debug(f'run: setting status=RECONNECTING because of long inactivity, fail_path={fail_path}')
                self._notify_cs(ConnectionStatus.RECONNECTING)

            # establishing a connection
            if status in (ConnectionStatus.RECONNECTING, ConnectionStatus.NOT_CONNECTED):
                if status == ConnectionStatus.RECONNECTING and self.reconnect_tries >= 3:
                    self._notify_cs(ConnectionStatus.DISCONNECTED)
                    continue

                self._reset_outseq()
                self._prepare_keys()

                # shake the imaginary kettle's hand
                wrapped = WrappedMessage(HandshakeMessage(),
                                         handler=self._handshake_callback,
                                         validator=lambda m: isinstance(m, (AckMessage, HandshakeResponseMessage)))
                self.enqueue_message(wrapped, prepend=True)
                self._notify_cs(ConnectionStatus.CONNECTING)

            # pick next (wrapped) message to send
            wm = self._get_next_message()  # wm means "wrapped message"
            if wm:
                one_shot = isinstance(wm.message, (AckMessage, NakMessage))

                if not isinstance(wm.message, (AckMessage, NakMessage)):
                    old_seq = wm.seq
                    wm.seq = self.outseq
                    self._set_response_handler(wm, old_seq=old_seq)
                elif wm.seq is None:
                    # ack/nak is a response to some incoming message (and it must have the same seqno that incoming
                    # message had)
                    raise RuntimeError(f'run: seq must be set for {wm.__class__.__name__}')

                self._logger.debug(f'run: sending message: {wm.message}, one_shot={one_shot}, phase={wm.phase}')
                encrypted = False
                try:
                    wm.message.encrypt(outkey=self.encoutkey, inkey=self.encinkey,
                                       token=self.device_token, pubkey=self.pubkey)
                    encrypted = True
                except ValueError as exc:
                    # handle "ValueError: Invalid padding bytes."
                    self._logger.error('run: failed to encrypt the message.')
                    self._logger.exception(exc)

                if encrypted:
                    buf = wm.message.frame.pack()
                    # self._logger.debug(f'run: raw data to be sent: {buf.hex()}')

                    # sending the first time
                    if wm.phase == MessagePhase.WAITING:
                        sock.sendto(buf, self.get_address())
                    # resending
                    elif wm.phase == MessagePhase.SENT:
                        left = RESEND_ATTEMPTS
                        while left > 0:
                            sock.sendto(buf, self.get_address())
                            left -= 1
                            if left > 0:
                                time.sleep(0.05)

                    if one_shot or wm.phase == MessagePhase.SENT:
                        wm.phase = MessagePhase.DONE
                    else:
                        wm.phase = MessagePhase.SENT

                    now = time.time()
                    self.outgoing_time = now
                    if not self.outgoing_time_1st:
                        self.outgoing_time_1st = now

            # receiving data
            try:
                data = sock.recv(4096)
                self._handle_incoming(data)
            except (TimeoutError, socket.timeout):
                pass

        self._logger.info('bye...')

    def _get_next_message(self) -> Optional[WrappedMessage]:
        message = None
        lpfx = '_get_next_message:'
        remove_list = []
        for wm in self.outgoing_queue:
            if wm.phase == MessagePhase.DONE:
                if isinstance(wm.message, (AckMessage, NakMessage, PingMessage)) or time.time() - wm.phase_update_time >= MESSAGE_QUEUE_REMOVE_DELAY:
                    remove_list.append(wm)
                continue
            message = wm
            break

        for wm in remove_list:
            self._logger.debug(f'{lpfx} rm path: removing id={wm.id} seq={wm.seq}')

            # clear message handler
            if wm.seq in self.response_handlers:
                self.response_handlers[wm.seq].call(
                    False, error_message=f'{lpfx} rm path: error while calling callback for seq={wm.seq}')
                del self.response_handlers[wm.seq]

            # remove from queue
            try:
                self.outgoing_queue.remove(wm)
            except ValueError as exc:
                self._logger.error(f'{lpfx} rm path: removing from outgoing_queue raised an exception: {str(exc)}')

        # ping pong
        if not message and self.outgoing_time_1st != 0 and self.status == ConnectionStatus.CONNECTED:
            now = time.time()
            out_delta = now - self.outgoing_time
            in_delta = now - self.incoming_time
            if max(out_delta, in_delta) > PING_FREQUENCY:
                self._logger.debug(f'{lpfx} no activity: in for {in_delta:.2f}s, out for {out_delta:.2f}s, time to ping the damn thing')
                message = WrappedMessage(PingMessage(), ack=True)
                # add it to outgoing_queue in order to be aggressively resent in future (if needed)
                self.outgoing_queue.insert(0, message)

        return message

    def _handle_incoming(self, buf: bytes):
        try:
            incoming_message = Message.from_encrypted(buf, inkey=self.encinkey, outkey=self.encoutkey)
        except ValueError as exc:
            # handle "ValueError: Invalid padding bytes."
            self._logger.error('_handle_incoming: failed to decrypt incoming frame:')
            self._logger.exception(exc)
            return

        self.incoming_time = time.time()
        seq = incoming_message.seq

        lpfx = f'handle_incoming({incoming_message.id}):'
        self._logger.debug(f'{lpfx} received: {incoming_message}')

        if isinstance(incoming_message, (AckMessage, NakMessage)):
            seq_max = self.outseq
            seq_name = 'outseq'
        else:
            seq_max = self.inseq
            seq_name = 'inseq'
            self.inseq = seq

        if seq < seq_max < 0xfd:
            self._logger.warning(f'{lpfx} dropping: seq={seq}, {seq_name}={seq_name}')
            return

        if seq not in self.response_handlers:
            self._handle_incoming_cmd(incoming_message)
            return

        callback_value = None  # None means don't call a callback
        handler = self.response_handlers[seq]

        if handler.validate(incoming_message):
            self._logger.debug(f'{lpfx} response OK')
            handler.phase = MessagePhase.DONE
            callback_value = incoming_message
            self._incr_outseq()
        else:
            self._logger.warning(f'{lpfx} response is INVALID')

            # It seems that we've received an incoming CmdMessage or PingMessage with the same seqno that our outgoing
            # message had. Bad, but what can I say, this is quick-and-dirty made UDP based protocol and this sort of
            # shit just happens.

            # (To be fair, maybe my implementation is not perfect either. But hey, what did you expect from a
            # reverse-engineered re-implementation of custom UDP-based protocol that some noname vendor uses for their
            # cheap IoT devices? I think _that_ is _the_ definition of shit. At least my implementation is FOSS, which
            # is more than you'll ever be able to say about them.)

            # All this crapload of code below might not be needed at all, 'cause the protocol uses separate frame seq
            # numbers for IN and OUT frames and this situation is not highly likely, as Theresa May could argue.
            # After a handshake, a kettle sends us 10 or so CmdMessages, and then either we continuously ping it every
            # 3 seconds, or kettle pings us. This in any case widens the gap between inseq and outseq.

            # But! the seqno is only 1 byte in size and once it reaches 0xff, it circles back to zero. And that (plus,
            # perhaps, some bad luck) gives a chance for a collision.

            if handler.phase == MessagePhase.DONE or isinstance(handler.message, HandshakeMessage):
                # no more attempts left, returning error back to user
                # as to handshake, it cannot fail.
                callback_value = False

            # else:
            #     # try resending the message
            #     handler.phase_reset()
            #     max_seq = self.outseq
            #     wait_remap = {}
            #     for m in self.outgoing_queue:
            #         if m.seq in self.waiting_for_response:
            #             wait_remap[m.seq] = (m.seq+1) % 256
            #         m.set_seq((m.seq+1) % 256)
            #         if m.seq > max_seq:
            #             max_seq = m.seq
            #     if max_seq > self.outseq:
            #         self.outseq = max_seq % 256
            #     if wait_remap:
            #         waiting_new = {}
            #         for old_seq, new_seq in wait_remap.items():
            #             waiting_new[new_seq] = self.waiting_for_response[old_seq]
            #         self.waiting_for_response = waiting_new

            if isinstance(incoming_message, (PingMessage, CmdIncomingMessage)):
                # handle incoming message as usual, as we need to ack/nak it anyway
                self._handle_incoming_cmd(incoming_message)

        if callback_value is not None:
            handler.call(callback_value,
                         error_message=f'{lpfx} error while calling callback for msg id={handler.message.id} seq={seq}')
            del self.response_handlers[seq]

    def _handle_incoming_cmd(self, incoming_message: Message):
        if isinstance(incoming_message, (AckMessage, NakMessage)):
            self._logger.debug(f'_handle_incoming_cmd({incoming_message.id}, seq={incoming_message.seq}): it\'s {incoming_message.__class__.__name__}, ignoring')
            return

        replied = False
        with self._iml_lock:
            for f in self.inc_listeners:
                retval = safe_callback_call(f.incoming_message, incoming_message,
                                            logger=self._logger,
                                            error_message=f'_handle_incoming_cmd({incoming_message.id}, seq={incoming_message.seq}): error while calling message listener')
                if isinstance(retval, Message):
                    if isinstance(retval, (AckMessage, NakMessage)):
                        retval.seq = incoming_message.seq
                        self.enqueue_message(WrappedMessage(retval), prepend=True)
                        replied = True
                        break
                    else:
                        raise RuntimeError('are you sure your response is correct? only ack/nak are allowed')

        if not replied:
            self.enqueue_message(WrappedMessage(AckMessage(incoming_message.seq)), prepend=True)

    def enqueue_message(self, wrapped: WrappedMessage, prepend=False):
        self._logger.debug(f'enqueue_message: {wrapped.message}')
        if not prepend:
            self.outgoing_queue.append(wrapped)
        else:
            self.outgoing_queue.insert(0, wrapped)

    def _set_response_handler(self, wm: WrappedMessage, old_seq=None):
        if old_seq in self.response_handlers:
            del self.response_handlers[old_seq]

        seq = wm.seq
        assert seq is not None, 'seq is not set'

        if seq in self.response_handlers:
            self._logger.debug(f'_set_response_handler(seq={seq}): handler is already set, cancelling it')
            self.response_handlers[seq].call(False,
                                             error_message=f'_set_response_handler({seq}): error while calling old callback')
        self.response_handlers[seq] = wm

    def _incr_outseq(self) -> None:
        self.outseq = (self.outseq + 1) % 256

    def _reset_outseq(self):
        self.outseq = 0
        self._logger.debug(f'_reset_outseq: set 0')


MessageResponse = Union[Message, bool]
