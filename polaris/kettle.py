# Polaris PWK 1725CGLD smart kettle python library
# ------------------------------------------------
# Copyright (C) Evgeny Zinoviev, 2022
# License: BSD-3c

from __future__ import annotations

import threading
import logging
import zeroconf

from abc import abstractmethod
from ipaddress import ip_address, IPv4Address, IPv6Address
from typing import Optional, List, Union

from .protocol import (
    UDPConnection,
    ModeMessage,
    TargetTemperatureMessage,
    PowerType,
    ConnectionStatus,
    ConnectionStatusListener,
    WrappedMessage
)


class DeviceDiscover(threading.Thread, zeroconf.ServiceListener):
    si: Optional[zeroconf.ServiceInfo]
    _mac: str
    _sb: Optional[zeroconf.ServiceBrowser]
    _zc: Optional[zeroconf.Zeroconf]
    _listeners: List[DeviceListener]
    _valid_addresses: List[Union[IPv4Address, IPv6Address]]
    _only_ipv4: bool

    def __init__(self, mac: str,
                 listener: Optional[DeviceListener] = None,
                 only_ipv4=True):
        super().__init__()
        self.si = None
        self._mac = mac
        self._zc = None
        self._sb = None
        self._only_ipv4 = only_ipv4
        self._valid_addresses = []
        self._listeners = []
        if isinstance(listener, DeviceListener):
            self._listeners.append(listener)
        self._logger = logging.getLogger(f'{__name__}.{self.__class__.__name__}')

    def add_listener(self, listener: DeviceListener):
        if listener not in self._listeners:
            self._listeners.append(listener)
        else:
            self._logger.warning(f'add_listener: listener {listener} already in the listeners list')

    def set_info(self, info: zeroconf.ServiceInfo):
        valid_addresses = self._get_valid_addresses(info)
        if not valid_addresses:
            raise ValueError('no valid addresses')
        self._valid_addresses = valid_addresses
        self.si = info
        for f in self._listeners:
            try:
                f.device_updated()
            except Exception as exc:
                self._logger.error(f'set_info: error while calling device_updated on {f}')
                self._logger.exception(exc)

    def add_service(self, zc: zeroconf.Zeroconf, type_: str, name: str) -> None:
        self._add_update_service('add_service', zc, type_, name)

    def update_service(self, zc: zeroconf.Zeroconf, type_: str, name: str) -> None:
        self._add_update_service('update_service', zc, type_, name)

    def _add_update_service(self, method: str, zc: zeroconf.Zeroconf, type_: str, name: str) -> None:
        info = zc.get_service_info(type_, name)
        if name.startswith(f'{self._mac}.'):
            self._logger.info(f'{method}: type={type_} name={name}')
            try:
                self.set_info(info)
            except ValueError as exc:
                self._logger.error(f'{method}: rejected: {str(exc)}')
        else:
            self._logger.debug(f'{method}: mac not matched: {info}')

    def remove_service(self, zc: zeroconf.Zeroconf, type_: str, name: str) -> None:
        if name.startswith(f'{self._mac}.'):
            self._logger.info(f'remove_service: type={type_} name={name}')
            # TODO what to do here?!

    def run(self):
        self._logger.debug('starting zeroconf service browser')
        ip_version = zeroconf.IPVersion.V4Only if self._only_ipv4 else zeroconf.IPVersion.All
        self._zc = zeroconf.Zeroconf(ip_version=ip_version)
        self._sb = zeroconf.ServiceBrowser(self._zc, "_syncleo._udp.local.", self)
        self._sb.join()

    def stop(self):
        if self._sb:
            try:
                self._sb.cancel()
            except RuntimeError:
                pass
            self._sb = None
        self._zc.close()
        self._zc = None

    def _get_valid_addresses(self, si: zeroconf.ServiceInfo) -> List[Union[IPv4Address, IPv6Address]]:
        valid = []
        for addr in map(ip_address, si.addresses):
            if self._only_ipv4 and not isinstance(addr, IPv4Address):
                continue
            if isinstance(addr, IPv4Address) and str(addr).startswith('169.254.'):
                continue
            valid.append(addr)
        return valid

    @property
    def pubkey(self) -> bytes:
        return bytes.fromhex(self.si.properties[b'public'].decode())

    @property
    def curve(self) -> int:
        return int(self.si.properties[b'curve'].decode())

    @property
    def addr(self) -> Union[IPv4Address, IPv6Address]:
        return self._valid_addresses[0]

    @property
    def port(self) -> int:
        return int(self.si.port)

    @property
    def protocol(self) -> int:
        return int(self.si.properties[b'protocol'].decode())


class DeviceListener:
    @abstractmethod
    def device_updated(self):
        pass


class Kettle(DeviceListener, ConnectionStatusListener):
    mac: str
    device: Optional[DeviceDiscover]
    device_token: str
    conn: Optional[UDPConnection]
    conn_status: Optional[ConnectionStatus]
    _logger: logging.Logger
    _find_evt: threading.Event

    def __init__(self, mac: str, device_token: str):
        super().__init__()
        self.mac = mac
        self.device = None
        self.device_token = device_token
        self.conn = None
        self.conn_status = None
        self._find_evt = threading.Event()
        self._logger = logging.getLogger(f'{__name__}.{self.__class__.__name__}')

    def device_updated(self):
        self._find_evt.set()
        self._logger.info(f'device updated, service info: {self.device.si}')

    def connection_status_updated(self, status: ConnectionStatus):
        self.conn_status = status

    def discover(self, wait=True, timeout=None, listener=None) -> Optional[zeroconf.ServiceInfo]:
        do_start = False
        if not self.device:
            self.device = DeviceDiscover(self.mac, listener=self, only_ipv4=True)
            do_start = True
            self._logger.debug('discover: started device discovery')
        else:
            self._logger.warning('discover: already started')

        if listener is not None:
            self.device.add_listener(listener)

        if do_start:
            self.device.start()

        if wait:
            self._find_evt.clear()
            try:
                self._find_evt.wait(timeout=timeout)
            except KeyboardInterrupt:
                self.device.stop()
                return None
            return self.device.si

    def start_server_if_needed(self,
                               incoming_message_listener=None,
                               connection_status_listener=None):
        if self.conn:
            self._logger.warning('start_server_if_needed: server is already started!')
            self.conn.set_address(self.device.addr, self.device.port)
            self.conn.set_device_pubkey(self.device.pubkey)
            return

        assert self.device.curve == 29, f'curve type {self.device.curve} is not implemented'
        assert self.device.protocol == 2, f'protocol {self.device.protocol} is not supported'

        self.conn = UDPConnection(addr=self.device.addr,
                                  port=self.device.port,
                                  device_pubkey=self.device.pubkey,
                                  device_token=bytes.fromhex(self.device_token))
        if incoming_message_listener:
            self.conn.add_incoming_message_listener(incoming_message_listener)

        self.conn.add_connection_status_listener(self)
        if connection_status_listener:
            self.conn.add_connection_status_listener(connection_status_listener)

        self.conn.start()

    def stop_all(self):
        # when we stop server, we should also stop device discovering service
        if self.conn:
            self.conn.interrupted = True
            self.conn = None
        self.device.stop()
        self.device = None

    def is_connected(self) -> bool:
        return self.conn is not None and self.conn_status == ConnectionStatus.CONNECTED

    def set_power(self, power_type: PowerType, callback: callable):
        message = ModeMessage(power_type)
        self.conn.enqueue_message(WrappedMessage(message, handler=callback, ack=True))

    def set_target_temperature(self, temp: int, callback: callable):
        message = TargetTemperatureMessage(temp)
        self.conn.enqueue_message(WrappedMessage(message, handler=callback, ack=True))
