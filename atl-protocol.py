import socket
import struct
import os
import time
import hashlib
import hmac
from collections import deque, defaultdict, OrderedDict
from enum import IntEnum
from typing import Optional, Tuple, Union, Dict, Deque, Callable, Any, List
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import threading
import select
import zlib
import random
import bisect
import math
import logging
import heapq
from dataclasses import dataclass

PROTOCOL_VERSION = 0x02
HEADER_SIZE = 32
MAX_SEQ = 0xFFFFFFFF
INITIAL_WINDOW = 8
MAX_WINDOW = 1024
MIN_RTO = 0.2
MAX_RTO = 60.0
INITIAL_RTT = 0.5
RTT_VAR = 0.25
HEARTBEAT_INTERVAL = 5.0
CONNECTION_TIMEOUT = 30.0
MAX_RETRANSMITS = 8
STREAM_BUFFER_SIZE = 1024 * 1024

class ATL:
    class Mode(IntEnum):
        UNRELIABLE = 0
        RELIABLE = 1
        ORDERED = 2
        STREAM = 3

    class PacketType(IntEnum):
        DATA = 0
        ACK = 1
        SYN = 2
        SYN_ACK = 3
        FIN = 4
        RST = 5
        HEARTBEAT = 6
        WINDOW_UPDATE = 7

    class ConnectionState(IntEnum):
        CLOSED = 0
        LISTEN = 1
        SYN_SENT = 2
        SYN_RECEIVED = 3
        ESTABLISHED = 4
        FIN_WAIT_1 = 5
        FIN_WAIT_2 = 6
        CLOSING = 7
        TIME_WAIT = 8
        CLOSE_WAIT = 9
        LAST_ACK = 10

    @dataclass
    class Packet:
        seq: int
        ack: int
        data: bytes
        timestamp: float
        retransmits: int = 0
        size: int = 0

    def __init__(self, mode: Mode = Mode.RELIABLE, port: int = 5699, 
                 mtu: int = 1400, auto_retry: bool = True, logger=None):
        self.mode = mode
        self.port = port
        self.mtu = mtu
        self.auto_retry = auto_retry
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('0.0.0.0', port))
        self.sock.setblocking(False)
        self.connections: Dict[Tuple[str, int], Any] = {}
        self.running = False
        self.sequence_num = random.randint(0, MAX_SEQ)
        self.crypto_ctx = self._init_crypto()
        self.send_lock = threading.Lock()
        self.recv_lock = threading.Lock()
        self.worker_thread = threading.Thread(target=self._network_worker)
        self.worker_thread.daemon = True
        self.logger = logger or logging.getLogger('ATL')
        self.callbacks = {
            'connect': None,
            'disconnect': None,
            'data': None,
            'error': None,
            'stream_data': None
        }
        self.stream_buffers: Dict[Tuple[str, int], Dict[str, Any]] = defaultdict(
            lambda: {
                'buffer': bytearray(),
                'expected_seq': 0,
                'out_of_order': {},
                'last_assembled': 0
            }
        )

    def _init_crypto(self) -> Dict[str, Any]:
        key_material = os.urandom(64)
        hkdf = HKDF(
            algorithm=hashes.SHA512(),
            length=96,
            salt=None,
            info=b'atl_protocol_key_derivation',
            backend=default_backend()
        )
        keys = hkdf.derive(key_material)
        return {
            'enc_key': keys[:32],
            'dec_key': keys[32:64],
            'mac_key': keys[64:],
            'send_nonce': 0,
            'recv_nonce': 0
        }

    def _encrypt_packet(self, data: bytes) -> bytes:
        nonce = self.crypto_ctx['send_nonce'].to_bytes(12, 'big')
        cipher = Cipher(algorithms.AES(self.crypto_ctx['enc_key']), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(data) + encryptor.finalize()
        self.crypto_ctx['send_nonce'] += 1
        return nonce + encrypted + encryptor.tag

    def _decrypt_packet(self, data: bytes) -> Optional[bytes]:
        if len(data) < 28: return None
        nonce = data[:12]
        tag = data[-16:]
        encrypted = data[12:-16]
        cipher = Cipher(algorithms.AES(self.crypto_ctx['dec_key']), modes.GCM(nonce, tag), backend=default_backend())
        try:
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(encrypted) + decryptor.finalize()
            self.crypto_ctx['recv_nonce'] += 1
            return decrypted
        except:
            return None

    def _pack_packet(self, ptype: PacketType, seq: int, ack: int, data: bytes = b'', window: int = 0) -> bytes:
        flags = (self.mode << 4) | ptype
        checksum = 0
        header = struct.pack('!BBHIIIIQ', PROTOCOL_VERSION, flags, checksum, seq, ack, len(data), window, 0)
        full_packet = header + data
        checksum = zlib.crc32(full_packet)
        header = struct.pack('!BBHIIIIQ', PROTOCOL_VERSION, flags, checksum & 0xFFFF, seq, ack, len(data), window, 0)
        return self._encrypt_packet(header + data)

    def _unpack_packet(self, data: bytes) -> Optional[Tuple[PacketType, int, int, int, bytes]]:
        decrypted = self._decrypt_packet(data)
        if not decrypted or len(decrypted) < HEADER_SIZE: return None
        
        version, flags, checksum, seq, ack, length, window, reserved = struct.unpack('!BBHIIIIQ', decrypted[:HEADER_SIZE])
        if version != PROTOCOL_VERSION: return None
        
        header = decrypted[:HEADER_SIZE]
        received_checksum = checksum
        header_with_zero_checksum = header[:2] + b'\x00\x00' + header[4:]
        calculated_checksum = zlib.crc32(header_with_zero_checksum + decrypted[HEADER_SIZE:HEADER_SIZE+length])
        if (calculated_checksum & 0xFFFF) != received_checksum: return None
        
        ptype = PacketType(flags & 0x0F)
        mode = Mode((flags >> 4) & 0x0F)
        return (ptype, seq, ack, window, decrypted[HEADER_SIZE:HEADER_SIZE+length])

    def start(self):
        self.running = True
        self.worker_thread.start()
        self.logger.info("ATL Protocol started on port %d", self.port)

    def stop(self):
        self.running = False
        for addr in list(self.connections.keys()):
            self.disconnect(addr)
        self.worker_thread.join()
        self.sock.close()
        self.logger.info("ATL Protocol stopped")

    def connect(self, addr: Tuple[str, int]):
        with self.send_lock:
            if addr in self.connections:
                return
            
            self.sequence_num = (self.sequence_num + 1) % MAX_SEQ
            syn_packet = self._pack_packet(self.PacketType.SYN, self.sequence_num, 0)
            self.sock.sendto(syn_packet, addr)
            
            conn = {
                'state': self.ConnectionState.SYN_SENT,
                'addr': addr,
                'seq': self.sequence_num,
                'ack': 0,
                'send_queue': deque(),
                'retransmit_queue': OrderedDict(),
                'retransmit_count': defaultdict(int),
                'recv_queue': deque(),
                'ack_queue': set(),
                'last_activity': time.time(),
                'window': INITIAL_WINDOW,
                'peer_window': INITIAL_WINDOW,
                'rtt': INITIAL_RTT,
                'rtt_var': RTT_VAR,
                'rto': INITIAL_RTT + 4 * RTT_VAR,
                'congestion_window': 1,
                'ssthresh': MAX_WINDOW,
                'flight_size': 0,
                'partial_ack': 0,
                'stream_buffer': bytearray(),
                'stream_seq': 0,
                'out_of_order': {}
            }
            conn['retransmit_queue'][self.sequence_num] = self.Packet(
                seq=self.sequence_num,
                ack=0,
                data=b'',
                timestamp=time.time(),
                size=len(syn_packet)
            )
            self.connections[addr] = conn
            self.logger.debug("Connecting to %s:%d", addr[0], addr[1])

    def disconnect(self, addr: Tuple[str, int]):
        with self.send_lock:
            if addr not in self.connections:
                return
            
            conn = self.connections[addr]
            if conn['state'] in [self.ConnectionState.ESTABLISHED, self.ConnectionState.CLOSE_WAIT]:
                self.sequence_num = (self.sequence_num + 1) % MAX_SEQ
                fin_packet = self._pack_packet(self.PacketType.FIN, self.sequence_num, conn['ack'])
                self.sock.sendto(fin_packet, addr)
                conn['state'] = self.ConnectionState.FIN_WAIT_1
                conn['retransmit_queue'][self.sequence_num] = self.Packet(
                    seq=self.sequence_num,
                    ack=conn['ack'],
                    data=b'',
                    timestamp=time.time(),
                    size=len(fin_packet)
                )
                self.logger.debug("Disconnecting from %s:%d", addr[0], addr[1])
            else:
                self._terminate_connection(conn, 'forced')

    def send(self, addr: Tuple[str, int], data: bytes):
        if addr not in self.connections:
            self.connect(addr)
            time.sleep(0.1)
        
        with self.send_lock:
            conn = self.connections.get(addr)
            if not conn or conn['state'] != self.ConnectionState.ESTABLISHED:
                return
            
            if self.mode == self.Mode.STREAM:
                conn['send_queue'].append(data)
            else:
                if len(data) > self.mtu - HEADER_SIZE:
                    chunks = [data[i:i+self.mtu-HEADER_SIZE] for i in range(0, len(data), self.mtu-HEADER_SIZE)]
                    for chunk in chunks:
                        conn['send_queue'].append(chunk)
                else:
                    conn['send_queue'].append(data)

    def recv(self) -> Optional[Tuple[Tuple[str, int], bytes]]:
        with self.recv_lock:
            for addr, conn in self.connections.items():
                if conn['recv_queue']:
                    return (addr, conn['recv_queue'].popleft())
        return None

    def _network_worker(self):
        while self.running:
            now = time.time()
            readable, _, _ = select.select([self.sock], [], [], 0.1)
            
            if readable:
                try:
                    data, addr = self.sock.recvfrom(65535)
                    self._handle_packet(addr, data, now)
                except Exception as e:
                    self.logger.error("Error receiving packet: %s", str(e))
                    continue
            
            self._process_retransmits(now)
            self._process_send_queues(now)
            self._process_heartbeats(now)
            self._process_timeouts(now)
            self._process_stream_assembly(now)

    def _handle_packet(self, addr: Tuple[str, int], data: bytes, now: float):
        packet = self._unpack_packet(data)
        if not packet:
            self.logger.debug("Invalid packet from %s:%d", addr[0], addr[1])
            return
        
        ptype, seq, ack, window, payload = packet
        
        if addr not in self.connections:
            if ptype == self.PacketType.SYN:
                self._handle_syn(addr, seq, window, now)
            return
        
        conn = self.connections[addr]
        conn['last_activity'] = now
        conn['peer_window'] = window
        
        if ptype == self.PacketType.ACK:
            self._handle_ack(conn, ack, now)
        elif ptype == self.PacketType.DATA:
            self._handle_data(conn, seq, payload, now)
        elif ptype == self.PacketType.FIN:
            self._handle_fin(conn, seq, now)
        elif ptype == self.PacketType.RST:
            self._handle_rst(conn)
        elif ptype == self.PacketType.HEARTBEAT:
            self._handle_heartbeat(conn, now)
        elif ptype == self.PacketType.SYN_ACK:
            self._handle_syn_ack(conn, seq, now)
        elif ptype == self.PacketType.WINDOW_UPDATE:
            self._handle_window_update(conn, window)

    def _handle_syn(self, addr: Tuple[str, int], seq: int, window: int, now: float):
        with self.send_lock:
            self.sequence_num = (self.sequence_num + 1) % MAX_SEQ
            syn_ack = self._pack_packet(self.PacketType.SYN_ACK, self.sequence_num, seq + 1, window=INITIAL_WINDOW)
            self.sock.sendto(syn_ack, addr)
            
            conn = {
                'state': self.ConnectionState.SYN_RECEIVED,
                'addr': addr,
                'seq': self.sequence_num,
                'ack': seq + 1,
                'send_queue': deque(),
                'retransmit_queue': OrderedDict(),
                'retransmit_count': defaultdict(int),
                'recv_queue': deque(),
                'ack_queue': set(),
                'last_activity': now,
                'window': INITIAL_WINDOW,
                'peer_window': window,
                'rtt': INITIAL_RTT,
                'rtt_var': RTT_VAR,
                'rto': INITIAL_RTT + 4 * RTT_VAR,
                'congestion_window': 1,
                'ssthresh': MAX_WINDOW,
                'flight_size': 0,
                'partial_ack': 0,
                'stream_buffer': bytearray(),
                'stream_seq': 0,
                'out_of_order': {}
            }
            conn['retransmit_queue'][self.sequence_num] = self.Packet(
                seq=self.sequence_num,
                ack=seq + 1,
                data=b'',
                timestamp=now,
                size=len(syn_ack)
            )
            self.connections[addr] = conn
            self.logger.debug("Received SYN from %s:%d", addr[0], addr[1])

    def _handle_syn_ack(self, conn: Dict[str, Any], seq: int, now: float):
        if conn['state'] != self.ConnectionState.SYN_SENT:
            return
        
        with self.send_lock:
            self._update_rtt(conn, now - conn['retransmit_queue'][conn['seq']].timestamp)
            conn['ack'] = seq
            conn['state'] = self.ConnectionState.ESTABLISHED
            conn['retransmit_queue'].pop(conn['seq'], None)
            
            if self.callbacks['connect']:
                self.callbacks['connect'](conn['addr'])
            
            self.logger.debug("Connection established with %s:%d", conn['addr'][0], conn['addr'][1])

    def _handle_ack(self, conn: Dict[str, Any], ack: int, now: float):
        if conn['state'] not in [self.ConnectionState.ESTABLISHED, self.ConnectionState.FIN_WAIT_1, 
                               self.ConnectionState.FIN_WAIT_2, self.ConnectionState.CLOSING]:
            return
        
        with self.send_lock:
            new_ack = False
            for seq in list(conn['retransmit_queue'].keys()):
                if seq <= ack:
                    packet = conn['retransmit_queue'].pop(seq, None)
                    if packet:
                        self._update_rtt(conn, now - packet.timestamp)
                        conn['flight_size'] -= packet.size
                        new_ack = True
            
            if new_ack:
                if conn['congestion_window'] < conn['ssthresh']:
                    conn['congestion_window'] += 1
                else:
                    conn['congestion_window'] += 1 / conn['congestion_window']
                
                if conn['state'] == self.ConnectionState.FIN_WAIT_1 and ack == conn['seq']:
                    conn['state'] = self.ConnectionState.FIN_WAIT_2
                elif conn['state'] == self.ConnectionState.CLOSING and ack == conn['seq']:
                    self._terminate_connection(conn, 'normal')
            
            if ack > conn['ack']:
                conn['ack'] = ack
                if self.auto_retry and conn['send_queue']:
                    self._send_queued_data(conn, now)

    def _handle_data(self, conn: Dict[str, Any], seq: int, data: bytes, now: float):
        if conn['state'] != self.ConnectionState.ESTABLISHED:
            return
        
        expected_seq = conn['ack']
        if seq == expected_seq:
            conn['ack'] = (conn['ack'] + len(data)) % MAX_SEQ
            if self.mode == self.Mode.STREAM:
                conn['stream_buffer'] += data
                if self.callbacks['stream_data']:
                    self.callbacks['stream_data'](conn['addr'], bytes(conn['stream_buffer']))
                    conn['stream_buffer'] = bytearray()
            else:
                with self.recv_lock:
                    conn['recv_queue'].append(data)
            
            while conn['ack'] in conn['out_of_order']:
                data = conn['out_of_order'].pop(conn['ack'])
                conn['ack'] = (conn['ack'] + len(data)) % MAX_SEQ
                if self.mode == self.Mode.STREAM:
                    conn['stream_buffer'] += data
                    if self.callbacks['stream_data']:
                        self.callbacks['stream_data'](conn['addr'], bytes(conn['stream_buffer']))
                        conn['stream_buffer'] = bytearray()
                else:
                    with self.recv_lock:
                        conn['recv_queue'].append(data)
        elif seq > expected_seq:
            if seq not in conn['out_of_order']:
                conn['out_of_order'][seq] = data
        
        ack_packet = self._pack_packet(self.PacketType.ACK, conn['seq'], conn['ack'], window=conn['window'])
        with self.send_lock:
            self.sock.sendto(ack_packet, conn['addr'])

    def _handle_fin(self, conn: Dict[str, Any], seq: int, now: float):
        if conn['state'] == self.ConnectionState.ESTABLISHED:
            conn['state'] = self.ConnectionState.CLOSE_WAIT
            conn['ack'] = (seq + 1) % MAX_SEQ
            fin_ack = self._pack_packet(self.PacketType.ACK, conn['seq'], conn['ack'])
            self.sock.sendto(fin_ack, conn['addr'])
            
            if self.callbacks['disconnect']:
                self.callbacks['disconnect'](conn['addr'], 'peer_initiated')
            
            self.logger.debug("Received FIN from %s:%d", conn['addr'][0], conn['addr'][1])
        elif conn['state'] == self.ConnectionState.FIN_WAIT_1:
            conn['state'] = self.ConnectionState.CLOSING
            conn['ack'] = (seq + 1) % MAX_SEQ
            fin_ack = self._pack_packet(self.PacketType.ACK, conn['seq'], conn['ack'])
            self.sock.sendto(fin_ack, conn['addr'])
        elif conn['state'] == self.ConnectionState.FIN_WAIT_2:
            conn['ack'] = (seq + 1) % MAX_SEQ
            fin_ack = self._pack_packet(self.PacketType.ACK, conn['seq'], conn['ack'])
            self.sock.sendto(fin_ack, conn['addr'])
            self._terminate_connection(conn, 'normal')

    def _handle_rst(self, conn: Dict[str, Any]):
        self._terminate_connection(conn, 'reset')

    def _handle_heartbeat(self, conn: Dict[str, Any], now: float):
        ack_packet = self._pack_packet(self.PacketType.ACK, conn['seq'], conn['ack'])
        with self.send_lock:
            self.sock.sendto(ack_packet, conn['addr'])

    def _handle_window_update(self, conn: Dict[str, Any], window: int):
        conn['peer_window'] = window

    def _process_retransmits(self, now: float):
        with self.send_lock:
            for addr, conn in list(self.connections.items()):
                to_retransmit = []
                
                for seq, packet in conn['retransmit_queue'].items():
                    if now - packet.timestamp > conn['rto']:
                        to_retransmit.append(seq)
                
                for seq in to_retransmit:
                    packet = conn['retransmit_queue'][seq]
                    if conn['retransmit_count'][seq] >= MAX_RETRANSMITS:
                        self._terminate_connection(conn, 'max_retries')
                        break
                    
                    self.sock.sendto(
                        self._pack_packet(
                            self.PacketType.DATA if packet.data else self.PacketType.FIN if conn['state'] in [
                                self.ConnectionState.FIN_WAIT_1, self.ConnectionState.LAST_ACK
                            ] else self.PacketType.SYN_ACK,
                            packet.seq,
                            packet.ack,
                            packet.data,
                            window=conn['window']
                        ),
                        conn['addr']
                    )
                    packet.timestamp = now
                    packet.retransmits += 1
                    conn['retransmit_count'][seq] += 1
                    
                    if conn['congestion_window'] > 1:
                        conn['ssthresh'] = max(conn['congestion_window'] / 2, 2)
                        conn['congestion_window'] = 1
                    
                    conn['rto'] = min(conn['rto'] * 2, MAX_RTO)
                    self.logger.debug("Retransmitting packet %d to %s:%d (attempt %d)", 
                                    seq, conn['addr'][0], conn['addr'][1], conn['retransmit_count'][seq])

    def _process_send_queues(self, now: float):
        with self.send_lock:
            for conn in self.connections.values():
                if conn['state'] != self.ConnectionState.ESTABLISHED:
                    continue
                
                while (conn['send_queue'] and 
                       len(conn['retransmit_queue']) < min(conn['congestion_window'], conn['peer_window']) and
                       conn['flight_size'] < conn['peer_window']):
                    data = conn['send_queue'].popleft()
                    self.sequence_num = (self.sequence_num + 1) % MAX_SEQ
                    packet = self._pack_packet(self.PacketType.DATA, self.sequence_num, conn['ack'], data, window=conn['window'])
                    self.sock.sendto(packet, conn['addr'])
                    
                    pkt = self.Packet(
                        seq=self.sequence_num,
                        ack=conn['ack'],
                        data=data,
                        timestamp=now,
                        size=len(packet)
                    )
                    conn['retransmit_queue'][self.sequence_num] = pkt
                    conn['flight_size'] += pkt.size
                    self.logger.debug("Sent packet %d to %s:%d (%d bytes)", 
                                    self.sequence_num, conn['addr'][0], conn['addr'][1], len(data))

    def _process_heartbeats(self, now: float):
        if now - getattr(self, '_last_heartbeat', 0) > HEARTBEAT_INTERVAL:
            self._last_heartbeat = now
            with self.send_lock:
                for addr, conn in list(self.connections.items()):
                    if conn['state'] != self.ConnectionState.ESTABLISHED:
                        continue
                    
                    if now - conn['last_activity'] > CONNECTION_TIMEOUT:
                        self._terminate_connection(conn, 'timeout')
                    else:
                        heartbeat = self._pack_packet(self.PacketType.HEARTBEAT, conn['seq'], conn['ack'], window=conn['window'])
                        self.sock.sendto(heartbeat, addr)

    def _process_timeouts(self, now: float):
        with self.send_lock:
            for addr, conn in list(self.connections.items()):
                if (conn['state'] not in [self.ConnectionState.SYN_SENT, self.ConnectionState.SYN_RECEIVED] and
                    now - conn['last_activity'] > CONNECTION_TIMEOUT):
                    self._terminate_connection(conn, 'timeout')

    def _process_stream_assembly(self, now: float):
        if self.mode != self.Mode.STREAM:
            return
        
        with self.recv_lock:
            for addr, conn in self.connections.items():
                if conn['state'] != self.ConnectionState.ESTABLISHED:
                    continue
                
                if conn['stream_buffer'] and self.callbacks['stream_data']:
                    self.callbacks['stream_data'](conn['addr'], bytes(conn['stream_buffer']))
                    conn['stream_buffer'] = bytearray()

    def _terminate_connection(self, conn: Dict[str, Any], reason: str):
        if conn['addr'] not in self.connections:
            return
        
        if self.callbacks['disconnect']:
            self.callbacks['disconnect'](conn['addr'], reason)
        
        self.logger.debug("Connection to %s:%d terminated: %s", 
                         conn['addr'][0], conn['addr'][1], reason)
        self.connections.pop(conn['addr'], None)

    def _update_rtt(self, conn: Dict[str, Any], rtt_sample: float):
        if rtt_sample <= 0:
            return
        
        if conn['rtt'] == 0:
            conn['rtt'] = rtt_sample
            conn['rtt_var'] = rtt_sample / 2
        else:
            conn['rtt_var'] = 0.75 * conn['rtt_var'] + 0.25 * abs(conn['rtt'] - rtt_sample)
            conn['rtt'] = 0.875 * conn['rtt'] + 0.125 * rtt_sample
        
        conn['rto'] = max(min(conn['rtt'] + max(4 * conn['rtt_var'], 1.0), MIN_RTO)
        conn['rto'] = min(conn['rto'], MAX_RTO)

    def set_callback(self, event: str, callback: Callable):
        if event in self.callbacks:
            self.callbacks[event] = callback

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    atl = ATL(mode=ATL.Mode.STREAM)
    atl.set_callback('stream_data', lambda addr, data: print(f"Stream from {addr}: {data.decode()}"))
    atl.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        atl.stop()
