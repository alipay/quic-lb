import quic_base
import socket

class QuicClient(quic_base.QuicBase):
    _migrate_adrr = ""
    _migrate_port = 0
    _dst_addr = ""
    _dst_port = 0
    token_recved = ""
    token_mocked = "test_token"

    def __init__(self, src_addr, src_port, migrate_addr, migrate_port,
                 dst_addr, dst_port):
        quic_base.QuicBase.__init__(self, src_addr, src_port)
        self._migrate_adrr = migrate_addr
        self._migrate_port = migrate_port
        self._dst_addr = dst_addr
        self._dst_port = dst_port
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.bind((self.src_addr, self.src_port))
        self._socket.settimeout(400)

    def recvfrom(self):
        data, addr = self._socket.recvfrom(32768)
        return data, addr

    def terminate(self):
        self._socket.close()

    def addr_migration(self):
        self._socket.close()
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.bind((self._migrate_adrr, self._migrate_port))
        self._socket.settimeout(5)
