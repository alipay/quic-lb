import quic_base
import threading
import socket
import struct

class QuicServer(quic_base.QuicBase, threading.Thread):
    #_recv_handler = quic_server_data_process_handler
    _cid_len = 18
    _sid = ""
    _sid_len = 0
    _token = bytearray("test token")
    _payload = bytearray("test payload")
    _cid_dict = {}
    _conf_id = 0
    _debug_tag = True
    client_ip = ""
    proxy_ip = ""
    client_port = ""
    proxy_port = ""
    use_retry = False

    def __init__(self, threadID, src_addr, src_port, sid, conf_id, use_retry):
        quic_base.QuicBase.__init__(self, src_addr, src_port)
        threading.Thread.__init__(self)
        self.threadID = threadID
        self._sid = sid
        self._sid_len = len(sid)
        if (conf_id == 0):
            self._conf_id = 0x00
        elif (conf_id == 1):
            self._conf_id = 0x40
        elif (conf_id == 2):
            self._conf_id = 0x80
        else:
            raise Exception("Invalid conf id: ", conf_id)

        self.use_retry = use_retry

    def run(self):
        self.quic_recvfrom(self.quic_server_data_process_handler)

    def quic_packet_is_quic_lb_proxy_protocol(self, data):
        if data[0:5] == "PROXY":
            return True
        return False

    def process_quic_lb_proxy_protocol_header(self, data):
        str_begin_index = 0
        move_index = 0
        tag = 0
        while (True):
            if (data[move_index] == ' '):
                if (tag == 0): #PROXY
                    str_begin_index = move_index + 1
                    tag += 1
                elif (tag == 1): #QUICV4
                    str_begin_index = move_index + 1
                    tag += 1
                elif (tag == 2): #Client IP
                    self.client_ip = data[str_begin_index:move_index]
                    str_begin_index = move_index + 1
                    tag += 1
                elif (tag == 3): #Proxy IP
                    self.proxy_ip = data[str_begin_index:move_index]
                    str_begin_index = move_index + 1
                    tag += 1
                elif (tag == 4): #Client Port
                    self.client_port = data[str_begin_index:move_index]
                    str_begin_index = move_index + 1
                    tag += 1
                elif (tag == 5): #Proxy Port
                    self.proxy_ip = data[str_begin_index:move_index]
                    str_begin_index = move_index + 1
                    tag += 1
            elif (data[move_index] == '\r' and (data[move_index+1] == '\n')):
                return move_index+2

            move_index = move_index + 1
            if (move_index > len(data) - 1):
                return -1
        return -1

    def quic_server_data_process_handler(self, data, peer_addr):
        if len(data) == 0:
            return
        if (self.quic_packet_is_quic_lb_proxy_protocol(data)):
            if self._debug_tag:
                print("recv quic lb proxy protocol packet")
            begin_index = self.process_quic_lb_proxy_protocol_header(data)
            if (begin_index == -1):
                self.recv_error_packet_num = self.recv_error_packet_num + 1
            data = data[begin_index:]

        if (self.quic_packet_is_long_packet(data)):
            if self._debug_tag:
                print("server %s recv %d long header data, server thread id is %d"
                    % (self._sid, len(data), self.threadID))
            init_packet = quic_base.InitPacket(data)
            if (init_packet.version != self._draft_version):
                self.recv_error_init_packet_num += 1
                return

            if self.use_retry:
                # if no token carried, send retry packet to client
                if (init_packet.token_len == 0):
                    self.retry_recv_packet_with_no_token_num += 1
                    return

                self.retry_recv_packet_with_token_num += 1
                # Note: the address in token is big-endian
                ip_int = struct.unpack('@I', socket.inet_aton(peer_addr[0]))[0]
                res = self.quic_validate_token(ip_int, init_packet.token)
                print("[server] validate token result:", res)
                if (res <= 0):
                    self.retry_recv_packet_with_invalid_token_num += 1
                    return
                else:
                    self.retry_recv_packet_with_valid_token_num += 1

            # if success validate client token, then send an test init packet to client,
            # just test quic-lb can success foward upstream/downstream packet
            self.recv_correct_init_packet_num += 1
            # generate new server id for client dcid
            rand_len = self._cid_len - self._sid_len - 1
            server_cid = bytes(bytearray([self._conf_id]) + bytearray(self._sid) +
                             bytearray(self.gen_random_bytes(rand_len)))
            if self._debug_tag:
                print("server gen server_cid is: " , server_cid)
            self._cid_dict[server_cid] = init_packet.scid
            # construct init packet and send
            pkt = self.quic_construct_init_packet(self._token, self._payload, init_packet.scid, server_cid)
            self.quic_sendto(pkt, peer_addr[0], peer_addr[1])
        else:
            if self._debug_tag:
                print("server %s recv %d short header data, server thread id is %d"
                      % (self._sid, len(data), self.threadID))
            server_cid = data[1:1+self._cid_len]
            if self._debug_tag:
                print("short header dcid is:", server_cid)
            if (self._cid_dict[server_cid] != None):
                if self._debug_tag:
                    print("server %s recv a correct app packet, server thread id is %d"
                          % (self._sid, self.threadID))
                self.recv_correct_app_packet_num += 1
                pkt = self.quic_construct_short_header_packet(self._payload, self._cid_dict[server_cid])
                self.quic_sendto(pkt, peer_addr[0], peer_addr[1])
            else:
                self.recv_error_app_packet_num += 1
