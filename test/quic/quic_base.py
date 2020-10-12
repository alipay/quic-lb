import socket
import random
import struct
import errno
from ctypes import *
import ctypes

class QuicBase:
    _socket = 0
    src_addr = ""
    src_port = 0
    _mtu = 1200
    _buf = []
    _draft_version = 29
    _terminate_tag = False
    # statistic variabl
    recv_correct_init_packet_num = 0
    recv_error_init_packet_num = 0
    recv_correct_app_packet_num = 0
    recv_error_app_packet_num = 0
    recv_error_packet_num = 0

    # cache dcid, used for retry
    odcid = ""
    odcid_len = 0
    retry_recv_packet_with_no_token_num    = 0
    retry_recv_packet_with_token_num       = 0
    retry_recv_packet_with_valid_token_num = 0
    retry_recv_packet_with_invalid_token_num = 0

    def __init__(self, src_addr, src_port):
        self.src_addr = src_addr
        self.src_port = src_port

    def quic_sendto(self, data, dst_addr, dst_port):
        i = 0
        l = len(data[i:])
        while i < l:
            left = l-i
            if left < self._mtu:
                left = self._mtu
            self._socket.sendto(data[i:i+left], (dst_addr, dst_port))
            i = i+left

    def quic_data_process_handler(self, data, peer_addr):
        pass

    def quic_recvfrom(self, recv_handler):
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.bind((self.src_addr, self.src_port))
        self._socket.setblocking(False)
        while True:
            try:
                if (self._terminate_tag == True):
                    break
                data, addr = self._socket.recvfrom(32768)
                if len(data) != 0:
                    recv_handler(data, addr)

            except IOError as e:
                if e.errno == errno.EWOULDBLOCK:
                    pass
            except Exception as e:
                print(e)
        self._socket.close()

    def terminate(self):
        self._terminate_tag = True

    def singlebyte2int(self, data):
        ret = struct.unpack('>B', data)
        return ret[0]

    def quic_packet_is_long_packet(self, data):
        tag = self.singlebyte2int(data[0])
        if (tag & 0x80 != 0):
            return True
        return False

    def quic_packet_is_retry_packet(self, data):
        tag = self.singlebyte2int(data[0])
        if (tag & 0x30 == 0x30):
            return True
        return False

    def quic_construct_init_packet(self, token, payload, dcid, scid):
        pkt = bytearray()
        # We just mock the whole route progress, so we don't need pkt number and crypto
        first_byte = 0xc0
        pkt.append(first_byte)

        version = 0xff000000 + self._draft_version
        pkt.append((version & 0xffffffff) >> 24)
        pkt.append((version & 0x00ffffff) >> 16)
        pkt.append((version & 0x0000ffff) >> 8)
        pkt.append(version & 0x000000ff)

        dcid_len = 0xff & len(dcid)
        pkt.append(dcid_len)
        pkt += bytearray(dcid)

        scid_len = 0xff & len(scid)
        pkt.append(scid_len)
        pkt += bytearray(scid)

        token_len = self.quic_variable_length_encoding(token)
        pkt += token_len
        pkt += bytearray(token)

        payload_len = self.quic_variable_length_encoding(payload)
        pkt += payload_len
        pkt += bytearray(payload)

        return pkt

    def quic_construct_short_header_packet(self, dcid, payload):
        pkt = bytearray()
        # We just mock the whole route progress, so we don't need pkt number and crypto
        first_byte = bytearray([0x40])
        pkt += first_byte

        pkt += bytearray(dcid)
        pkt += bytearray(payload)
        return pkt

    # decribed in https://tools.ietf.org/html/draft-ietf-quic-transport-29#section-16
    def quic_variable_length_encoding(self, data):
        len_byte = bytearray()
        l = len(data)
        if (l == 0):
            len_byte += bytearray([0x00])
        elif(0 < l and l < 64):
            byte = l & 0xff | 0x00
            len_byte += bytearray([byte])
        elif(64 < l and l < 16383):
            len_byte.append(chr((l & 0xffff | 0x4000) >> 8))
            len_byte.append(chr(l & 0x00ff))
        elif(16383 < l and l < 1073741823):
            len_byte.append(chr((l & 0xffffffff | 0x80000000) >> 24))
            len_byte.append(chr((l & 0x00ffffff) >> 16))
            len_byte.append(chr((l & 0x0000ffff) >> 8))
            len_byte.append(chr(l & 0x000000ff))
        elif(1073741823 < l):
            len_byte.append(chr((len & 0xffffffffffffffff | 0xc000000000000000) >> 56))
            len_byte.append(chr((len & 0x00ffffffffffffff) >> 48))
            len_byte.append(chr((len & 0x0000ffffffffffff) >> 40))
            len_byte.append(chr((len & 0x000000ffffffffff) >> 32))
            len_byte.append(chr((len & 0x00000000ffffffff) >> 24))
            len_byte.append(chr((len & 0x0000000000ffffff) >> 16))
            len_byte.append(chr((len & 0x000000000000ffff) >> 8))
            len_byte.append(chr(len & 0x00000000000000ff))
        return len_byte

    def quic_validate_token(self, selfaddr, token):
        tls_verify_lib = CDLL("./liblbtest.so")
        return tls_verify_lib.test_verify_token(selfaddr, token, len(token))

    def gen_random_bytes(self, len):
        res = bytearray()
        for _ in range(0,len):
            n = random.randint(0, 255)
            res += bytearray([n])
        return res

class RetryPacket:
    retry_token_len = 0
    retry_token_data = ""
    retry_tag_data = ""
    retry_token_tag_len = 16  # fix value
    retry_data_wo_tag = ""
    def __init__(self, data):
        self.parse(data, len(data))

    def singlebyte2int(self, data):
        ret = struct.unpack('>B', data)
        return ret[0]

    def parse(self, data, total_len):
        self.retry_data_wo_tag = data[0: total_len - self.retry_token_tag_len] # wo 16B
        read_index = 1 # we don't need first byte
        version = data[read_index:read_index+4]
        self.version = self.singlebyte2int(version[3])
        read_index += 4
        self.dcid_len = self.singlebyte2int(data[read_index:read_index+1])
        read_index += 1
        self.dcid = data[read_index:read_index + self.dcid_len]
        read_index += self.dcid_len
        self.scid_len = self.singlebyte2int(data[read_index:read_index+1])
        read_index += 1
        self.scid = data[read_index:read_index + self.scid_len]
        read_index += self.scid_len
        # reach read_index
        self.retry_token_len = total_len - read_index - self.retry_token_tag_len
        self.retry_token_data = data[read_index:read_index + self.retry_token_len]
        self.retry_tag_data = data[total_len - self.retry_token_tag_len:]
        return

    def pkt_verify_retry_tag(self, odcid, odcid_len):
        # put odcid, len
        pseudo_retry_buf = ""
        pseudo_retry_buf += chr(odcid_len)
        for i in range (0,odcid_len):
            pseudo_retry_buf += chr(odcid[i])
        pseudo_retry_buf += self.retry_data_wo_tag
        tls_verify_lib = CDLL("./liblbtest.so")
        tls_verify_lib.test_verify_retry_tag.argtypes = [ctypes.c_char_p, ctypes.c_uint, ctypes.c_char_p]
        return tls_verify_lib.test_verify_retry_tag(ctypes.c_char_p(pseudo_retry_buf), len(pseudo_retry_buf), self.retry_tag_data)


class InitPacket:
    version = 0
    scid_len = 0
    scid = ""
    dcid_len = 0
    dcid = ""
    token_len = 0
    token = ""

    def __init__(self, data):
        self.parse(data)

    def parse(self, data):
        read_index = 1 # we don't need first byte
        version = data[read_index:read_index+4]
        self.version = self.singlebyte2int(version[3])
        read_index += 4
        self.dcid_len = self.singlebyte2int(data[read_index:read_index+1])
        read_index += 1
        self.dcid = data[read_index:read_index + self.dcid_len]
        read_index += self.dcid_len
        self.scid_len = self.singlebyte2int(data[read_index:read_index+1])
        read_index += 1
        self.scid = data[read_index:read_index + self.scid_len]
        read_index += self.scid_len
        self.token_len, offset = self.quic_variable_length_decode(data[read_index:])
        if (self.token_len == 0):
            return
        read_index += offset
        # validate client token, if faild, return
        self.token = data[read_index:read_index+self.token_len]

    def singlebyte2int(self, data):
        ret = struct.unpack('>B', data)
        return ret[0]

    def quic_variable_length_decode(self, data):
        first_byte = self.singlebyte2int(data[0])
        mode = first_byte >> 6
        l = 0
        offset = 0
        if (mode == 0):
            l = first_byte & 0x3f
            offset = 1
        elif (mode == 1):
            second_byte = self.singlebyte2int(data[1])
            l = int((first_byte & 0x3f) << 8) | second_byte
            offset = 2
        elif (mode == 2):
            second_byte = self.singlebyte2int(data[1])
            third_byte = self.singlebyte2int(data[2])
            fourth_byte = self.singlebyte2int(data[3])
            l = int((first_byte & 0x3f) << 24 | (second_byte << 16)
                     | (third_byte << 8) | fourth_byte)
            offset = 4
        elif (mode == 3):
            second_byte = self.singlebyte2int(data[1])
            third_byte = self.singlebyte2int(data[2])
            fourth_byte = self.singlebyte2int(data[3])
            fifth_byte = self.singlebyte2int(data[4])
            sixth_byte = self.singlebyte2int(data[5])
            seventh_byte = self.singlebyte2int(data[6])
            eighth_byte = self.singlebyte2int(data[7])
            l = int((first_byte & 0x3f) << 56 | (second_byte << 48) | (third_byte << 40)
                     | (fourth_byte << 32) | (fifth_byte << 24) | (sixth_byte << 16)
                     | (seventh_byte << 8) | eighth_byte)
            offset = 8

        return l, offset






