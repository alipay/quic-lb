import pytest
import quic.quic_server as quic_server
import quic.quic_client as quic_client
import quic.quic_base as quic_base
import socket
import time
import os
import json

debug_tag = True

class conf:
    conf_id = 0
    isMajor = True
    route_mode = "plaintext"
    sid_len = 0
    retry_method =  "shared_state",
    retry_mode = "inactive",
    retry_token_key = "01234567890123456789012345678901"

    def __init__(self):
        pass



class TestCase():
    # test server info
    test_server_num = 5
    server_arr = []
    server_orig_src_addr = "127.0.0.1"
    server_orig_src_port = 8443

    # test server info with retry
    test_server_num_ues_retry = 5
    server_arr_retry = []
    server_orig_src_port_use_retry = 9443

    server_cid_len = 18
    # test client info
    client_src_addr = "127.0.0.1"
    client_src_port = 6666
    client_migrate_addr = "127.0.0.1"
    client_migrate_port = 6667
    client_cid_len = 18
    client = None
    # quic-lb info
    quic_lb_ip = "127.0.0.1"
    quic_lb_port = 8001

    def load_conf_file(self, conf_file):
        with open('conf_file','r') as f:
            data = json.load(f)
            return data

    def setup_class(self):
        os.system("echo '' > ./quic_lb/logs/error.log")
        os.system("echo '' > ./quic_lb/logs/access.log")
        pass

    def teardown_class(self):
        for server in self.server_arr:
            server.terminate()

        for server in self.server_arr_retry:
            server.terminate()

    def setup(self):
        os.system("pkill nginx")
        os.system("./quic_lb/nginx -p quic_lb -c conf/quic_lb.conf")
        self.server_arr = []
        self.server_arr_retry = []
        self.client = None
        for i in range(0, self.test_server_num):
            port = self.server_orig_src_port + i
            ip = self.server_orig_src_addr
            server = quic_server.QuicServer(i, ip, port, ip+":"+str(port), 0, False)
            server.start()
            self.server_arr.append(server)

        # server with retry service
        for i in range(0, self.test_server_num_ues_retry):
            port = self.server_orig_src_port_use_retry + i
            ip = self.server_orig_src_addr
            server = quic_server.QuicServer(i, ip, port, ip+":"+str(port), 0, True)
            server.start()
            self.server_arr_retry.append(server)


    def teardown(self):
        os.system("pkill nginx")
        for server in self.server_arr:
            server.terminate()

        for server in self.server_arr_retry:
            server.terminate()

        self.server_arr = []
        self.server_arr_retry = []
        self.client.terminate()

    def test_quic_client_send_init_packet_without_token(self):
        server = self.server_arr[0]
        self.client = quic_client.QuicClient(self.client_src_addr, self.client_src_port,
                                        "", "", server.src_addr, server.src_port)
        token = []
        test_payload = ""
        odcid = self.client.gen_random_bytes(self.server_cid_len)
        scid = self.client.gen_random_bytes(self.client_cid_len)
        pkt = self.client.quic_construct_init_packet(token, test_payload, odcid, scid)
        self.client.quic_sendto(pkt, server.src_addr, server.src_port)

    def test_quic_client_send_init_packet_with_token(self):
        server = self.server_arr[0]
        self.client = quic_client.QuicClient(self.client_src_addr, self.client_src_port,
                                        "", "", server.src_addr, server.src_port)
        # token = self.client.gen_token()
        token = self.client.token_mocked
        test_payload = "this is test payload"
        odcid = self.client.gen_random_bytes(self.server_cid_len)
        scid = self.client.gen_random_bytes(self.client_cid_len)
        pkt = self.client.quic_construct_init_packet(token, test_payload, odcid, scid)
        self.client.quic_sendto(pkt, server.src_addr, server.src_port)
        data, addr = self.client.recvfrom()
        assert addr[0] == server.src_addr
        assert addr[1] == server.src_port
        assert server.recv_correct_init_packet_num == 1
        #assert self.client.quic_packet_is_long_packet(data) == True

    def test_quic_client_send_init_packet_and_app_packet(self):
        server = self.server_arr[0]
        self.client = quic_client.QuicClient(self.client_src_addr, self.client_src_port,
                                        "", "", server.src_addr, server.src_port)
        # token = self.client.gen_token()
        token = self.client.token_mocked
        test_payload = "this is test payload"
        odcid = self.client.gen_random_bytes(self.server_cid_len)
        scid = self.client.gen_random_bytes(self.client_cid_len)
        init_pkt = self.client.quic_construct_init_packet(token, test_payload, odcid, scid)
        self.client.quic_sendto(init_pkt, server.src_addr, server.src_port)
        data, addr = self.client.recvfrom()
        assert addr[0] == server.src_addr
        assert addr[1] == server.src_port
        assert server.recv_correct_init_packet_num == 1
        assert self.client.quic_packet_is_long_packet(data) == True
        # extract server cid
        init_packet = quic_base.InitPacket(data)
        assert init_packet.version == self.client._draft_version
        app_pkt = self.client.quic_construct_short_header_packet(init_packet.scid, test_payload)
        self.client.quic_sendto(app_pkt, server.src_addr, server.src_port)
        data, addr = self.client.recvfrom()
        assert addr[0] == server.src_addr
        assert addr[1] == server.src_port
        assert server.recv_correct_app_packet_num == 1

    def test_quic_connection_migrate(self):
        server = self.server_arr[0]
        self.client = quic_client.QuicClient(self.client_src_addr, self.client_src_port,
                                        self.client_migrate_addr, self.client_migrate_port,
                                        server.src_addr, server.src_port)
        # token = self.client.gen_token()
        token = self.client.token_mocked
        test_payload = "this is test payload"
        odcid = self.client.gen_random_bytes(self.server_cid_len)
        scid = self.client.gen_random_bytes(self.client_cid_len)
        init_pkt = self.client.quic_construct_init_packet(token, test_payload, odcid, scid)
        self.client.quic_sendto(init_pkt, server.src_addr, server.src_port)
        data, addr = self.client.recvfrom()
        assert addr[0] == server.src_addr
        assert addr[1] == server.src_port
        assert server.recv_correct_init_packet_num == 1
        assert self.client.quic_packet_is_long_packet(data) == True
        # extract server cid
        init_packet = quic_base.InitPacket(data)
        assert init_packet.version == self.client._draft_version
        app_pkt = self.client.quic_construct_short_header_packet(init_packet.scid, test_payload)
        self.client.quic_sendto(app_pkt, server.src_addr, server.src_port)
        data, addr = self.client.recvfrom()
        assert addr[0] == server.src_addr
        assert addr[1] == server.src_port
        assert server.recv_correct_app_packet_num == 1
        self.client.addr_migration()
        self.client.quic_sendto(app_pkt, server.src_addr, server.src_port)
        data, addr = self.client.recvfrom()
        assert addr[0] == server.src_addr
        assert addr[1] == server.src_port
        assert server.recv_correct_app_packet_num == 2

# for some print, use this again
if __name__ == "__main__":
    pytest.main(["-s", "quic_lb_test.py"])
    os._exit(1)