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

    def test_quic_client_send_init_packet_and_app_packet_with_quic_lb(self):
        self.client = quic_client.QuicClient(self.client_src_addr, self.client_src_port,
                                        "", "", self.quic_lb_ip, self.quic_lb_port)
        # token = self.client.gen_token()
        token = self.client.token_mocked
        test_payload = "this is test payload"
        odcid = self.client.gen_random_bytes(self.server_cid_len)
        scid = self.client.gen_random_bytes(self.client_cid_len)
        init_pkt = self.client.quic_construct_init_packet(token, test_payload, odcid, scid)
        self.client.quic_sendto(init_pkt, self.quic_lb_ip, self.quic_lb_port)
        data, addr = self.client.recvfrom()
        # for consistent hash algorithm, we would use 3th server as dest server
        # todo: chash implement in test case
        server = self.server_arr[2]
        assert addr[0] == self.quic_lb_ip
        assert addr[1] == self.quic_lb_port
        assert server.recv_correct_init_packet_num == 1
        assert self.client.quic_packet_is_long_packet(data) == True
        # extract server cid
        init_packet = quic_base.InitPacket(data)
        assert init_packet.version == self.client._draft_version
        if debug_tag:
            print("client new dcid is: %s " % init_packet.scid)
        app_pkt = self.client.quic_construct_short_header_packet(init_packet.scid, test_payload)
        self.client.quic_sendto(app_pkt, self.quic_lb_ip, self.quic_lb_port)
        data, addr = self.client.recvfrom()
        assert addr[0] == self.quic_lb_ip
        assert addr[1] == self.quic_lb_port
        assert server.recv_correct_app_packet_num == 1

    def test_quic_client_send_small_init_packet_and_app_packet_with_quic_lb(self):
        self.client = quic_client.QuicClient(self.client_src_addr, self.client_src_port,
                                        "", "", self.quic_lb_ip, self.quic_lb_port)
        # token = self.client.gen_token()
        token = self.client.token_mocked
        test_payload = "t"
        odcid = self.client.gen_random_bytes(self.server_cid_len)
        scid = self.client.gen_random_bytes(self.client_cid_len)
        init_pkt = self.client.quic_construct_init_packet(token, test_payload, odcid, scid)
        self.client.quic_sendto(init_pkt, self.quic_lb_ip, self.quic_lb_port)
        data, addr = self.client.recvfrom()
        # for consistent hash algorithm, we would use 3th server as dest server
        # todo: chash implement in test case
        server = self.server_arr[2]
        assert addr[0] == self.quic_lb_ip
        assert addr[1] == self.quic_lb_port
        assert server.recv_correct_init_packet_num == 1
        assert self.client.quic_packet_is_long_packet(data) == True
        # extract server cid
        init_packet = quic_base.InitPacket(data)
        assert init_packet.version == self.client._draft_version
        if debug_tag:
            print("client new dcid is: %s " % init_packet.scid)
        app_pkt = self.client.quic_construct_short_header_packet(init_packet.scid, test_payload)
        self.client.quic_sendto(app_pkt, self.quic_lb_ip, self.quic_lb_port)
        data, addr = self.client.recvfrom()
        assert addr[0] == self.quic_lb_ip
        assert addr[1] == self.quic_lb_port
        assert server.recv_correct_app_packet_num == 1

    def test_quic_client_send_many_small_init_packet_and_app_packets_with_quic_lb(self):
        self.client = quic_client.QuicClient(self.client_src_addr, self.client_src_port,
                                        "", "", self.quic_lb_ip, self.quic_lb_port)
        # token = self.client.gen_token()
        token = self.client.token_mocked
        test_payload = "t"
        odcid = self.client.gen_random_bytes(self.server_cid_len)
        scid = self.client.gen_random_bytes(self.client_cid_len)
        init_pkt = self.client.quic_construct_init_packet(token, test_payload, odcid, scid)
        self.client.quic_sendto(init_pkt, self.quic_lb_ip, self.quic_lb_port)
        data, addr = self.client.recvfrom()
        # for consistent hash algorithm, we would use 3th server as dest server
        # todo: chash implement in test case
        server = self.server_arr[2]
        assert addr[0] == self.quic_lb_ip
        assert addr[1] == self.quic_lb_port
        assert server.recv_correct_init_packet_num == 1
        assert self.client.quic_packet_is_long_packet(data) == True
        # extract server cid
        init_packet = quic_base.InitPacket(data)
        assert init_packet.version == self.client._draft_version
        if debug_tag:
            print("client new dcid is: %s " % init_packet.scid)
        app_pkt_num = 100
        expire_receive_pkt_num = 1
        for i in range(0, app_pkt_num):
            app_pkt = self.client.quic_construct_short_header_packet(init_packet.scid, test_payload)
            self.client.quic_sendto(app_pkt, self.quic_lb_ip, self.quic_lb_port)
            data, addr = self.client.recvfrom()
            assert addr[0] == self.quic_lb_ip
            assert addr[1] == self.quic_lb_port
            assert server.recv_correct_app_packet_num == expire_receive_pkt_num
            expire_receive_pkt_num = expire_receive_pkt_num + 1

    def test_quic_client_send_big_init_packet_and_app_packet_with_quic_lb(self):
        self.client = quic_client.QuicClient(self.client_src_addr, self.client_src_port,
                                        "", "", self.quic_lb_ip, self.quic_lb_port)
        # token = self.client.gen_token()
        token = self.client.token_mocked
        test_payload_len = 10000
        test_payload = ""
        for i in range(0, 10000):
            test_payload += "t"
        odcid = self.client.gen_random_bytes(self.server_cid_len)
        scid = self.client.gen_random_bytes(self.client_cid_len)
        init_pkt = self.client.quic_construct_init_packet(token, test_payload, odcid, scid)
        self.client.quic_sendto(init_pkt, self.quic_lb_ip, self.quic_lb_port)
        data, addr = self.client.recvfrom()
        # for consistent hash algorithm, we would use 3th server as dest server
        # todo: chash implement in test case
        server = self.server_arr[2]
        assert addr[0] == self.quic_lb_ip
        assert addr[1] == self.quic_lb_port
        assert server.recv_correct_init_packet_num == 1
        assert self.client.quic_packet_is_long_packet(data) == True
        # extract server cid
        init_packet = quic_base.InitPacket(data)
        assert init_packet.version == self.client._draft_version
        if debug_tag:
            print("client new dcid is: %s " % init_packet.scid)
        app_pkt = self.client.quic_construct_short_header_packet(init_packet.scid, test_payload)
        self.client.quic_sendto(app_pkt, self.quic_lb_ip, self.quic_lb_port)
        data, addr = self.client.recvfrom()
        assert addr[0] == self.quic_lb_ip
        assert addr[1] == self.quic_lb_port
        assert server.recv_correct_app_packet_num == 1

    def test_quic_client_send_many_big_init_packet_and_app_packet_with_quic_lb(self):
        self.client = quic_client.QuicClient(self.client_src_addr, self.client_src_port,
                                        "", "", self.quic_lb_ip, self.quic_lb_port)
        # token = self.client.gen_token()
        token = self.client.token_mocked
        test_payload_len = 10000
        test_payload = ""
        for i in range(0, 10000):
            test_payload += "t"
        odcid = self.client.gen_random_bytes(self.server_cid_len)
        scid = self.client.gen_random_bytes(self.client_cid_len)
        init_pkt = self.client.quic_construct_init_packet(token, test_payload, odcid, scid)
        self.client.quic_sendto(init_pkt, self.quic_lb_ip, self.quic_lb_port)
        data, addr = self.client.recvfrom()
        # for consistent hash algorithm, we would use 3th server as dest server
        # todo: chash implement in test case
        server = self.server_arr[2]
        assert addr[0] == self.quic_lb_ip
        assert addr[1] == self.quic_lb_port
        assert server.recv_correct_init_packet_num == 1
        assert self.client.quic_packet_is_long_packet(data) == True
        # extract server cid
        init_packet = quic_base.InitPacket(data)
        assert init_packet.version == self.client._draft_version
        if debug_tag:
            print("client new dcid is: %s " % init_packet.scid)
        app_pkt_num = 100
        expire_receive_pkt_num = 1
        for i in range(0, app_pkt_num):
            app_pkt = self.client.quic_construct_short_header_packet(init_packet.scid, test_payload)
            self.client.quic_sendto(app_pkt, self.quic_lb_ip, self.quic_lb_port)
            data, addr = self.client.recvfrom()
            assert addr[0] == self.quic_lb_ip
            assert addr[1] == self.quic_lb_port
            assert server.recv_correct_app_packet_num == expire_receive_pkt_num
            expire_receive_pkt_num = expire_receive_pkt_num + 1

    def test_quic_connection_migrate_with_quic_lb(self):
        self.client = quic_client.QuicClient(self.client_src_addr, self.client_src_port,
                                        self.client_migrate_addr, self.client_migrate_port,
                                        self.quic_lb_ip, self.quic_lb_port)
        # token = self.client.gen_token()
        token = self.client.token_mocked
        test_payload = "test"
        odcid = self.client.gen_random_bytes(self.server_cid_len)
        scid = self.client.gen_random_bytes(self.client_cid_len)
        init_pkt = self.client.quic_construct_init_packet(token, test_payload, odcid, scid)
        self.client.quic_sendto(init_pkt, self.quic_lb_ip, self.quic_lb_port)
        data, addr = self.client.recvfrom()
        # for consistent hash algorithm, we would use 3th server as dest server
        # todo: fix me, chash implement in test case
        server = self.server_arr[2]
        assert addr[0] == self.quic_lb_ip
        assert addr[1] == self.quic_lb_port
        assert server.recv_correct_init_packet_num == 1
        assert self.client.quic_packet_is_long_packet(data) == True
        # extract server cid
        init_packet = quic_base.InitPacket(data)
        assert init_packet.version == self.client._draft_version
        app_pkt = self.client.quic_construct_short_header_packet(init_packet.scid, test_payload)
        self.client.quic_sendto(app_pkt, self.quic_lb_ip, self.quic_lb_port)
        data, addr = self.client.recvfrom()
        assert addr[0] == self.quic_lb_ip
        assert addr[1] == self.quic_lb_port
        assert server.recv_correct_app_packet_num == 1
        self.client.addr_migration()
        self.client.quic_sendto(app_pkt, self.quic_lb_ip, self.quic_lb_port)
        data, addr = self.client.recvfrom()
        assert addr[0] == self.quic_lb_ip
        assert addr[1] == self.quic_lb_port
        assert server.recv_correct_app_packet_num == 2

    def test_quic_connection_migrate_then_send_many_packets_with_quic_lb(self):
        self.client = quic_client.QuicClient(self.client_src_addr, self.client_src_port,
                                        self.client_migrate_addr, self.client_migrate_port,
                                        self.quic_lb_ip, self.quic_lb_port)
        # token = self.client.gen_token()
        token = self.client.token_mocked
        test_payload = "test"
        odcid = self.client.gen_random_bytes(self.server_cid_len)
        scid = self.client.gen_random_bytes(self.client_cid_len)
        init_pkt = self.client.quic_construct_init_packet(token, test_payload, odcid, scid)
        self.client.quic_sendto(init_pkt, self.quic_lb_ip, self.quic_lb_port)
        data, addr = self.client.recvfrom()
        # for consistent hash algorithm, we would use 2th server as dest server
        # todo: fix me, chash implement in test case
        server = self.server_arr[2]
        assert addr[0] == self.quic_lb_ip
        assert addr[1] == self.quic_lb_port
        assert server.recv_correct_init_packet_num == 1
        assert self.client.quic_packet_is_long_packet(data) == True
        # extract server cid
        init_packet = quic_base.InitPacket(data)
        assert init_packet.version == self.client._draft_version
        app_pkt = self.client.quic_construct_short_header_packet(init_packet.scid, test_payload)
        self.client.quic_sendto(app_pkt, self.quic_lb_ip, self.quic_lb_port)
        data, addr = self.client.recvfrom()
        assert addr[0] == self.quic_lb_ip
        assert addr[1] == self.quic_lb_port
        assert server.recv_correct_app_packet_num == 1
        self.client.addr_migration()
        self.client.quic_sendto(app_pkt, self.quic_lb_ip, self.quic_lb_port)
        data, addr = self.client.recvfrom()
        assert addr[0] == self.quic_lb_ip
        assert addr[1] == self.quic_lb_port
        assert server.recv_correct_app_packet_num == 2
        expire_receive_pkt_num = 3
        app_pkt_num = 100
        for i in range(0, app_pkt_num):
            app_pkt = self.client.quic_construct_short_header_packet(init_packet.scid, test_payload)
            self.client.quic_sendto(app_pkt, self.quic_lb_ip, self.quic_lb_port)
            data, addr = self.client.recvfrom()
            assert addr[0] == self.quic_lb_ip
            assert addr[1] == self.quic_lb_port
            assert server.recv_correct_app_packet_num == expire_receive_pkt_num
            expire_receive_pkt_num = expire_receive_pkt_num + 1

    def test_quic_new_connection_reuse_old_addr_with_quic_lb(self):
        self.test_quic_client_send_init_packet_and_app_packet_with_quic_lb()
        # now we set up a new client with the same src address but a new dcid
        self.client.terminate()
        client_new_addr = "127.0.0.1"
        client_new_port = 16666
        self.client = quic_client.QuicClient(client_new_addr, client_new_port,
                                        "", "", self.quic_lb_ip, self.quic_lb_port)
        # token = self.client.gen_token()
        token = self.client.token_mocked
        test_payload = "test"
        odcid = self.client.gen_random_bytes(self.server_cid_len)
        scid = self.client.gen_random_bytes(self.client_cid_len)
        init_pkt = self.client.quic_construct_init_packet(token, test_payload, odcid, scid)
        self.client.quic_sendto(init_pkt, self.quic_lb_ip, self.quic_lb_port)
        data, addr = self.client.recvfrom()
        # if sid route failed, quic lb use weight consistant hash algorithm, it will
        # choose the 1th server as upstream.
        # Todo: weight consistant hash algorithm implement
        server = self.server_arr[0]
        assert addr[0] == self.quic_lb_ip
        assert addr[1] == self.quic_lb_port
        assert server.recv_correct_init_packet_num == 1
        assert self.client.quic_packet_is_long_packet(data) == True
        init_packet = quic_base.InitPacket(data)
        assert init_packet.version == self.client._draft_version
        if debug_tag:
            print("client new dcid is: %s " % init_packet.scid)
        app_pkt = self.client.quic_construct_short_header_packet(init_packet.scid, test_payload)
        self.client.quic_sendto(app_pkt, self.quic_lb_ip, self.quic_lb_port)
        data, addr = self.client.recvfrom()
        assert addr[0] == self.quic_lb_ip
        assert addr[1] == self.quic_lb_port
        assert server.recv_correct_app_packet_num == 1

    def test_quic_new_connection_reuse_old_migrate_addr_with_quic_lb(self):
        self.test_quic_connection_migrate_with_quic_lb()
        self.client.terminate()
        client_new_addr = "127.0.0.1"
        client_new_port = 16666
        # now we use migrate_addr as src addr
        self.client = quic_client.QuicClient(client_new_addr,
            client_new_port, self.client_src_addr, self.client_src_port,
            self.quic_lb_ip, self.quic_lb_port)
        # token = self.client.gen_token()
        token = self.client.token_mocked
        test_payload = "test"
        odcid = self.client.gen_random_bytes(self.server_cid_len)
        scid = self.client.gen_random_bytes(self.client_cid_len)
        init_pkt = self.client.quic_construct_init_packet(token, test_payload, odcid, scid)
        self.client.quic_sendto(init_pkt, self.quic_lb_ip, self.quic_lb_port)
        data, addr = self.client.recvfrom()
        # for weight consistent hash algorithm, quic lb would use 1th server
        # as dest server
        # todo: fix me, chash implement in test case
        server = self.server_arr[0]
        assert addr[0] == self.quic_lb_ip
        assert addr[1] == self.quic_lb_port
        assert server.recv_correct_init_packet_num == 1
        assert self.client.quic_packet_is_long_packet(data) == True
        # extract server cid
        init_packet = quic_base.InitPacket(data)
        assert init_packet.version == self.client._draft_version
        app_pkt = self.client.quic_construct_short_header_packet(init_packet.scid,
            test_payload)
        self.client.quic_sendto(app_pkt, self.quic_lb_ip, self.quic_lb_port)
        data, addr = self.client.recvfrom()
        assert addr[0] == self.quic_lb_ip
        assert addr[1] == self.quic_lb_port
        assert server.recv_correct_app_packet_num == 1
        self.client.addr_migration()
        self.client.quic_sendto(app_pkt, self.quic_lb_ip, self.quic_lb_port)
        data, addr = self.client.recvfrom()
        assert addr[0] == self.quic_lb_ip
        assert addr[1] == self.quic_lb_port
        assert server.recv_correct_app_packet_num == 2

    def test_quic_client_send_init_packet_and_app_packet_with_quic_lb_proxy_protocol(self):
        os.system("pkill nginx")
        os.system("./quic_lb/nginx -p quic_lb -c conf/quic_lb_proxy_protocol.conf")
        self.client = quic_client.QuicClient(self.client_src_addr, self.client_src_port,
                                        "", "", self.quic_lb_ip, self.quic_lb_port)
        # token = self.client.gen_token()
        token = self.client.token_mocked
        test_payload = "this is test payload"
        odcid = self.client.gen_random_bytes(self.server_cid_len)
        scid = self.client.gen_random_bytes(self.client_cid_len)
        init_pkt = self.client.quic_construct_init_packet(token, test_payload, odcid, scid)
        self.client.quic_sendto(init_pkt, self.quic_lb_ip, self.quic_lb_port)
        data, addr = self.client.recvfrom()
        # for consistent hash algorithm, we would use 3th server as dest server
        # todo: chash implement in test case
        server = self.server_arr[2]
        assert addr[0] == self.quic_lb_ip
        assert addr[1] == self.quic_lb_port
        assert server.recv_correct_init_packet_num == 1
        assert self.client.quic_packet_is_long_packet(data) == True
        # extract server cid
        init_packet = quic_base.InitPacket(data)
        assert init_packet.version == self.client._draft_version
        if debug_tag:
            print("client new dcid is: %s " % init_packet.scid)
        app_pkt = self.client.quic_construct_short_header_packet(init_packet.scid, test_payload)
        self.client.quic_sendto(app_pkt, self.quic_lb_ip, self.quic_lb_port)
        data, addr = self.client.recvfrom()
        assert addr[0] == self.quic_lb_ip
        assert addr[1] == self.quic_lb_port
        assert server.recv_correct_app_packet_num == 1
        assert server.client_ip == self.client_src_addr
        assert int(server.client_port) == self.client_src_port


    def test_nginx_quic_lb_retry_service(self):
        os.system("pkill nginx")
        os.system("./quic_lb/nginx -p quic_lb -c conf/quic_lb_retry_on.conf")
        self.client = quic_client.QuicClient(self.client_src_addr, self.client_src_port,
                                             "", "", self.quic_lb_ip, self.quic_lb_port)
        # 1. send initial packet without token
        token = self.client.token_recved
        test_payload = "this is test payload"
        odcid = self.client.gen_random_bytes(self.server_cid_len)
        odcid[0] &= 0x3f # use config id 0
        self.client.odcid = odcid
        self.client.odcid_len = self.server_cid_len
        scid = self.client.gen_random_bytes(self.client_cid_len)
        init_pkt = self.client.quic_construct_init_packet(token, test_payload, odcid, scid)
        self.client.quic_sendto(init_pkt, self.quic_lb_ip, self.quic_lb_port)

        # 2. expect recv retry packet from quiclb , not server
        data, addr = self.client.recvfrom()
        assert self.client.quic_packet_is_retry_packet(data) == True
        found = False
        for i in range(0, self.test_server_num_ues_retry):
            server = self.server_arr_retry[i]
            if server.retry_recv_packet_with_token_num > 0:
                found = True
                break
        assert found == False

        # 3. get retry token from retry packet, and verify tag
        retry_packet = quic_base.RetryPacket(data)
        self.client.token_recved = retry_packet.retry_token_data
        res = retry_packet.pkt_verify_retry_tag(self.client.odcid, self.client.odcid_len)
        print("[client] verify retry tag result:", res)
        assert res == True

        # 4. send another packet with token
        odcid = retry_packet.scid
        scid = self.client.gen_random_bytes(self.client_cid_len)
        init_pkt = self.client.quic_construct_init_packet(self.client.token_recved, test_payload, odcid, scid)
        self.client.quic_sendto(init_pkt, self.quic_lb_ip, self.quic_lb_port)

        # 5. recv initial packet again from quic server, with token validated succ
        data, addr = self.client.recvfrom()
        assert self.client.quic_packet_is_long_packet(data) == True
        assert addr[0] == self.quic_lb_ip
        assert addr[1] == self.quic_lb_port
        found = False
        for i in range(0, self.test_server_num_ues_retry):
            server = self.server_arr_retry[i]
            if server.retry_recv_packet_with_valid_token_num > 0 and server.recv_correct_init_packet_num > 0:
                found = True
                break
        assert found == True

       # 6. send short packet to server
        init_packet = quic_base.InitPacket(data)
        app_pkt = self.client.quic_construct_short_header_packet(init_packet.scid, test_payload)
        self.client.quic_sendto(app_pkt, self.quic_lb_ip, self.quic_lb_port)
        data, addr = self.client.recvfrom()
        assert addr[0] == self.quic_lb_ip
        assert addr[1] == self.quic_lb_port
        assert server.recv_correct_app_packet_num == 1

    def test_nginx_quic_lb_retry_service_with_zero_length_odcid(self):
        os.system("pkill nginx")
        os.system("./quic_lb/nginx -p quic_lb -c conf/quic_lb_retry_on.conf")
        self.client = quic_client.QuicClient(self.client_src_addr, self.client_src_port,
                                             "", "", self.quic_lb_ip, self.quic_lb_port)
        # 1. send initial packet without token
        token = self.client.token_recved
        test_payload = "this is test payload"
        odcid = ""
        self.client.odcid = odcid
        self.client.odcid_len = 0
        scid = self.client.gen_random_bytes(self.client_cid_len)
        init_pkt = self.client.quic_construct_init_packet(token, test_payload, odcid, scid)
        self.client.quic_sendto(init_pkt, self.quic_lb_ip, self.quic_lb_port)
        self.client._socket.settimeout(0.5)

        # 2. packet will be dropped by quic-lb, catch timeout exception
        try:
            data, addr = self.client.recvfrom()
        except Exception as e:
            assert str(e) == "timed out"


# for some print, use this again
if __name__ == "__main__":
    pytest.main(["-s", "quic_lb_test.py"])
    os._exit(1)
