#ifndef CLIENT_H
#define CLIENT_H
#include "mysocket.h"
#include <ctime>

class CRouter
{
    private:
    CSocket _mysock;
    CSocket _icmp_sock;
    CSocket _tcp_sock;

    struct circuit cc;

    char _logfn[MAX_FN_LEN];
    int _stage;
    int _index;
    int _cc_seq;
    int _open_circuit = 1;
    int _create_circuit_count = 0;
    int _current_circuit = 0;
    struct circuit _circuit_array[2000];
    unsigned int _seq_array[100];
    unsigned short _last_seen = 0;
    struct sockaddr_in _paddr;
    clock_t _start_time = 0;

    struct sockaddr_in old_src_addr;
    struct sockaddr_in old_tcp_saddr;
    unsigned short old_ip_id;
    unsigned short old_tcp_port;
    char packet_buf[MAX_PACKET_SIZE];
    int packet_len;

    unsigned long _rip;
    unsigned char aes_key[KEY_LEN];

    public:
    CRouter();
    CRouter(int stage, int index,  struct sockaddr_in paddr, unsigned long ip);
    ~CRouter();


    void print_buf_hex(char* buf, int buf_len, int port);

    bool initialize_socket();
    bool initialize_rawsocket();
    bool initialize_tcpsocket();

    bool bind_rawsock_dev(char* dev);
    //bind raw socket to a source IP;
    bool bind_rawsock_src(struct sockaddr_in src);


    bool connect_server(const char* serv_host, const int serv_port);
    int send_data(const char* send_buf);
    int recv_data(char* recv_buf);
    int get_port();
    void output_log(char* out_str);

    void run();
    int send_data_UDP(const char* send_buf, const int len, struct sockaddr_in & ser_addr);
    int recv_data_UDP(char* recv_buf, struct sockaddr_in & si_other);
    
    //old ICMP data sending function, not work actually, might delete in the future.
    int send_data_ICMP(const char* send_buf, const int len, struct sockaddr_in & ser_addr);
    int recv_data_ICMP(char* recv_buf, struct sockaddr_in & ser_addr);

    int send_ICMP_packet(struct sockaddr_in dst_addr);
    int send_TCP_packet(struct sockaddr_in src_addr, struct sockaddr_in dst_addr, char* org_packet, int len);
    int recv_data_TCP(char* recv_buf, struct sockaddr_in & ser_addr);

    void construct_icmp_packet(char* buf, const int buf_len, in_addr_t src, in_addr_t dst);
    int construct_router_worried_msg(char* buf, int len, unsigned short cID, unsigned short self_hop, unsigned short next_hop);
    
    void handle_rawsock_icmp_traffic(char* buf, int len);
    void handle_rawsock_tcp_traffic(char* buf, int len);
    void handle_proxy_icmp_traffic(char* buf, int len, struct sockaddr_in si_other);
    void handle_proxy_tcp_traffic(char* buf, int len, struct sockaddr_in si_other); //need to make sure routers send tcp packets back to proxy correctly, appears to send out to real world correctly

    void handle_ccext_msg(char* buf, int len, struct sockaddr_in si_other);
    void handle_ccext_done_msg(char* buf, int len, struct sockaddr_in si_other);
    void handle_cc_worried_msg(char* buf, int len, struct sockaddr_in si_other);
    void handle_relay_msg(char* buf, int len, struct sockaddr_in si_other);
    void self_reply_icmp(char* buf, int len, struct sockaddr_in si_other);

    void handle_deffie_hellman_msg(char* buf, int len, struct sockaddr_in si_other);

};

#endif
