#include "nfqnl_test.h"

char bad[30]; /*user's input*/
int _ret=0;/*check data exist*/
void dump(unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i != 0 && i % 16 == 0)
            printf("\n");
        printf("%02X ", buf[i]);
    }
    printf("\n");
}

/* returns packet id */
void check(unsigned char *data,int ret){
    struct libnet_ipv4_hdr* ip = (struct libnet_ipv4_hdr*)(data);
    
    /* check tcp */
    if(ip->ip_p!=0x06)return;
    
    /* go to tcp */
    data += sizeof(struct libnet_ipv4_hdr);
    struct libnet_tcp_hdr* tcp = (struct libnet_tcp_hdr*)(data);
    
    /* go to http */
    data += (tcp->th_off)*4;

    if(check_str(data))/*if data exist*/
    { 
	    dump(data,ret);
	    _ret = 1;
    }
}

int check_str(unsigned char *data){

    unsigned char pat[100] = "Host: ";
    strcat(pat,bad);
    uint16_t pat_len = strlen(pat);
    uint16_t txt_len = strlen(data);
    
    /*using BoyerMoore to find url*/
    BmCtx* ctx = BoyerMooreCtxInit((uint8_t*)pat, pat_len);

    printf("Bad Character table\n");
    for (int i = 0; i < ALPHABET_SIZE; i++) {
	if (ctx->bmBc[i] != pat_len)
		printf("%d(%c) = %d\n", i, i, ctx->bmBc[i]);
    }
    printf("\n");

    printf("Good Suffix table\n");
    for (int i = 0; i < pat_len; i++) {
 	printf("%d(%c) %d\n", i, pat[i], ctx->bmGs[i]);
    }
    printf("\n");

    unsigned char* found = BoyerMoore(pat, pat_len, data, txt_len, ctx);
    
    int flag = 0;
    if (found == NULL)
	    printf("not found\n");
    else{
	    printf("found %ld\n", found - data);
	    flag = 1;
    }
    BoyerMooreCtxDeInit(ctx);
    return flag;
}

static uint32_t print_pkt (struct nfq_data *tb)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    uint32_t mark, ifi, uid, gid;
    int ret;
    unsigned char *data, *secdata;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ",
            ntohs(ph->hw_protocol), ph->hook, id);
    }

    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);

        printf("hw_src_addr=");
        for (i = 0; i < hlen-1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen-1]);
    }

    mark = nfq_get_nfmark(tb);
    if (mark)
        printf("mark=%u ", mark);

    ifi = nfq_get_indev(tb);
    if (ifi)
        printf("indev=%u ", ifi);

    ifi = nfq_get_outdev(tb);
    if (ifi)
        printf("outdev=%u ", ifi);
    ifi = nfq_get_physindev(tb);
    if (ifi)
        printf("physindev=%u ", ifi);

    ifi = nfq_get_physoutdev(tb);
    if (ifi)
        printf("physoutdev=%u ", ifi);

    if (nfq_get_uid(tb, &uid))
        printf("uid=%u ", uid);

    if (nfq_get_gid(tb, &gid))
        printf("gid=%u ", gid);

    ret = nfq_get_secctx(tb, &secdata);
    if (ret > 0)
        printf("secctx=\"%.*s\" ", ret, secdata);

    ret = nfq_get_payload(tb, &data);
    if (ret >= 0){
        printf("payload_len=%d\n", ret);
        check(data,ret);
    }

    fputc('\n', stdout);

    return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data)
{
    uint32_t id = print_pkt(nfa);
    printf("entering callback\n");
    if(_ret)/*if found url*/
	    return nfq_set_verdict(qh,id,NF_DROP,0,NULL);//drop
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);//accept
}

int main(int argc, char **argv)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    uint32_t queue = 0;
    char buf[4096] __attribute__ ((aligned));

    if (argc == 2) {
        queue = 0;
	    strcpy(bad,argv[1]);
    }

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '%d'\n", queue);
    qh = nfq_create_queue(h, queue, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    printf("setting flags to request UID and GID\n");
    if (nfq_set_queue_flags(qh, NFQA_CFG_F_UID_GID, NFQA_CFG_F_UID_GID)) {
        fprintf(stderr, "This kernel version does not allow to "
                "retrieve process UID/GID.\n");
    }

    printf("setting flags to request security context\n");
    if (nfq_set_queue_flags(qh, NFQA_CFG_F_SECCTX, NFQA_CFG_F_SECCTX)) {
        fprintf(stderr, "This kernel version does not allow to "
                "retrieve security context.\n");
    }

    printf("Waiting for packets...\n");

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}
