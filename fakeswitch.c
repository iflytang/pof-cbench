#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>

#include <net/ethernet.h>

#include <netinet/in.h>

#include "pof.h"
#include "cbench.h"
#include "fakeswitch.h"

static int debug_msg(struct fakeswitch * fs, char * msg, ...);
static int make_features_reply(int switch_id, int xid, char * buf, int buflen);
//static int make_stats_desc_reply(struct ofp_stats_request * req, char * buf, int buflen);
static int parse_set_config(struct pof_header * msg);
static int make_config_reply(int id, int xid, char * buf, int buflen);
//static int make_vendor_reply(int xid, char * buf, int buflen);
static int make_packet_in(int switch_id, int xid, int buffer_id, char * buf, int buflen, int mac_address);
static int packet_out_is_lldp(struct pof_packet_out * po);
static void fakeswitch_handle_write(struct fakeswitch *fs);
static void fakeswitch_learn_dstmac(struct fakeswitch *fs);
void fakeswitch_change_status_now (struct fakeswitch *fs, int new_status);
void fakeswitch_change_status (struct fakeswitch *fs, int new_status);

static struct pof_switch_config Switch_config = {
	.header = { 	POF_VERSION,
			POFT_GET_CONFIG_REPLY,
			0,
			0},
	.flags = 0,
	.miss_send_len = 0,
};

static inline uint64_t htonll(uint64_t n)
{
    return htonl(1) == 1 ? n : ((uint64_t) htonl(n) << 32) | htonl(n >> 32);
}

static inline uint64_t ntohll(uint64_t n)
{
    return htonl(1) == 1 ? n : ((uint64_t) ntohl(n) << 32) | ntohl(n >> 32);
}

void fakeswitch_init(struct fakeswitch *fs, int dpid, int sock, int bufsize, int debug, int delay, enum test_mode mode, int total_mac_addresses, int learn_dstmac)
{
    char buf[BUFLEN];
    struct pof_header pofph;
    fs->sock = sock;
    fs->debug = debug;
    fs->id = dpid;
    fs->inbuf = msgbuf_new(bufsize);
    fs->outbuf = msgbuf_new(bufsize);
    fs->probe_state = 0;
    fs->mode = mode;
    fs->probe_size = make_packet_in(fs->id, 0, 0, buf, BUFLEN, fs->current_mac_address++);
    fs->send_count = 0;
    fs->recv_count = 0;
    fs->switch_status = START;
    fs->delay = delay;
    fs->total_mac_addresses = total_mac_addresses;
    fs->current_mac_address = 0;
    fs->xid = 1;
    fs->learn_dstmac = learn_dstmac;
    fs->current_buffer_id = 1;
  
    pofph.version = POF_VERSION;
    pofph.type = POFT_HELLO;
    pofph.length = htons(sizeof(pofph));
    pofph.xid   = htonl(1);

    // Send HELLO
    msgbuf_push(fs->outbuf,(char * ) &pofph, sizeof(pofph));
    debug_msg(fs, " sent hello");
}

/***********************************************************************/

void fakeswitch_learn_dstmac(struct fakeswitch *fs)
{
    // thanks wireshark
/*    char gratuitous_arp_reply [] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x0c, 
        0x29, 0x1a, 0x29, 0x1a, 0x08, 0x06, 0x00, 0x01, 
        0x08, 0x00, 0x06, 0x04, 0x00, 0x02, 0x00, 0x0c, 
        0x29, 0x1a, 0x29, 0x1a, 0x7f, 0x00, 0x00, 0x01, 
        0x00, 0x0c, 0x29, 0x1a, 0x29, 0x1a, 0x7f, 0x00, 
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    char mac_address_to_learn[] = { 0x80, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x01 };
    char ip_address_to_learn[] = { 192, 168 , 1, 40 };

    char buf [512];
    int len = sizeof( struct ofp_packet_in ) + sizeof(gratuitous_arp_reply);
    struct ofp_packet_in *pkt_in;
    struct ether_header * eth;
    void * arp_reply;

    memset(buf, 0, sizeof(buf));
    pkt_in = ( struct ofp_packet_in *) buf;

    pkt_in->header.version = POF_VERSION;
    pkt_in->header.type = POFT_PACKET_IN;
    pkt_in->header.length = htons(len);
    pkt_in->header.xid = htonl(fs->xid++);

    pkt_in->buffer_id = -1;
    pkt_in->total_len = htons(sizeof(gratuitous_arp_reply));
    pkt_in->in_port = htons(2);
    pkt_in->reason = POFR_NO_MATCH;

    memcpy(pkt_in->data, gratuitous_arp_reply, sizeof(gratuitous_arp_reply));

    mac_address_to_learn[5] = fs->id;
    ip_address_to_learn[2] = fs->id;

    eth = (struct ether_header * ) pkt_in->data;
    memcpy (eth->ether_shost, mac_address_to_learn, 6);

    arp_reply =  ((void *)  eth) + sizeof (struct ether_header);
    memcpy ( arp_reply + 8, mac_address_to_learn, 6);
    memcpy ( arp_reply + 14, ip_address_to_learn, 4);
    memcpy ( arp_reply + 18, mac_address_to_learn, 6);
    memcpy ( arp_reply + 24, ip_address_to_learn, 4);

    msgbuf_push(fs->outbuf,(char * ) pkt_in, len);
    debug_msg(fs, " sent gratuitous ARP reply to learn about mac address: version %d length %d type %d eth: %x arp: %x ", pkt_in->header.version, len, buf[1], eth, arp_reply);*/
}


/***********************************************************************/

void fakeswitch_set_pollfd(struct fakeswitch *fs, struct pollfd *pfd)
{
    pfd->events = POLLIN|POLLOUT;
    /* if(msgbuf_count_buffered(fs->outbuf) > 0)
        pfd->events |= POLLOUT; */
    pfd->fd = fs->sock;
}

/***********************************************************************/

int fakeswitch_get_recv_count(struct fakeswitch *fs)
{
    int ret = fs->recv_count;
    int count;
    int msglen;
    struct pof_header * pofph;
    fs->recv_count = 0;
    fs->probe_state = 0;        // reset packet state
    // keep reading until there is nothing to clear out the queue
    while( (count = msgbuf_read(fs->inbuf,fs->sock)) > 0) {
        while(count > 0) {
            // need to read msg by msg to ensure framing isn't broken
            pofph = msgbuf_peek(fs->inbuf);
            msglen = ntohs(pofph->length);
            //printf("count of msgbuf: %d and msglen: %d\n", count, msglen);
            if(count < msglen)
                break;     // msg not all there yet; 
            msgbuf_pull(fs->inbuf, NULL, ntohs(pofph->length));
            count -= msglen;
        }
    }
    return ret;
}

int fakeswitch_get_send_count(struct fakeswitch *fs) {
    int ret = fs->send_count;
    fs->send_count = 0;
    return ret;
}

/***********************************************************************/
static int parse_set_config(struct pof_header * msg) {
	/*struct ofp_switch_config * sc;
	assert(msg->type == OFPT_SET_CONFIG);
	sc = (struct ofp_switch_config *) msg;
	memcpy(&Switch_config, sc, sizeof(struct ofp_switch_config));*/

	return 0;
}


/***********************************************************************/
static int make_config_reply(int id, int xid, char * buf, int buflen) {
	int len = sizeof(struct pof_switch_config);
	assert(buflen >= len);
	Switch_config.header.type = POFT_GET_CONFIG_REPLY;
    Switch_config.header.length = htons(len);
	Switch_config.header.xid = xid;
    Switch_config.dev_id = htonl(id);
	memcpy(buf, &Switch_config, len);

	return len;
}

/***********************************************************************/
static int make_features_reply(int id, int xid, char * buf, int buflen)
{
    struct pof_switch_features * features;
    const char fake[] =     // stolen from wireshark, total 216 bytes
    {
            0x04, 0x06, 0x00, 0xd8, 0x00, 0x00, 0x15, 0xf1,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f,
            0x48, 0x75, 0x61, 0x77, 0x65, 0x69, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x50, 0x4f, 0x46, 0x53, 0x77, 0x69, 0x74, 0x63, 0x68, 0x2d, 0x31, 0x2e, 0x34, 0x2e, 0x30, 0x2e,
            0x30, 0x31, 0x35, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x50, 0x4f, 0x46, 0x53, 0x77, 0x69, 0x74, 0x63, 0x68, 0x2d, 0x31, 0x2e, 0x34, 0x2e, 0x30, 0x2e,
            0x30, 0x31, 0x35, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    assert(buflen> sizeof(fake));
    memcpy(buf, fake, sizeof(fake));
    features = (struct pof_switch_features *) buf;
    features->header.version = POF_VERSION;
    features->header.xid = xid;
    features->dev_id = htonl(id); //sizeof(dev_id) = 4
    return sizeof(fake);
}
/***********************************************************************/

static int make_table_resource_reply(int xid, char * buf, int buflen)
{
    struct pof_flow_table_resource * table_resource;
    const char fake[] =     // stolen from wireshark, total 88 bytes
            {
                    0x04, 0x0d, 0x00, 0x58, 0x00, 0x00, 0x15, 0xf3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
                    0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x01, 0x40,
                    0x00, 0x00, 0x17, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x02, 0x01, 0x40,
                    0x00, 0x00, 0x17, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x06, 0x01, 0x40,
                    0x00, 0x00, 0x17, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x07, 0x01, 0x40,
                    0x00, 0x00, 0x17, 0x70, 0x00, 0x00, 0x00, 0x00
            };

    assert(buflen> sizeof(fake));
    memcpy(buf, fake, sizeof(fake));
    table_resource = (struct pof_flow_table_resource *) buf;
    table_resource->header.version = POF_VERSION;
    table_resource->header.type = POFT_RESOURCE_REPORT;
    table_resource->header.xid = xid;
    return sizeof(fake);
}

/***********************************************************************/
static int make_port_status_reply(int xid, char * buf, int buflen)
{
    struct pof_port_status * port_status;
    const char fake[] =     // stolen from wireshark, total 136 bytes
            {
                    0x04, 0x0c, 0x00, 0x88, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0xa2, 0xe6, 0xec, 0x18, 0xd3, 0xdf, 0x00, 0x00,
                    0x73, 0x31, 0x2d, 0x65, 0x74, 0x68, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x0a,
                    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            };

    assert(buflen> sizeof(fake));
    memcpy(buf, fake, sizeof(fake));
    port_status = (struct pof_port_status *) buf;
    port_status->header.version = POF_VERSION;
    port_status->header.type = POFT_PORT_STATUS;
    port_status->header.xid = xid;
    return sizeof(fake);
}

/***********************************************************************
 *  return 1 if the embedded packet in the packet_out is lldp or bddp
 * 
 */

#ifndef ETHERTYPE_LLDP
#define ETHERTYPE_LLDP 0x88cc
#endif

#ifndef ETHERTYPE_BDDP
#define ETHERTYPE_BDDP 0x8942
#endif

static int packet_out_is_lldp(struct pof_packet_out * po){
	//char * ptr = (char *) po;
	//ptr += sizeof(struct ofp_packet_out) + ntohs(po->actions_len);
    char * ptr = po->data;
	struct ether_header * ethernet = (struct ether_header *) ptr;
	unsigned short ethertype = ntohs(ethernet->ether_type);
	if (ethertype == ETHERTYPE_VLAN) {
		ethernet = (struct ether_header *) ((char *) ethernet) +4;
		ethertype = ntohs(ethernet->ether_type);
	}
	
	return ethertype == ETHERTYPE_LLDP || ethertype == ETHERTYPE_BDDP;
}

/***********************************************************************/
static int make_packet_in(int switch_id, int xid, int buffer_id, char * buf, int buflen, int mac_address)
{
    struct pof_packet_in * pi;
    struct ether_header * eth;
    const char fake[] = {           // stolen from wireshark, total 130 bytes
            0x04, 0x0a, 0x00, 0x82, 0x00, 0x00, 0x00, 0x0e,
            0xff, 0xff, 0xff, 0xff, 0x00, 0x62, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x45, 0x00, 0x00, 0x54, 0xd5, 0xf1, 0x40, 0x00, 0x40, 0x01,
            0x50, 0xb5, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02, 0x08, 0x00, 0x76, 0xa3, 0x06, 0x7c,
            0x00, 0x01, 0x0c, 0xd0, 0x49, 0x59, 0x00, 0x00, 0x00, 0x00, 0x5e, 0xe3, 0x07, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
            0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37
    };
    assert(buflen> sizeof(fake));
    memcpy(buf, fake, sizeof(fake));
    pi = (struct pof_packet_in *) buf;
    pi->header.version = POF_VERSION;
    pi->header.xid = htonl(xid);
    pi->buffer_id = htonl(buffer_id);
    eth = (struct ether_header * ) pi->data;
    // copy into src mac addr; only 4 bytes, but should suffice to not confuse
    // the controller; don't overwrite first byte
    memcpy(&eth->ether_shost[1], &mac_address, sizeof(mac_address));
    // mark this as coming from us, mostly for debug
    eth->ether_dhost[5] = switch_id;
    eth->ether_shost[5] = switch_id;
    return sizeof(fake);
}

void fakeswitch_change_status_now (struct fakeswitch *fs, int new_status) {
    fs->switch_status = new_status;
    if(new_status == READY_TO_SEND) {
        fs->recv_count = 0;
        fs->probe_state = 0;
    }
        
}

void fakeswitch_change_status(struct fakeswitch *fs, int new_status) {
    if( fs->delay == 0) {
        fakeswitch_change_status_now(fs, new_status);
        debug_msg(fs, " switched to next status %d", new_status);
    } else {
        fs->switch_status = WAITING;
        fs->next_status = new_status;
        gettimeofday(&fs->delay_start, NULL);
        fs->delay_start.tv_sec += fs->delay / 1000;
        fs->delay_start.tv_usec += (fs->delay % 1000 ) * 1000;
        debug_msg(fs, " delaying next status %d by %d ms", new_status, fs->delay);
    }

}


/***********************************************************************/
void fakeswitch_handle_read(struct fakeswitch *fs)
{
    int count;
    struct pof_header * pofh;
    struct pof_header echo;
    //struct ofp_header barrier;
    char buf[BUFLEN];
    count = msgbuf_read(fs->inbuf, fs->sock);   // read any queued data
    if (count <= 0)
    {
        fprintf(stderr, "controller msgbuf_read() = %d:  ", count);
        if(count < 0)
            perror("msgbuf_read");
        else
            fprintf(stderr, " closed connection ");
        fprintf(stderr, "... exiting\n");
        exit(1);
    }
    while((count= msgbuf_count_buffered(fs->inbuf)) >= sizeof(struct pof_header ))
    {
        pofh = msgbuf_peek(fs->inbuf);
        if(count < ntohs(pofh->length))
            return;     // msg not all there yet
        msgbuf_pull(fs->inbuf, NULL, ntohs(pofh->length));
        pof_flow_entry * fm;
        struct pof_packet_out *po;
        switch(pofh->type)
        {
            case POFT_PACKET_OUT:
                po = (pof_packet_out *) pofh;
                if ( fs->switch_status == READY_TO_SEND && ! packet_out_is_lldp(po)) { 
                    // assume this is in response to what we sent
                    fs->recv_count++;        // got response to what we went
                    fs->probe_state--;
                }
                break;
            case POFT_FLOW_MOD:
                fm = (pof_flow_entry *) pofh;
                if(fs->switch_status == READY_TO_SEND && (fm->command == htons(POFFC_ADD) ||
                        fm->command == htons(POFFC_MODIFY_STRICT)))
                {
                    fs->recv_count++;        // got response to what we went
                    fs->probe_state--;
                }
                break;
            case POFT_TABLE_MOD:
                debug_msg(fs, "Got table_mode message");
                break;
            case POFT_FEATURES_REQUEST:
                // pull msgs out of buffer
                debug_msg(fs, "got feature_req");
                // Send features reply
                count = make_features_reply(fs->id, pofh->xid, buf, BUFLEN);
                msgbuf_push(fs->outbuf, buf, count);
                debug_msg(fs, "sent feature_rsp");
                fakeswitch_change_status(fs, fs->learn_dstmac ? LEARN_DSTMAC : READY_TO_SEND);
                break;
            case POFT_SET_CONFIG:
                // pull msgs out of buffer
                debug_msg(fs, "parsing set_config");
                parse_set_config(pofh);
                break;
            case POFT_GET_CONFIG_REQUEST:
                // pull msgs out of buffer
                debug_msg(fs, "got get_config_request");
                count = make_config_reply(fs->id, pofh->xid, buf, BUFLEN);
                msgbuf_push(fs->outbuf, buf, count);
                debug_msg(fs, "sent get_config_reply");

                count = make_table_resource_reply(pofh->xid, buf, BUFLEN);
                msgbuf_push(fs->outbuf, buf, count);
                debug_msg(fs, "send table resource report, length: %d", count);

                //the fake switch has two port, thus we need to send two port status message.
                count = make_port_status_reply(pofh->xid, buf, BUFLEN);
                msgbuf_push(fs->outbuf, buf, count);
                debug_msg(fs, "sent port status, length: %d", count);
                msgbuf_push(fs->outbuf, buf, count);
                debug_msg(fs, "sent port status, length: %d", count);


                if ((fs->mode == MODE_LATENCY)  && ( fs->probe_state == 1 )) {
                    fs->probe_state = 0;        // restart probe state b/c some
                                                // controllers block on config
                    debug_msg(fs, "reset probe state b/c of get_config_reply");
                }
                break;
            case POFT_HELLO:
                debug_msg(fs, "got hello");
                // we already sent our own HELLO; don't respond
                break;
            case POFT_ECHO_REQUEST:
                debug_msg(fs, "got echo, sent echo_resp");
                echo.version= POF_VERSION;
                echo.length = htons(sizeof(echo));
                echo.type   = POFT_ECHO_REPLY;
                echo.xid = pofh->xid;
                msgbuf_push(fs->outbuf,(char *) &echo, sizeof(echo));
                break;
            default: 
    //            if(fs->debug)
                    fprintf(stderr, "Ignoring POF message type %d\n", pofh->type);
        };
        if(fs->probe_state < 0)
        {
                debug_msg(fs, "WARN: Got more responses than probes!!: : %d",
                            fs->probe_state);
                fs->probe_state =0;
        }
    }
}
/***********************************************************************/
static void fakeswitch_handle_write(struct fakeswitch *fs)
{
    char buf[BUFLEN];
    int count ;
    int send_count = 0 ;
    int throughput_buffer = BUFLEN;
    int i;
    if( fs->switch_status == READY_TO_SEND) 
    {
        if ((fs->mode == MODE_LATENCY)  && ( fs->probe_state == 0 ))      
            send_count = 1;                 // just send one packet
        else if ((fs->mode == MODE_THROUGHPUT) && 
                (msgbuf_count_buffered(fs->outbuf) < throughput_buffer))  // keep buffer full
            send_count = (throughput_buffer - msgbuf_count_buffered(fs->outbuf)) / fs->probe_size;
        for (i = 0; i < send_count; i++)
        {
            // queue up packet
            
            fs->probe_state++;
            // TODO come back and remove this copy
            count = make_packet_in(fs->id, fs->xid++, fs->current_buffer_id, buf, BUFLEN, fs->current_mac_address);
            fs->current_mac_address = ( fs->current_mac_address + 1 ) % fs->total_mac_addresses;
            fs->current_buffer_id =  ( fs->current_buffer_id + 1 ) % NUM_BUFFER_IDS;
            msgbuf_push(fs->outbuf, buf, count);
            debug_msg(fs, "send message %d", i);
        }
        fs->send_count = fs->send_count + send_count;
    } else if( fs->switch_status == WAITING) 
    {
        struct timeval now;
        gettimeofday(&now, NULL);
        if (timercmp(&now, &fs->delay_start, > ))
        {
            fakeswitch_change_status_now(fs, fs->next_status);
            debug_msg(fs, " delay is over: switching to state %d", fs->next_status);
        }
    } else if (  fs->switch_status == LEARN_DSTMAC) 
    {
        // we should learn the dst mac addresses
        fakeswitch_learn_dstmac(fs);
        fakeswitch_change_status(fs, READY_TO_SEND);
    }
    // send any data if it's queued
    if( msgbuf_count_buffered(fs->outbuf) > 0)
        msgbuf_write(fs->outbuf, fs->sock, 0);
}
/***********************************************************************/
void fakeswitch_handle_io(struct fakeswitch *fs, const struct pollfd *pfd)
{
    if(pfd->revents & POLLIN)
        fakeswitch_handle_read(fs);
    if(pfd->revents & POLLOUT)
        fakeswitch_handle_write(fs);
}
/************************************************************************/
static int debug_msg(struct fakeswitch * fs, char * msg, ...)
{
    va_list aq;
    if(fs->debug == 0 )
        return 0;
    fprintf(stderr,"\n-------Switch %d: ", fs->id);
    va_start(aq,msg);
    vfprintf(stderr,msg,aq);
    if(msg[strlen(msg)-1] != '\n')
        fprintf(stderr, "\n");
    // fflush(stderr);     // should be redundant, but often isn't :-(
    return 1;
}
