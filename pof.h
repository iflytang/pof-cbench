/* Copyright (c) 2008 The Board of Trustees of The Leland Stanford
 * Junior University
 *
 * We are making the OpenFlow specification and associated documentation
 * (Software) available for public use and benefit with the expectation
 * that others will use, modify and enhance the Software and contribute
 * those enhancements back to the community. However, since we would
 * like to make the Software available for broadest use, with as few
 * restrictions as possible permission is hereby granted, free of
 * charge, to any person obtaining a copy of this Software to deal in
 * the Software under the copyrights without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * The name and trademarks of copyright holder(s) may NOT be used in
 * advertising or publicity pertaining to the Software or any
 * derivatives without specific, written prior permission.
 */

/* POF: protocol between controller and datapath. */

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

#ifdef SWIG
#define OFP_ASSERT(EXPR)        /* SWIG can't handle OFP_ASSERT. */
#elif !defined(__cplusplus)
/* Build-time assertion for use in a declaration context. */
#define OFP_ASSERT(EXPR)                                                \
        extern int (*build_assert(void))[ sizeof(struct {               \
                    unsigned int build_assert_failed : (EXPR) ? 1 : -1; })]
#else /* __cplusplus */
#define OFP_ASSERT(_EXPR) typedef int build_assert_failed[(_EXPR) ? 1 : -1]
#endif /* __cplusplus */

#ifndef SWIG
#define OFP_PACKED __attribute__((packed))
#else
#define OFP_PACKED              /* SWIG doesn't understand __attribute. */
#endif

#ifndef POF_MULTIPLE_SLOTS
#define POF_MULTIPLE_SLOTS
#endif

/*pof version*/
#define POF_VERSION (0x04)

#define OFP_MAX_TABLE_NAME_LEN 32
#define OFP_MAX_PORT_NAME_LEN  16

#define OFP_TCP_PORT  6633
#define OFP_SSL_PORT  6633

#define OFP_ETH_ALEN 6          /* Bytes in an Ethernet address. */

/*Define the length of device name.*/
#define POF_NAME_MAX_LENGTH   (64)

/* Bytes in an Ethernet address. */
#define POF_ETH_ALEN (6)

/*Define the max length in byte unit of match field.*/
#define POF_MAX_FIELD_LENGTH_IN_BYTE (16)

/*Define the max number of match field in one flow entry.*/
#define POF_MAX_MATCH_FIELD_NUM (8)

/*Define the max instruction number of one flow entry.*/
#define POF_MAX_INSTRUCTION_NUM (6)

/*Define the max length of packetin.*/
#define POF_PACKET_IN_MAX_LENGTH (2048)

/*Define the max instruction length in unit of byte.*/
#define POF_MAX_INSTRUCTION_LENGTH  (8 + POF_MAX_ACTION_NUMBER_PER_INSTRUCTION * (POF_MAX_ACTION_LENGTH + 4))

/*Define the max action number in one instruction.*/
#define POF_MAX_ACTION_NUMBER_PER_INSTRUCTION (6)

/*Define the max action number in one group.*/
#define POF_MAX_ACTION_NUMBER_PER_GROUP (4)

/*Define the max action length in unit of byte.*/
#define POF_MAX_ACTION_LENGTH (44)


/* Header on all POF packets. */
typedef struct pof_header{
    uint8_t  version; /* POF_VERSION. */
    uint8_t  type; /* One of the POFT_ constants. */
    uint16_t length; /* Length including this pof_header. */
    uint32_t xid; /* Transaction id associated with this packet.
                    Replies use the same id as was in the request to facilitate pairing. */
}pof_header;        //sizeof=8
OFP_ASSERT(sizeof(struct pof_header) == 8);

/*Define the pof command type.*/
typedef enum pof_type {
    /* Immutable messages. */
    POFT_HELLO = 0, /* Symmetric message */
    POFT_ERROR = 1, /* Symmetric message */
    POFT_ECHO_REQUEST = 2, /* Symmetric message */
    POFT_ECHO_REPLY = 3, /* Symmetric message */
    POFT_EXPERIMENTER = 4, /* Symmetric message */

    /* Switch configuration messages. */
    POFT_FEATURES_REQUEST = 5, /* Controller/switch message */
    POFT_FEATURES_REPLY = 6, /* Controller/switch message */
    POFT_GET_CONFIG_REQUEST = 7, /* Controller/switch message */
    POFT_GET_CONFIG_REPLY = 8, /* Controller/switch message */
    POFT_SET_CONFIG = 9, /* Controller/switch message */

    /* Asynchronous messages. */
    POFT_PACKET_IN = 10, /* Async message */
    POFT_FLOW_REMOVED = 11, /* Async message */
    POFT_PORT_STATUS = 12, /* Async message */
    POFT_RESOURCE_REPORT = 13,/* Async message */

    /* Controller command messages. */
    POFT_PACKET_OUT = 14, /* Controller/switch message */
    POFT_FLOW_MOD = 15, /* Controller/switch message */
    POFT_GROUP_MOD = 16, /* Controller/switch message */
    POFT_PORT_MOD = 17, /* Controller/switch message */
    POFT_TABLE_MOD = 18, /* Controller/switch message */

    /* Multipart messages. */
    POFT_MULTIPART_REQUEST = 19, /* Controller/switch message */
    POFT_MULTIPART_REPLY = 20, /* Controller/switch message */

    /* Barrier messages. */
    POFT_BARRIER_REQUEST = 21, /* Controller/switch message */
    POFT_BARRIER_REPLY = 22, /* Controller/switch message */

    /* Queue Configuration messages. */
    POFT_QUEUE_GET_CONFIG_REQUEST = 23, /* Controller/switch message */
    POFT_QUEUE_GET_CONFIG_REPLY = 24, /* Controller/switch message */

    /* Controller role change request messages. */
    POFT_ROLE_REQUEST = 25, /* Controller/switch message */
    POFT_ROLE_REPLY = 26, /* Controller/switch message */

    /* Asynchronous message configuration. */
    POFT_GET_ASYNC_REQUEST = 27, /* Controller/switch message */
    POFT_GET_ASYNC_REPLY = 28, /* Controller/switch message */
    POFT_SET_ASYNC = 29, /* Controller/switch message */

    /* Meters and rate limiters configuration messages. */
    POFT_METER_MOD = 30, /* Controller/switch message */

    /*Conter message*/
    POFT_COUNTER_MOD = 31, /* Controller/switch message */
    POFT_COUNTER_REQUEST = 32, /* Controller/switch message */
    POFT_COUNTER_REPLY = 33, /* Controller/switch message */

    /*Query all message*/
    POFT_QUERYALL_REQUEST = 34, /* Controller to switch message. */
    POFT_QUERYALL_FIN = 35,     /* Switch to controller message when finished sending all
                                 * queried message. */
#ifdef POF_SHT_VXLAN
    /* Instruction Block Message. */
    POFT_INSTRUCTION_BLOCK_MOD = 36,

    /* Enable/Disable POF forwarding of one designated slot. */
    POFT_SLOT_CONFIG = 101,

    /* Slot status message from device to controller. */
    POFT_SLOT_STATUS = 102
#endif // POF_SHT_VXLAN
}pof_type;

/* Table commands */
typedef enum pof_table_mod_command {
    POFTC_ADD = 0, /* New table. */
    POFTC_MODIFY = 1, /* Modify specified table. */
    POFTC_DELETE = 2, /* Delete specified table. */
    POFTC_QUERY = 3,
    POFTC_QUERY_RESULT = 4,
}pof_table_mod_command;

/* flow commands */
typedef enum pof_flow_mod_command {
    POFFC_ADD = 0, /* New flow. */
    POFFC_MODIFY = 1, /* Modify all matching flows. */
    POFFC_MODIFY_STRICT = 2, /* Modify entry strictly matching wildcards and priority. */
    POFFC_DELETE = 3, /* Delete all matching flows. */
    POFFC_DELETE_STRICT = 4, /* Delete entry strictly matching wildcards and priority. */
    POFFC_QUERY = 5,
    POFFC_QUERY_RESULT = 6,
}pof_flow_mod_command;

/*Pof hello message. It has an empty body*/
struct pof_hello {
    pof_header header;
};

/*Upon session establishment, the controller sends an POFT_FEATURES_REQUEST message.
This message does not contain a body beyond the OpenFlow header.*/
typedef struct pof_switch_features{
    pof_header header;
    uint32_t dev_id;
#ifdef POF_MULTIPLE_SLOTS
    uint16_t slotID;
#endif // POF_MULTIPLE_SLOTS
    uint16_t port_num;
    uint16_t table_num;

#ifdef POF_MULTIPLE_SLOTS
    uint8_t pad[2];
    uint32_t capabilities;
#else //  POF_MULTIPLE_SLOTS
    uint32_t capabilities;
    uint8_t   pad[4];
#endif // POF_MULTIPLE_SLOTS

    char     vendor_id[POF_NAME_MAX_LENGTH];
    char     dev_fw_id[POF_NAME_MAX_LENGTH]; /*device forward engine ID*/
    char     dev_lkup_id[POF_NAME_MAX_LENGTH]; /*device lookup engine ID*/
}pof_switch_features;  //sizeof = 16 + 3*64 = 208

/* Switch configuration */
typedef struct pof_switch_config{
    pof_header header;
#ifdef POF_MULTIPLE_SLOTS
    uint32_t dev_id;
#endif // POF_MULTIPLE_SLOTS
    uint16_t flags;         /* POFC_* flags. */
    uint16_t miss_send_len; /* Max bytes of packet tha datapath
                               should send to the controller. See
                               pof_controller_max_len for valid values.*/
}pof_switch_config;  // sizeof() = 16

enum pof_config_flags{
    POFC_FRAG_NORMAL = 0,      /* No special handling for fragments. */
    POFC_FRAG_DROP   = 1 << 0, /* Drop fragments. */
    POFC_FRAG_REASM  = 1 << 1, /* Reassemble (only if POFC_IP_REASM set). */
    POFC_FRAG_MASK   = 3
};

/* What changed about the physical port */
enum pof_port_reason {
    POFPR_ADD = 0, /* The port was added. */
    POFPR_DELETE = 1, /* The port was removed. */
    POFPR_MODIFY = 2, /* Some attribute of the port has changed. */
};


/* Infomation of ports */
typedef enum pof_port_config {
    POFPC_PORT_UP = 0, /* Port is administratively up. */
    POFPC_PORT_DOWN = 1 << 0, /* Port is administratively down. */
    POFPC_NO_RECV = 1 << 2, /* Drop all packets received by port. */
    POFPC_NO_FWD = 1 << 5, /* Drop packets forwarded to port. */
    POFPC_NO_PACKET_IN = 1 << 6 /* Do not send packet-in msgs for port. */
}pof_port_config;

typedef enum pof_port_state {
    POFPS_LINK_DOWN = 1 << 0, /* No physical link present. */
    POFPS_BLOCKED = 1 << 1, /* Port is blocked */
    POFPS_LIVE = 1 << 2, /* Live for Fast Failover Group. */
}pof_port_state;

/* Port numbering. Ports are numbered starting from 1. */
typedef enum pof_port_id {
    /* Maximum number of physical and logical switch ports. */
            POFP_MAX = 0xffffff00,

    /* Reserved OpenFlow Port (fake output "ports"). */
            POFP_IN_PORT = 0xfffffff8, /* Send the packet out the input port. This reserved port must
                                be explicitly used in order to send back out of the input port. */
    POFP_TABLE = 0xfffffff9, /* Submit the packet to the first flow table NB: This destination port can only be
                                 used in packet-out messages. */
    POFP_NORMAL = 0xfffffffa, /* Process with normal L2/L3 switching. */
    POFP_FLOOD = 0xfffffffb, /* All physical ports in VLAN, except input port and those blocked or link down. */
    POFP_ALL = 0xfffffffc, /* All physical ports except input port. */
    POFP_CONTROLLER = 0xfffffffd, /* Send to controller. */
    POFP_LOCAL = 0xfffffffe, /* Local openflow "port". */

    POFP_ANY = 0xffffffff /* Wildcard port used only for flow mod (delete) and flow stats requests. Selects
                              all flows regardless of output port (including flows with no output port). */
}pof_port_id;

/* Capabilities supported by the datapath. */
enum pof_capabilities {
    POFC_FLOW_STATS = 1 << 0, /* Flow statistics. */
    POFC_TABLE_STATS = 1 << 1, /* Table statistics. */
    POFC_PORT_STATS = 1 << 2, /* Port statistics. */
    POFC_GROUP_STATS = 1 << 3, /* Group statistics. */
    POFC_IP_REASM = 1 << 5, /* Can reassemble IP fragments. */
    POFC_QUEUE_STATS = 1 << 6, /* Queue statistics. */
    POFC_PORT_BLOCKED = 1 << 8 /* Switch will block looping ports. */
};


/* Features of ports available in a datapath. */
typedef enum pof_port_features{
    POFPF_10MB_HD = 1 << 0, /* 10 Mb half-duplex rate support. */
    POFPF_10MB_FD = 1 << 1, /* 10 Mb full-duplex rate support. */
    POFPF_100MB_HD = 1 << 2, /* 100 Mb half-duplex rate support. */
    POFPF_100MB_FD = 1 << 3, /* 100 Mb full-duplex rate support. */
    POFPF_1GB_HD = 1 << 4, /* 1 Gb half-duplex rate support. */
    POFPF_1GB_FD = 1 << 5, /* 1 Gb full-duplex rate support. */
    POFPF_10GB_FD = 1 << 6, /* 10 Gb full-duplex rate support. */
    POFPF_40GB_FD = 1 << 7, /* 40 Gb full-duplex rate support. */
    POFPF_100GB_FD = 1 << 8, /* 100 Gb full-duplex rate support. */
    POFPF_1TB_FD = 1 << 9, /* 1 Tb full-duplex rate support. */
    POFPF_OTHER = 1 << 10, /* Other rate, not in the list. */
    POFPF_COPPER = 1 << 11, /* Copper medium. */
    POFPF_FIBER = 1 << 12, /* Fiber medium. */
    POFPF_AUTONEG = 1 << 13, /* Auto-negotiation. */
    POFPF_PAUSE = 1 << 14, /* Pause. */
    POFPF_PAUSE_ASYM = 1 << 15 /* Asymmetric pause. */
}pof_port_features;

/* Describe the match struct, including the location, the length and the value. */
typedef struct pof_match{
    uint16_t field_id;  /*0xffff means metadata,
                          0x8XXX means from table parameter,
                          otherwise means from packet data. */
    uint16_t offset; /*bit unit*/
    uint16_t len;   /*length in bit unit*/
    uint8_t pad[2];   /*8 bytes aligned*/
}pof_match;         //sizeof=8
typedef struct pof_match_x{
    uint16_t field_id;  /*0xffff means metadata,
                          0x8XXX means from table parameter,
                          otherwise means from packet data. */
    uint16_t offset;  /*bit unit*/
    uint16_t len;    /*length in bit unit*/
    uint8_t pad[2];   /*8 bytes aligned*/

    uint8_t value[POF_MAX_FIELD_LENGTH_IN_BYTE];
    uint8_t mask[POF_MAX_FIELD_LENGTH_IN_BYTE];
}pof_match_x;       //sizeof=8+2*16=40

/* Discribe the instruction struct. */
typedef struct pof_instruction{
    uint16_t type;
    uint16_t len;
    uint8_t pad[4];   /*8 bytes aligned*/
#ifdef POF_SHT_VXLAN
    uint8_t  instruction_data[0];
#else // POF_SHT_VXLAN
    uint8_t  instruction_data[POF_MAX_INSTRUCTION_LENGTH];
    /*Store the real instruction data such as "Goto-Table" */
#endif // POF_SHT_VXLAN
}pof_instruction;       //sizeof=8+(8+(6*(44+4)))=304

/* Describe the flow table struct including key length, table type.*/
typedef struct pof_flow_table{
    pof_header header;
    uint8_t command;
    uint8_t tid;              /*table ID*/
    uint8_t type;            /*table type*/
    uint8_t match_field_num;  /*the number of match fields.*/
    uint32_t size;            /*table size*/

    uint16_t key_len;         /*The max sum of length of all match fields*/
    uint16_t slotID;            /* For multiple slots. */
    uint8_t pad[4];             /*8 bytes aligned*/

    char table_name[POF_NAME_MAX_LENGTH];
    pof_match match[POF_MAX_MATCH_FIELD_NUM];
}pof_flow_table;        //size = 16 + 64 + 8*8 = 144

/* Discribe the flow entry struct. */
#ifdef POF_SHT_VXLAN
typedef struct pof_flow_entry{
    uint8_t command;
    uint8_t match_field_num;
    uint8_t pad[2];   /*8 bytes aligned*/
    uint32_t counter_id;

    uint64_t cookie;
    uint64_t cookie_mask;

    uint8_t table_id;
    uint8_t table_type;   /*table type: MM,LPM,EM,DT*/
    uint16_t idle_timeout;
    uint16_t hard_timeout;
    uint16_t priority;

    uint32_t  index;
    uint16_t slotID;            /* For multiple slots. */
    uint8_t pad2[2];   /*8 bytes aligned*/

    pof_match_x match[POF_MAX_MATCH_FIELD_NUM];    /*The match fields.  */
    /* The id of the target instruction block.
     * The value 0xFFFFFFFF means the instruction block is carried in this
     * flow entry structure directly.*/
    uint16_t instruction_block_id;
    uint16_t parameter_length;  /* Length of the following parameters fields in unit of bit. */
    uint8_t pad3[4];
    uint8_t parameters[0];  /* The parameters of the flow instructions. */
}pof_flow_entry;        //sizeof=40+8*40+6*304=2184
#else // POF_SHT_VXLAN
typedef struct pof_flow_entry{
    pof_header header;
    uint8_t command;
    uint8_t match_field_num;
    uint8_t instruction_num;
    uint8_t pad[1];   /*8 bytes aligned*/
    uint32_t counter_id;

    uint64_t cookie;
    uint64_t cookie_mask;

    uint8_t table_id;
    uint8_t table_type;   /*table type: MM,LPM,EM,DT*/
    uint16_t idle_timeout;
    uint16_t hard_timeout;
    uint16_t priority;

    uint32_t  index;
    uint16_t slotID;            /* For multiple slots. */
    uint8_t pad2[2];   /*8 bytes aligned*/

    pof_match_x match[POF_MAX_MATCH_FIELD_NUM];    /*The match fields.  */
    pof_instruction instruction[POF_MAX_INSTRUCTION_NUM]; /*The instructions*/
}pof_flow_entry;        //sizeof=8+40+8*40+6*304=2192
#endif // POF_SHT_VXLAN

typedef struct pof_table_resource_desc{
    uint32_t device_id;
    uint8_t  type; /*table type: MM or EM or LPM */
    uint8_t  tbl_num; /*table number*/
    uint16_t key_len;   /*key length*/

    uint32_t total_size; /*the  total number of EM entry*/
    uint8_t pad[4];   /*8 bytes aligned*/
}pof_table_resource_desc;       //sizeof=16

typedef enum pof_table_type{
    POF_MM_TABLE = 0,
    POF_LPM_TABLE,
    POF_EM_TABLE,
    POF_LINEAR_TABLE,
    POF_MAX_TABLE_TYPE
}pof_table_type;

typedef struct pof_flow_table_resource{
    pof_header header;
    uint8_t resourceType;
#ifdef POF_MULTIPLE_SLOTS
    uint8_t pad;    /* 8 bytes aligned. */
    uint16_t slotID;
#else // POF_MULTIPLE_SLOTS
    uint8_t pad[3];   /*24 bytes aligned*/
#endif // POF_MULTIPLE_SLOTS
    uint32_t counter_num; /*Counter number*/

    uint32_t meter_num; /*Meter number*/
    uint32_t group_num; /*Group number*/

    pof_table_resource_desc tbl_rsc_desc[POF_MAX_TABLE_TYPE]; /*All table resource information*/

}pof_flow_table_resource;       //sizeof=POF_MAX_TABLE_TYPE * 16 + 16 + 8 = 88

typedef struct pof_port{
#ifdef POF_MULTIPLE_SLOTS
    uint16_t slotID;
    uint16_t port_id;
#else // POF_MULTIPLE_SLOTS
    uint32_t port_id;  /*Port numberring */
#endif // POF_MULTIPLE_SLOTS
    uint32_t device_id; /*The device id*/

    uint8_t hw_addr[POF_ETH_ALEN];
    uint8_t pad[2];

    char    name[POF_NAME_MAX_LENGTH];

    uint32_t config; /*Bitmap of POFPC_* */
    uint32_t state; /* Bitmap of POFPS_**/

    /*Port features described by POFPF_* */
    uint32_t curr;   /* port current features described by POFPF_* */
    uint32_t advertised;   /* Advertised features described by POFPF_* */
    uint32_t supported;   /* Supported features described by POFPF_* */
    uint32_t peer;   /* features advertised by peer.  */

    uint32_t curr_speed;
    uint32_t max_speed;

    uint8_t of_enable; /*indicate whether openflow is enabled */
    uint8_t pad2[7];   /*8 bytes aligned*/
}pof_port;  //

typedef struct pof_port_status{
    pof_header header;
    uint8_t reason; /* One of POFPR_*. */
    uint8_t pad[7]; /* Align to 64-bits. */
    pof_port desc;
}pof_port_status; //sizeof = 136

/* Describe the packet struct upward to Controller. */
typedef struct pof_packet_in {
    pof_header header;
    uint32_t buffer_id; /*Buffer ID assigned by datapath. 0xffffffff means invalid buffer id*/
    uint16_t total_len; /*Full length of the packet. */
    uint8_t  reason;  /*Reason that packet is sent.*/
    uint8_t  table_id; /*ID of the table that was looked up*/

    uint64_t cookie; /*Cookie of the flow entry that was looked up*/

    uint32_t device_id;
#if 0
    #ifdef POF_MULTIPLE_SLOTS
    uint16_t slotID;
    uint16_t port_id;
#else // POF_MULTIPLE_SLOTS
    uint8_t pad[4];   /*8 bytes aligned*/
#endif // POF_MULTIPLE_SLOTS
#endif // caiqishen 00219933 要求packetIn带有port信息。
    uint16_t slotID;
    uint16_t port_id;

    char    data[POF_PACKET_IN_MAX_LENGTH];
} pof_packet_in;    //sizeof=32 + 2048 = 2072

/* Why is this packet being sent to the controller? */
enum pof_packet_in_reason {
    POFR_NO_MATCH = 0, /* No matching flow (table-miss flow entry). */
    POFR_ACTION = 1, /* Action explicitly output to controller. */
    POFR_INVALID_TTL = 2, /* Packet has invalid TTL */
};

/* Describe the action struct. */
typedef struct pof_action{
    uint16_t type;
    uint16_t len;
#ifdef POF_SHT_VXLAN
    uint8_t rsv[4];
    uint8_t action_data[0];
#else // POF_SHT_VXLAN
    uint8_t  action_data[POF_MAX_ACTION_LENGTH];
#endif // POF_SHT_VXLAN
}pof_action;    //sizof=4+44=48, NOTES: POFAction header size is 4


/*Describe the packet out struct comes from controller*/
typedef struct pof_packet_out{
    pof_header header;
    uint32_t bufferId;
    uint32_t inPort;
    uint8_t actionNum;
    uint8_t padding[3];
    uint32_t packetLen;
    pof_action actionList[POF_MAX_ACTION_NUMBER_PER_INSTRUCTION];
    char data[POF_PACKET_IN_MAX_LENGTH];
}pof_packet_out; //sizeof = 8 + 16 + 48*6 + 2048 = 2360

typedef struct pof_role_request{
    pof_header header;
    uint8_t role; /*TODO: add padding bytes to the message*/
}pof_role_request;

typedef struct pof_role_reply{
    pof_header header;
    uint8_t role; /*TODO: add padding bytes to the message*/
}pof_role_reply;

typedef enum pof_role_type{
    ROLE_NOCHANGE,
    ROLE_EQUAL,
    ROLE_MASTER,
    ROLE_SLAVE
}pof_role_type;