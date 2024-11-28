//////////////////////////////////////////////////////////////////////////////
// This file is part of 'wireshark-rssi'.
// It is subject to the license terms in the LICENSE.txt file found in the 
// top-level directory of this distribution and at: 
//    https://confluence.slac.stanford.edu/display/ppareg/LICENSE.html. 
// No part of 'wireshark-rssi', including this file, 
// may be copied, modified, propagated, or distributed except according to 
// the terms contained in the LICENSE.txt file.
//////////////////////////////////////////////////////////////////////////////
#include <epan/packet.h>
#include <epan/epan_dissect.h>
#include <epan/plugin_if.h>

#include "cksum.h"

/* Compat with <4.0 */
#ifndef WIRESHARK_VERSION_MAJOR
#   include <wireshark/config.h>
#   define WIRESHARK_VERSION_MAJOR VERSION_MAJOR
#   define WIRESHARK_VERSION_MINOR VERSION_MINOR
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

#define EXPORT_SYM __attribute__((visibility("default")))

#define PLUGIN_VERSION "0.1.0"

EXPORT_SYM const gchar plugin_version[] = PLUGIN_VERSION;
EXPORT_SYM const gchar version[] = PLUGIN_VERSION; /* For old API */
EXPORT_SYM int plugin_want_major = WIRESHARK_VERSION_MAJOR;
EXPORT_SYM int plugin_want_minor = WIRESHARK_VERSION_MINOR;

static int rssi_proto = -1;

// RSSI header fields
static int hf_rssi_hdr_len = -1;
static int hf_rssi_flags = -1;
static int hf_rssi_seq_num = -1;
static int hf_rssi_ack_num = -1;
static int hf_rssi_spare = -1;
static int hf_rssi_checksum = -1;
static int hf_rssi_flag_busy = -1;
static int hf_rssi_flag_nul = -1;
static int hf_rssi_flag_rst = -1;
static int hf_rssi_flag_eac = -1;
static int hf_rssi_flag_ack = -1;
static int hf_rssi_flag_syn = -1;

// RSSI SYN header fields
static int hf_rssi_syn_flags = -1;
static int hf_rssi_syn_version = -1;
static int hf_rssi_syn_max_out_segs = -1;
static int hf_rssi_syn_max_seg_size = -1;
static int hf_rssi_syn_retrans_timeo = -1;
static int hf_rssi_syn_cum_ack_timeo = -1;
static int hf_rssi_syn_null_timeo = -1;
static int hf_rssi_syn_max_retrans = -1;
static int hf_rssi_syn_max_cum_ack = -1;
static int hf_rssi_syn_max_oseq = -1;
static int hf_rssi_syn_timeo_unit = -1;
static int hf_rssi_syn_connid = -1;
static int hf_rssi_syn_flag_chk = -1;

static int rssi_ett = -1;

#define RSSI_FLAG_BUSY (1<<0)
#define RSSI_FLAG_NUL  (1<<3)
#define RSSI_FLAG_RST  (1<<4)
#define RSSI_FLAG_EAC  (1<<5)
#define RSSI_FLAG_ACK  (1<<6)
#define RSSI_FLAG_SYN  (1<<7)

#pragma pack(1)
typedef struct {
    uint8_t hdr_len;
    uint8_t flags;
    uint8_t ack_num;
    uint8_t seq_num;
} rssi_common_hdr_t;
#pragma pack()

static int rssi_dissect(tvbuff_t* tvb, packet_info* pinfo, proto_tree* ptree, void* data)
{
    if (tvb_reported_length(tvb) < sizeof(rssi_common_hdr_t))
        return 0;

    const uint8_t flags = tvb_get_bits8(tvb, 0, 8);
    const int is_syn = flags & RSSI_FLAG_SYN;

    proto_tree* tree = proto_tree_add_subtree(ptree, tvb, 0, -1, rssi_ett, NULL, "SLAC Reliable Streaming Protocol (RSSI)");

    int offset = 0;
    // Begin common header items
    proto_tree_add_item(tree, hf_rssi_flags, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_rssi_flag_syn, tvb, offset, 1, ENC_LITTLE_ENDIAN); // Flag bits...
    proto_tree_add_item(tree, hf_rssi_flag_ack, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_rssi_flag_eac, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_rssi_flag_rst, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_rssi_flag_nul, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_rssi_flag_busy, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rssi_hdr_len, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rssi_seq_num, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_rssi_ack_num, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    // End common header items

    // Add syn header fields
    if (is_syn) {
        // These two fields are contained in the same byte
        proto_tree_add_item(tree, hf_rssi_syn_flags, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_rssi_syn_flag_chk, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_rssi_syn_version, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
        proto_tree_add_item(tree, hf_rssi_syn_max_out_segs, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;

        proto_tree_add_item(tree, hf_rssi_syn_max_seg_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_rssi_syn_retrans_timeo, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_rssi_syn_cum_ack_timeo, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_rssi_syn_null_timeo, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_rssi_syn_max_retrans, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
        proto_tree_add_item(tree, hf_rssi_syn_max_cum_ack, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;

        proto_tree_add_item(tree, hf_rssi_syn_max_oseq, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
        proto_tree_add_item(tree, hf_rssi_syn_timeo_unit, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;

        proto_tree_add_item(tree, hf_rssi_syn_connid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_rssi_checksum, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    }
    // Add remaining normal header fields
    else {
        offset += 2; // Spare
        proto_tree_add_item(tree, hf_rssi_checksum, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        //proto_tree_add_checksum(tree, tvb, offset, hf_rssi_checksum, -1, NULL, NULL,)
    }

    return tvb_captured_length(tvb);
}

static hf_register_info rssi_header_fields[] = {
    {
        &hf_rssi_flags,
        {
            "Flags",
            "rssi.hdr.flags",
            FT_UINT8,
            BASE_HEX,
            NULL,
            0x0,
            "Header flags"
        }
    },
    /*================ Begin flags ================*/
    {
        &hf_rssi_flag_busy,
        {
            "BUSY",
            "rssi.hdr.flags.busy",
            FT_UINT8,
            BASE_HEX,
            NULL,
            RSSI_FLAG_BUSY,
            "Busy"
        }
    },
    {
        &hf_rssi_flag_nul,
        {
            "NUL",
            "rssi.hdr.flags.nul",
            FT_UINT8,
            BASE_HEX,
            NULL,
            RSSI_FLAG_NUL,
            "Nul"
        }
    },
    {
        &hf_rssi_flag_rst,
        {
            "RST",
            "rssi.hdr.flags.rst",
            FT_UINT8,
            BASE_HEX,
            NULL,
            RSSI_FLAG_RST,
            "RST"
        }
    },
    {
        &hf_rssi_flag_eac,
        {
            "EAC",
            "rssi.hdr.flags.eac",
            FT_UINT8,
            BASE_HEX,
            NULL,
            RSSI_FLAG_EAC,
            "EAC"
        }
    },
    {
        &hf_rssi_flag_ack,
        {
            "ACK",
            "rssi.hdr.flags.ack",
            FT_UINT8,
            BASE_HEX,
            NULL,
            RSSI_FLAG_ACK,
            "ACK"
        }
    },
    {
        &hf_rssi_flag_syn,
        {
            "SYN",
            "rssi.hdr.flags.syn",
            FT_UINT8,
            BASE_HEX,
            NULL,
            RSSI_FLAG_SYN,
            "SYN"
        }
    },
    /*================ End flags ================*/
    {
        &hf_rssi_hdr_len,
        {
            "Header Length",
            "rssi.hdr.hdr_len",
            FT_UINT8,
            BASE_DEC_HEX,
            NULL,
            0x0,
            "Header length"
        }
    },
    {
        &hf_rssi_seq_num,
        {
            "Sequence Num",
            "rssi.hdr.seq_num",
            FT_UINT8,
            BASE_DEC_HEX,
            NULL,
            0x0,
            "Sequence number"
        }
    },
    {
        &hf_rssi_ack_num,
        {
            "Ack Num",
            "rssi.hdr.ack_num",
            FT_UINT8,
            BASE_DEC_HEX,
            NULL,
            0x0,
            "Ack number"
        }
    },
    {
        &hf_rssi_spare,
        {
            "Spare",
            "rssi.hdr.spare",
            FT_UINT16,
            BASE_HEX,
            NULL,
            0x0,
            "Spare (Unused)"
        }
    },
    {
        &hf_rssi_checksum,
        {
            "Header Checksum",
            "rssi.hdr.checksum",
            FT_UINT16,
            BASE_HEX,
            NULL,
            0x0,
            "Header checksum"
        }
    }
};

static hf_register_info rssi_syn_header_fields[] = {
    /* Reuse header fields in rssi_header_fields (up until ack number) */
    {
        &hf_rssi_syn_version,
        {
            "Version",
            "rssi.syn.version",
            FT_UINT8,
            BASE_DEC_HEX,
            NULL,
            0xF0,
            "RSSI Version"
        }
    },
    {
        &hf_rssi_syn_flags,
        {
            "Syn Header Flags",
            "rssi.syn.flags",
            FT_UINT8,
            BASE_HEX,
            NULL,
            0x0F,
            "Syn flags"
        }
    },
    {
        &hf_rssi_syn_max_out_segs,
        {
            "Max Outstanding Segs",
            "rssi.syn.max_oseg",
            FT_UINT8,
            BASE_DEC_HEX,
            NULL,
            0x0,
            "Max outstanding segments"
        }
    },
    {
        &hf_rssi_syn_max_seg_size,
        {
            "Max Segment Size",
            "rssi.syn.max_seg_size",
            FT_UINT16,
            BASE_DEC_HEX,
            NULL,
            0x0,
            "Max segment size"
        }
    },
    {
        &hf_rssi_syn_retrans_timeo,
        {
            "Retransmision Timeout",
            "rssi.syn.retrans_timeo",
            FT_UINT16,
            BASE_DEC_HEX,
            NULL,
            0x0,
            "Retransmission timeout"
        }
    },
    {
        &hf_rssi_syn_cum_ack_timeo,
        {
            "Cumulative Ack Timeout",
            "rssi.syn.cum_ack_timeo",
            FT_UINT16,
            BASE_DEC_HEX,
            NULL,
            0x0,
            "Cumulative ack timeout"
        }
    },
    {
        &hf_rssi_syn_null_timeo,
        {
            "NULL Timeout",
            "rssi.syn.null_timeo",
            FT_UINT16,
            BASE_DEC_HEX,
            NULL,
            0x0,
            "Null timeout"
        }
    },
    {
        &hf_rssi_syn_max_retrans,
        {
            "Max Retransmissions",
            "rssi.syn.max_retrans",
            FT_UINT8,
            BASE_DEC_HEX,
            NULL,
            0x0,
            "Max retransmissions"
        }
    },
    {
        &hf_rssi_syn_max_cum_ack,
        {
            "Max Cumulative Ack",
            "rssi.syn.max_cum_ack",
            FT_UINT8,
            BASE_DEC_HEX,
            NULL,
            0x0,
            "Max number of cumulative ack"
        }
    },
    {
        &hf_rssi_syn_max_oseq,
        {
            "Max out-of-sequence ack",
            "rssi.syn.max_oseq_ack",
            FT_UINT8,
            BASE_DEC_HEX,
            NULL,
            0x0,
            "Max out-of-sequence acks"
        }
    },
    {
        &hf_rssi_syn_timeo_unit,
        {
            "Timeout Unit",
            "rssi.syn.timeo_unit",
            FT_UINT8,
            BASE_DEC_HEX,
            NULL,
            0x0,
            "Timeout unit"
        }
    },
    {
        &hf_rssi_syn_connid,
        {
            "Connection ID",
            "rssi.syn.connid",
            FT_UINT32,
            BASE_DEC_HEX,
            NULL,
            0x0,
            "Connection ID"
        }
    },
    {
        &hf_rssi_syn_flag_chk,
        {
            "CHK",
            "rssi.syn.flags.chk",
            FT_UINT8,
            BASE_DEC_HEX,
            NULL,
            0x4,
            "CHK"
        }
    },
};

/* Exported for old versions of wireshark that directly call this for us */
EXPORT_SYM void plugin_reg_handoff() {
    dissector_handle_t handle = create_dissector_handle(rssi_dissect, rssi_proto);
    dissector_add_uint_with_preference("udp.port", 12000, handle);
}

void plugin_register_proto() {
    rssi_proto = proto_register_protocol("Reliable SLAC Streaming Protocol (RSSI)", "RSSI", "rssi");

    int* etts[] = {&rssi_ett};
    proto_register_subtree_array(etts, array_length(etts));

    /* Register header fields */
    proto_register_field_array(rssi_proto, rssi_header_fields, array_length(rssi_header_fields));

    /* Register syn header fields */
    proto_register_field_array(rssi_proto, rssi_syn_header_fields, array_length(rssi_syn_header_fields));
}

/* Entry point-- called by wireshark on load */
EXPORT_SYM void plugin_register() {
    static proto_plugin plugin;

    plugin.register_protoinfo = plugin_register_proto;
    plugin.register_handoff = plugin_reg_handoff;
    proto_register_plugin(&plugin);
}
