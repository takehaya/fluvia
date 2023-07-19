/*
 * Copyright (c) 2023 NTT Communications Corporation
 * Copyright (c) 2023 Takeru Hayasaka 
 */

#define KBUILD_MODNAME "xdp_probe"
#include <stdbool.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/seg6.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "xdp_map.h"

SEC("xdp")   
int xdp_prog(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IPV6))
        return XDP_PASS;

    struct ipv6hdr *ipv6 = (void *)(eth + 1);
    if ((void *)(ipv6 + 1) > data_end)
        return XDP_PASS;

    // is srv6
    if (ipv6->nexthdr != IPPROTO_IPV6ROUTE)
        return XDP_PASS;

    struct srhhdr *srh = (void *)(ipv6 + 1);
    if ((void *)(srh + 1) > data_end)
        return XDP_PASS;

    if (srh->routingType != IPV6_SRCRT_TYPE_4) // IPV6_SRCRT_TYPE_4 = SRH
        return XDP_PASS;

    struct probe_data probe = {};
    __builtin_memcpy(&probe.h_source, &eth->h_source, ETH_ALEN);
    __builtin_memcpy(&probe.h_dest, &eth->h_dest, ETH_ALEN);
    probe.h_proto = eth->h_proto;
    probe.v6_srcaddr = ipv6->saddr;
    probe.v6_dstaddr = ipv6->daddr;

    probe.nextHdr = srh->nextHdr;
    probe.hdrExtLen = srh->hdrExtLen;
    probe.routingType = srh->routingType;
    probe.segmentsLeft = srh->segmentsLeft;
    probe.lastEntry = srh->lastEntry;
    probe.flags = srh->flags;
    probe.tag = srh->tag;

    for(int i=0; i<MAX_SEGMENTLIST_ENTRIES; i++ )
    {   
        if (!(i < probe.lastEntry + 1) )
            break;
        
        if ((void *)(data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct srhhdr) + sizeof(struct in6_addr) * (i + 1) + 1) > data_end)
            break;

        __builtin_memcpy(&probe.segments[i], &srh->segments[i], sizeof(struct in6_addr));
    }

    __u64 flags = BPF_F_CURRENT_CPU;
    bpf_perf_event_output(ctx, &perf_event_ipfix_probe_map, flags, &probe, sizeof(probe));  
    return XDP_PASS;
}

char _license[] SEC("license") = "MIT";
