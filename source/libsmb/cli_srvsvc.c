/* 
   Unix SMB/CIFS implementation.
   NT Domain Authentication SMB / MSRPC client
   Copyright (C) Andrew Tridgell 1994-2000
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000
   Copyright (C) Tim Potter 2001
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"

static BOOL init_srv_share_info_ctr(SRV_SHARE_INFO_CTR *ctr,
	       uint32 info_level, uint32 *resume_hnd, uint32 *total_entries, BOOL all_shares);

/* Opens a SMB connection to the svrsvc pipe */

struct cli_state *cli_svrsvc_initialise(struct cli_state *cli, 
					char *system_name,
					struct ntuser_creds *creds)
{
        return cli_pipe_initialise(cli, system_name, PIPE_SRVSVC, creds);
}

NTSTATUS cli_srvsvc_net_srv_get_info(struct cli_state *cli, 
                                     TALLOC_CTX *mem_ctx,
                                     uint32 switch_value, SRV_INFO_CTR *ctr)
{
	prs_struct qbuf, rbuf;
	SRV_Q_NET_SRV_GET_INFO q;
	SRV_R_NET_SRV_GET_INFO r;
	NTSTATUS result;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Initialise input parameters */

	init_srv_q_net_srv_get_info(&q, cli->srv_name_slash, switch_value);

	/* Marshall data and send request */

	if (!srv_io_q_net_srv_get_info("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SRV_NET_SRV_GET_INFO, &qbuf, &rbuf)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* Unmarshall response */

	r.ctr = ctr;

	if (!srv_io_r_net_srv_get_info("", &r, &rbuf, 0)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	result = werror_to_ntstatus(r.status);

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

NTSTATUS cli_srvsvc_srv_netshareenumall(struct cli_state *cli, 
                                     TALLOC_CTX *mem_ctx,
                                     uint32 info_level, SRV_SHARE_INFO_CTR *ctr)
{

	prs_struct qbuf, rbuf;
	SRV_Q_NET_SHARE_ENUM q;
	SRV_R_NET_SHARE_ENUM r;
    ENUM_HND hnd;
	NTSTATUS result;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Initialise input parameters */

    init_srv_q_net_share_enum(&q, cli->srv_name_slash, info_level, 
                                            0xffffffff, &hnd);

    uint32 entries = 1;
    uint32 resume_hnd = 0;
	if (init_srv_share_info_ctr(&q.ctr, info_level, &resume_hnd, &entries, True)) {
        DEBUG(5,("cli_srvsvc_srv_netshareenumall WERR_OK\n"));
	} else {
        DEBUG(5,("cli_srvsvc_srv_netshareenumall WERR_UNKNOWN_LEVEL\n"));
	}

	init_enum_hnd(&q.enum_hnd, resume_hnd);

	/* Marshall data and send request */

	if (!srv_io_q_net_share_enum("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SRV_NETSHAREENUM_ALL, &qbuf, &rbuf)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* Unmarshall response */


	if (!srv_io_r_net_share_enum("", &r, &rbuf, 0)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}
	*ctr = r.ctr;

	result = werror_to_ntstatus(r.status);

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/*******************************************************************
 Fill in a share info structure.
 ********************************************************************/

static BOOL init_srv_share_info_ctr(SRV_SHARE_INFO_CTR *ctr,
	       uint32 info_level, uint32 *resume_hnd, uint32 *total_entries, BOOL all_shares)
{
	int num_entries = 0;
	int snum;

	DEBUG(5,("init_srv_share_info_ctr\n"));

	ZERO_STRUCTPN(ctr);

	ctr->info_level = ctr->switch_value = info_level;
	*resume_hnd = 0;

	*total_entries = num_entries;
	ctr->num_entries2 = ctr->num_entries = num_entries;
    ctr->ptr_entries = 0;
    ctr->ptr_share_info = 0x00020004;
    ctr->share.info1 = NULL;

	if (!num_entries)
		return True;

	switch (info_level) {
	case 1:

	case 2:

	case 501:

	case 502:

	default:
		DEBUG(5,("init_srv_share_info_ctr: unsupported switch value %d\n", info_level));
		return False;
	}

	return True;
}
