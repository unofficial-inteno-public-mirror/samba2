/* 
   Unix SMB/CIFS implementation.
   RPC pipe client

   Copyright (C) Andrew Tridgell 1992-1999
   Copyright (C) Luke Kenneth Casson Leighton 1996 - 1999
   Copyright (C) Tim Potter 2000

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
#include "rpcclient.h"


typedef enum action_type {
ACTION_HEADER,
ACTION_ENUMERATE,
ACTION_FOOTER
} action_type_e;

/****************************************************************************
convert a share type enum to a string
****************************************************************************/
char *get_share_type_str(uint32 type)
{
	static fstring typestr;

	switch (type)
	{
		case STYPE_DISKTREE: fstrcpy(typestr, "Disk"   ); break;
		case STYPE_PRINTQ  : fstrcpy(typestr, "Printer"); break;	      
		case STYPE_DEVICE  : fstrcpy(typestr, "Device" ); break;
		case STYPE_IPC     : fstrcpy(typestr, "IPC"    ); break;      
		default            : fstrcpy(typestr, "????"   ); break;      
	}
	return typestr;
}

/****************************************************************************
print shares on a host
****************************************************************************/
void display_share(FILE *out_hnd, enum action_type action,
				char *sname, uint32 type, char *comment)
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			break;
		}
		case ACTION_ENUMERATE:
		{
			fprintf(out_hnd, "{share=\"%.15s\", type=\"%.10s\", %s}\n",
			                 sname, get_share_type_str(type), comment);
			break;
		}
		case ACTION_FOOTER:
		{
			break;
		}
	}
}


/****************************************************************************
print shares on a host, level 2
****************************************************************************/
void display_share2(FILE *out_hnd, enum action_type action,
				char *sname, uint32 type, char *comment,
				uint32 perms, uint32 max_uses, uint32 num_uses,
				char *path, char *passwd)
{
	switch (action)
	{
		case ACTION_HEADER:
		{
			break;
		}
		case ACTION_ENUMERATE:
		{
			fprintf(out_hnd, "\t%-15.15s%-10.10s%s %x %x %x %s %s\n",
			                 sname, get_share_type_str(type), comment,
			                 perms, max_uses, num_uses, path, passwd);
			break;
		}
		case ACTION_FOOTER:
		{
			break;
		}
	}
}

/****************************************************************************
share info level 1 display function
****************************************************************************/
void display_share_info_1(FILE *out_hnd, enum action_type action,
			  SRV_SHARE_INFO_1 *info1)
{
	if (info1 == NULL)
	{
		return;
	}

	switch (action)
	{
		case ACTION_HEADER:
		{
			//fprintf(out_hnd, "Share Info Level 1:\n");

			break;
		}
		case ACTION_ENUMERATE:
		{
			fstring remark  ;
			fstring net_name;

			rpcstr_pull(net_name, info1->info_1_str.uni_netname.buffer, sizeof(net_name), info1->info_1_str.uni_netname.uni_str_len*2, 0);
			rpcstr_pull(remark, info1->info_1_str.uni_remark.buffer, sizeof(remark), info1->info_1_str.uni_remark.uni_str_len*2, 0);

			display_share(out_hnd, action, net_name, info1->info_1.type, remark);

			break;
		}
		case ACTION_FOOTER:
		{
			//fprintf(out_hnd, "\n");
			break;
		}
	}

}

/****************************************************************************
share info level 2 display function
****************************************************************************/
void display_share_info_2(FILE *out_hnd, enum action_type action,
			  SRV_SHARE_INFO_2 *info2)
{
	if (info2 == NULL)
	{
		return;
	}

	switch (action)
	{
		case ACTION_HEADER:
		{
			fprintf(out_hnd, "Share Info Level 2:\n");

			break;
		}
		case ACTION_ENUMERATE:
		{
			fstring remark  ;
			fstring net_name;
			fstring path    ;
			fstring passwd  ;

			rpcstr_pull(net_name, info2->info_2_str.uni_netname.buffer, sizeof(net_name), info2->info_2_str.uni_netname.uni_str_len*2, 0);
			rpcstr_pull(remark, info2->info_2_str.uni_remark.buffer, sizeof(remark), info2->info_2_str.uni_remark.uni_str_len*2, 0);
			rpcstr_pull(path, info2->info_2_str.uni_path.buffer, sizeof(path), info2->info_2_str.uni_path.uni_str_len*2, 0);
			rpcstr_pull(passwd, info2->info_2_str.uni_passwd.buffer, sizeof(passwd), info2->info_2_str.uni_passwd.uni_str_len*2, 0);

			display_share2(out_hnd, action, net_name,
			      info2->info_2.type, remark, info2->info_2.perms,
			      info2->info_2.max_uses, info2->info_2.num_uses,
			      path, passwd);

			break;
		}
		case ACTION_FOOTER:
		{
			fprintf(out_hnd, "\n");
			break;
		}
	}

}

/****************************************************************************
share info container display function
****************************************************************************/
void display_srv_share_info_ctr(FILE *out_hnd, enum action_type action,
				SRV_SHARE_INFO_CTR *ctr)
{
	if (ctr == NULL)
	{
		fprintf(out_hnd, "display_srv_share_info_ctr: unavailable due to an internal error\n");
	return;
	}

	switch (action)
	{
		case ACTION_HEADER:
		{
			break;
		}
		case ACTION_ENUMERATE:
		{
			int i;

			for (i = 0; i < ctr->num_entries; i++)
			{
				switch (ctr->info_level) {
				case 1:
					display_share_info_1(out_hnd, ACTION_HEADER   , &(ctr->share.info1[i]));
					display_share_info_1(out_hnd, ACTION_ENUMERATE, &(ctr->share.info1[i]));
					display_share_info_1(out_hnd, ACTION_FOOTER   , &(ctr->share.info1[i]));
					break;
				case 2:
					display_share_info_2(out_hnd, ACTION_HEADER   , &(ctr->share.info2[i]));
					display_share_info_2(out_hnd, ACTION_ENUMERATE, &(ctr->share.info2[i]));
					display_share_info_2(out_hnd, ACTION_FOOTER   , &(ctr->share.info2[i]));
					break;
				default:
					fprintf(out_hnd, "display_srv_share_info_ctr: Unknown Info Level\n");
					break;
				}
			}
			break;
		}
		case ACTION_FOOTER:
		{
			break;
		}
	}
}
/* Display server query info */

static char *get_server_type_str(uint32 type)
{
	static fstring typestr;
	int i;

	if (type == SV_TYPE_ALL) {
		fstrcpy(typestr, "All");
		return typestr;
	}
		
	typestr[0] = 0;

	for (i = 0; i < 32; i++) {
		if (type & (1 << i)) {
			switch (1 << i) {
			case SV_TYPE_WORKSTATION:
				fstrcat(typestr, "Wk ");
				break;
			case SV_TYPE_SERVER:
				fstrcat(typestr, "Sv ");
				break;
			case SV_TYPE_SQLSERVER:
				fstrcat(typestr, "Sql ");
				break;
			case SV_TYPE_DOMAIN_CTRL:
				fstrcat(typestr, "PDC ");
				break;
			case SV_TYPE_DOMAIN_BAKCTRL:
				fstrcat(typestr, "BDC ");
				break;
			case SV_TYPE_TIME_SOURCE:
				fstrcat(typestr, "Tim ");
				break;
			case SV_TYPE_AFP:
				fstrcat(typestr, "AFP ");
				break;
			case SV_TYPE_NOVELL:
				fstrcat(typestr, "Nov ");
				break;
			case SV_TYPE_DOMAIN_MEMBER:
				fstrcat(typestr, "Dom ");
				break;
			case SV_TYPE_PRINTQ_SERVER:
				fstrcat(typestr, "PrQ ");
				break;
			case SV_TYPE_DIALIN_SERVER:
				fstrcat(typestr, "Din ");
				break;
			case SV_TYPE_SERVER_UNIX:
				fstrcat(typestr, "Unx ");
				break;
			case SV_TYPE_NT:
				fstrcat(typestr, "NT ");
				break;
			case SV_TYPE_WFW:
				fstrcat(typestr, "Wfw ");
				break;
			case SV_TYPE_SERVER_MFPN:
				fstrcat(typestr, "Mfp ");
				break;
			case SV_TYPE_SERVER_NT:
				fstrcat(typestr, "SNT ");
				break;
			case SV_TYPE_POTENTIAL_BROWSER:
				fstrcat(typestr, "PtB ");
				break;
			case SV_TYPE_BACKUP_BROWSER:
				fstrcat(typestr, "BMB ");
				break;
			case SV_TYPE_MASTER_BROWSER:
				fstrcat(typestr, "LMB ");
				break;
			case SV_TYPE_DOMAIN_MASTER:
				fstrcat(typestr, "DMB ");
				break;
			case SV_TYPE_SERVER_OSF:
				fstrcat(typestr, "OSF ");
				break;
			case SV_TYPE_SERVER_VMS:
				fstrcat(typestr, "VMS ");
				break;
			case SV_TYPE_WIN95_PLUS:
				fstrcat(typestr, "W95 ");
				break;
			case SV_TYPE_ALTERNATE_XPORT:
				fstrcat(typestr, "Xpt ");
				break;
			case SV_TYPE_LOCAL_LIST_ONLY:
				fstrcat(typestr, "Dom ");
				break;
			case SV_TYPE_DOMAIN_ENUM:
				fstrcat(typestr, "Loc ");
				break;
			}
		}
	}

	i = strlen(typestr) - 1;

	if (typestr[i] == ' ')
		typestr[i] = 0;
	
	return typestr;
}

static void display_server(char *sname, uint32 type, const char *comment)
{
	printf("\t%-15.15s%-20s %s\n", sname, get_server_type_str(type), 
	       comment);
}


/* Server query info */

static NTSTATUS cmd_srvsvc_srv_query_info(struct cli_state *cli, 
                                          TALLOC_CTX *mem_ctx,
                                          int argc, char **argv)
{
	uint32 info_level = 101;
	SRV_INFO_CTR ctr;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	if (argc > 2) {
		printf("Usage: %s [infolevel]\n", argv[0]);
		return NT_STATUS_OK;
	}

	if (argc == 2)
		info_level = atoi(argv[1]);

	result = cli_srvsvc_net_srv_get_info(cli, mem_ctx, info_level,
					     &ctr);

	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

 done:
	return result;
}

static NTSTATUS cmd_srvsvc_srv_netshareenumall(struct cli_state *cli, 
                                          TALLOC_CTX *mem_ctx,
                                          int argc, char **argv)
{
	uint32 info_level = 101;
	SRV_SHARE_INFO_CTR ctr;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	if (argc > 2) {
		printf("Usage: %s [infolevel]\n", argv[0]);
		return NT_STATUS_OK;
	}

	if (argc == 2)
		info_level = atoi(argv[1]);

	result = cli_srvsvc_srv_netshareenumall(cli, mem_ctx, info_level, &ctr);

	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	/* Display results */
    display_srv_share_info_ctr(stdout, ACTION_ENUMERATE, &ctr);

 done:
	return result;
}

/* List of commands exported by this module */

struct cmd_set srvsvc_commands[] = {

	{ "SRVSVC" },

	{ "srvinfo",    cmd_srvsvc_srv_query_info,  PIPE_SRVSVC, "Server query info", "" },

	{ "netshareenumall",    cmd_srvsvc_srv_netshareenumall,  PIPE_SRVSVC, "Server enumerates to find all shared drives", "" },

	{ NULL }
};
