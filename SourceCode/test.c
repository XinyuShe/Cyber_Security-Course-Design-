#include<string.h>
#include<unistd.h>
#include<sys/ioctl.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<arpa/inet.h>
#include<linux/netfilter.h>
#include<linux/ip.h>
#include<fcntl.h>
#include<stdio.h>
#include<stdlib.h>
#include"mydev.h"
typedef struct _rule_infile
{
	char loc[25];
	char ip_src[16];
	char ip_src_mask[3];
	char port_src[6];
	char port_src_mask[3];
	char ip_dst[16];
	char ip_dst_mask[3];
	char port_dst[6];
	char port_dst_mask[3];
	char direction[4];
	char protocol[5];
	char log[2];
	char behavior[7];
	struct _rule_file* next;
}rule_infile;
void ShowRules(int fd)
{
	int size;
	ioctl(fd,GET_RULE_NUM,&size);
	rule head[size];
	ioctl(fd,GET_RULE,head);
	int i=0;
	while(i<size)
	{
		if(head[i].protocol!=IPPROTO_ICMP)
		{
			printf("Src:%d.%d.%d.%d/%u:%u/%u\tDst:%d.%d.%d.%d/%u:%u/%u\tProtocol:%s\tDirection:%s\tlog:%s\tBehavior:%s\n",
			((unsigned char *)&head[i].ip_src)[0],
			((unsigned char *)&head[i].ip_src)[1],
			((unsigned char *)&head[i].ip_src)[2],
			((unsigned char *)&head[i].ip_src)[3],
			(unsigned int)head[i].ip_src_mask,
			ntohs(head[i].port_src),
			(unsigned int)head[i].port_src_mask,
			((unsigned char *)&head[i].ip_dst)[0],
			((unsigned char *)&head[i].ip_dst)[1],
			((unsigned char *)&head[i].ip_dst)[2],
			((unsigned char *)&head[i].ip_dst)[3],
			(unsigned int)head[i].ip_src_mask,
			ntohs(head[i].port_dst),
			(unsigned int)head[i].port_dst_mask,
			head[i].protocol==IPPROTO_TCP?"TCP":"UDP",
			head[i].direction==NF_INET_PRE_ROUTING?"IN":"OUT",
			head[i].log==1?"Y":"N",
			head[i].behavior==1?"ACCEPT":"DROP"
			);
		}
		else
		{
			printf("Src:%d.%d.%d.%d/%u\tDst:%d.%d.%d.%d/%u\tType:%u/%u\tCode:%u/%u\tProtocol:%s\tDirection:%s\tlog:%s\tBehavior:%s\n",
			((unsigned char *)&head[i].ip_src)[0],
			((unsigned char *)&head[i].ip_src)[1],
			((unsigned char *)&head[i].ip_src)[2],
			((unsigned char *)&head[i].ip_src)[3],
			(unsigned int)head[i].ip_src_mask,
			((unsigned char *)&head[i].ip_dst)[0],
			((unsigned char *)&head[i].ip_dst)[1],
			((unsigned char *)&head[i].ip_dst)[2],
			((unsigned char *)&head[i].ip_dst)[3],
			(unsigned int)head[i].ip_src_mask,
			head[i].port_src,
			(unsigned int)head[i].port_src_mask,
			head[i].port_dst,
			(unsigned int)head[i].port_dst_mask,
			"ICMP",
			head[i].direction==NF_INET_PRE_ROUTING?"IN":"OUT",
			head[i].log==1?"Y":"N",
			head[i].behavior==1?"ACCEPT":"DROP"
			);
		}
		i++;
	}
}
void ShowLogs(int fd)
{
	int size;
	ioctl(fd,GET_LOG_NUM,&size);
	log head[size];
	ioctl(fd,GET_LOG,head);
	int i=0;
	while(i<size)
	{
		if(head[i].protocol!=IPPROTO_ICMP)
		{
			printf("Time:%s\tSrc:%d.%d.%d.%d:%u\tDst:%d.%d.%d.%d:%u\tProtocol:%s\tDirection:%s\tBehavior:%s\n",
			head[i].time,
			((unsigned char *)&head[i].ip_src)[0],
			((unsigned char *)&head[i].ip_src)[1],
			((unsigned char *)&head[i].ip_src)[2],
			((unsigned char *)&head[i].ip_src)[3],
			ntohs(head[i].port_src),
			((unsigned char *)&head[i].ip_dst)[0],
			((unsigned char *)&head[i].ip_dst)[1],
			((unsigned char *)&head[i].ip_dst)[2],
			((unsigned char *)&head[i].ip_dst)[3],
			ntohs(head[i].port_dst),
			head[i].protocol==IPPROTO_TCP?"TCP":"UDP",
			head[i].direction==NF_INET_PRE_ROUTING?"IN":"OUT",
			head[i].behavior==1?"ACCEPT":"DROP"
			);
		}
		else
		{
			printf("Time:%s\tSrc:%d.%d.%d.%d\tDst:%d.%d.%d.%d\tType:%u\tCode:%u\tProtocol:%s\tDirection:%s\tBehavior:%s\n",
			head[i].time,
			((unsigned char *)&head[i].ip_src)[0],
			((unsigned char *)&head[i].ip_src)[1],
			((unsigned char *)&head[i].ip_src)[2],
			((unsigned char *)&head[i].ip_src)[3],
			((unsigned char *)&head[i].ip_dst)[0],
			((unsigned char *)&head[i].ip_dst)[1],
			((unsigned char *)&head[i].ip_dst)[2],
			((unsigned char *)&head[i].ip_dst)[3],
			head[i].port_src,
			head[i].port_dst,
			"ICMP",
			head[i].direction==NF_INET_LOCAL_IN?"IN":"OUT",
			head[i].behavior==1?"ACCEPT":"DROP"
			);
		}
		i++;
	}
}

void ShowStates(int fd)
{
	int size;
	ioctl(fd,GET_STATE_NUM,&size);
	linkstate head[size];
	ioctl(fd,GET_STATE,head);
	for(int i = 0;i < size;i++)
	{
		if(head[i].protocol!=IPPROTO_ICMP)
		{
			printf("Src:%d.%d.%d.%d:%u\tDst:%d.%d.%d.%d:%u\tProtocol:%s\n",
			((unsigned char *)&head[i].ip_src)[0],
			((unsigned char *)&head[i].ip_src)[1],
			((unsigned char *)&head[i].ip_src)[2],
			((unsigned char *)&head[i].ip_src)[3],
			ntohs(head[i].port_src),
			((unsigned char *)&head[i].ip_dst)[0],
			((unsigned char *)&head[i].ip_dst)[1],
			((unsigned char *)&head[i].ip_dst)[2],
			((unsigned char *)&head[i].ip_dst)[3],
			ntohs(head[i].port_dst),
			head[i].protocol==IPPROTO_TCP?"TCP":"UDP"
			);
		}
		else
		{
			printf("Src:%d.%d.%d.%d\tDst:%d.%d.%d.%d\tType:%u\tCode:%u\tProtocol:%s\n",
			((unsigned char *)&head[i].ip_src)[0],
			((unsigned char *)&head[i].ip_src)[1],
			((unsigned char *)&head[i].ip_src)[2],
			((unsigned char *)&head[i].ip_src)[3],
			((unsigned char *)&head[i].ip_dst)[0],
			((unsigned char *)&head[i].ip_dst)[1],
			((unsigned char *)&head[i].ip_dst)[2],
			((unsigned char *)&head[i].ip_dst)[3],
			head[i].port_src,
			head[i].port_dst,
			"ICMP"
			);
		}
	}
}

void InsertRules(int fd,int loc,const char* ip_src,unsigned char ip_src_mask,unsigned short port_src,unsigned char port_src_mask,
			 const char* ip_dst,unsigned char ip_dst_mask,unsigned short port_dst,unsigned char port_dst_mask,
			 unsigned int direction,unsigned char protocol,unsigned char log,unsigned char behavior)
{
	addrule* t=(addrule*)malloc(sizeof(addrule));
	t->loc=loc;
	t->rlptr=(ruleptr)malloc(sizeof(rule));
	t->rlptr->direction=direction;
	t->rlptr->ip_src=inet_addr(ip_src);
	t->rlptr->ip_src_mask=ip_src_mask;
	t->rlptr->port_src=protocol==IPPROTO_ICMP?port_src:htons(port_src);
	t->rlptr->port_src_mask=port_src_mask;
	t->rlptr->protocol=protocol;
	t->rlptr->ip_dst=inet_addr(ip_dst);
	t->rlptr->ip_dst_mask=ip_dst_mask;
	t->rlptr->port_dst=protocol==IPPROTO_ICMP?port_dst:htons(port_dst);
	t->rlptr->port_dst_mask=port_dst_mask;
	t->rlptr->log=log;
	t->rlptr->behavior=behavior;
	ioctl(fd,INSERT_RULE,t);
	free(t->rlptr);
	free(t);
}
void ClearALLTables(int fd)
{
	ioctl(fd,MEM_CLEAR,NULL);
}
void DelRule(int fd,int num)
{
	int t=num;
	ioctl(fd,DEL_RULE,&t);
}
int insert_rule(int fd,char* loc,char* ip_src,char* ip_src_mask,char* port_src,char* port_src_mask,char* ip_dst,char* ip_dst_mask,char* port_dst,char* port_dst_mask,
		char* arg11,char* arg12,char* arg13,char* arg14)
{
	unsigned int direction;
	unsigned char protocol;
	unsigned char log;
	unsigned char behavior;
	if(!strcmp(arg11,"in"))
	{
		direction=NF_INET_PRE_ROUTING;
	}
	else if(!strcmp(arg11,"out"))
	{
		direction=NF_INET_POST_ROUTING;
	}
	else
	{
		printf("direction must be 'in' or 'out'\n");
		return 0;
	}
	
	if(!strcmp(arg12,"tcp"))
	{
		protocol=IPPROTO_TCP;
	}
	else if(!strcmp(arg12,"udp"))
	{
		protocol=IPPROTO_UDP;
	}
	else if(!strcmp(arg12,"icmp"))
	{
		protocol=IPPROTO_ICMP;
	}
	else
	{
		printf("protocol must be 'tcp', 'udp' or 'icmp'\n");
		return 0;
	}

	if(!strcmp(arg13,"y"))
	{
		log=1;
	}
	else if(!strcmp(arg13,"n"))
	{
		log=0;
	}
	else
	{
		printf("log_flag must be 'y' or 'n'\n");
		return 0;
	}

	if(!strcmp(arg14,"accept"))
	{
		behavior=1;
	}
	else if(!strcmp(arg14,"drop"))
	{
		behavior=0;
	}
	else
	{
		printf("behavior_flag must be 'accept' or 'drop'\n");
		return 0;
	}
	InsertRules(fd,atoi(loc),ip_src,(unsigned char)atoi(ip_src_mask),(unsigned short)atoi(port_src),(unsigned char)atoi(port_src_mask),
	ip_dst,(unsigned char)atoi(ip_dst_mask),(unsigned short)atoi(port_dst),(unsigned char)atoi(port_dst_mask),
	direction,protocol,log,behavior);
	return 1;
}
int main(int argc,char** argv)
{
	int fd=open("/dev/rule",O_RDWR);
	if(argc<2)
	{
		printf("too few arguments\n");
		return 0;
	}
	if(!strcmp(argv[1],"-a"))//add rule
	{
		if(argc!=15)
		{
			printf("Need 15 args!\n");
			return 0;
		}
		insert_rule(fd,argv[2],argv[3],argv[4],argv[5],argv[6],argv[7],argv[8],argv[9],argv[10],argv[11],argv[12],argv[13],argv[14]);
	}
	else if(!strcmp(argv[1],"-d"))//del rule
	{
		if(argc!=3)
		{
			printf("Need 3 args!\n");
			return 0;
		}
		DelRule(fd,atoi(argv[2]));
	}
	else if(!strcmp(argv[1],"-l"))//log info
	{
		printf("-------------------------------------------------------------------------------------------------------------------------------------------\n");
		ShowLogs(fd);
		printf("-------------------------------------------------------------------------------------------------------------------------------------------\n");
	}
	else if(!strcmp(argv[1],"-r"))//rule info
	{
		printf("-------------------------------------------------------------------------------------------------------------------------------------------\n");
		ShowRules(fd);
		printf("-------------------------------------------------------------------------------------------------------------------------------------------\n");
	}
	else if(!strcmp(argv[1],"-s"))//state list
	{
		printf("-------------------------------------------------------------------------------------------------------------------------------------------\n");
		ShowStates(fd);
		printf("-------------------------------------------------------------------------------------------------------------------------------------------\n");
	}
	else if(!strcmp(argv[1],"-c"))
	{
		ClearALLTables(fd);
	}
	else if(!strcmp(argv[1],"-save"))
	{
		FILE* filep=fopen("rule.txt","w+");
		int size;
		ioctl(fd,GET_RULE_NUM,&size);
		rule head[size];
		ioctl(fd,GET_RULE,head);
		int i=size-1;
		while(i>=0)
		{
			fprintf(filep,"0 %d.%d.%d.%d %u %u %u %d.%d.%d.%d %u %u %u %s %s %s %s\n",
			((unsigned char *)&head[i].ip_src)[0],
			((unsigned char *)&head[i].ip_src)[1],
			((unsigned char *)&head[i].ip_src)[2],
			((unsigned char *)&head[i].ip_src)[3],
			(unsigned int)head[i].ip_src_mask,
			ntohs(head[i].port_src),
			(unsigned int)head[i].port_src_mask,
			((unsigned char *)&head[i].ip_dst)[0],
			((unsigned char *)&head[i].ip_dst)[1],
			((unsigned char *)&head[i].ip_dst)[2],
			((unsigned char *)&head[i].ip_dst)[3],
			(unsigned int)head[i].ip_src_mask,
			ntohs(head[i].port_dst),
			(unsigned int)head[i].port_dst_mask,
			head[i].direction==NF_INET_PRE_ROUTING?"in":"out",
			head[i].protocol==IPPROTO_TCP?"tcp":head[i].protocol==IPPROTO_UDP?"udp":"icmp",
			head[i].log==1?"y":"n",
			head[i].behavior==1?"accept":"drop"
			);
			i--;
		}
		fclose(filep);
	}
	else if(!strcmp(argv[1],"-load"))
	{
		FILE* filep=fopen("rule.txt","r");
		rule_infile tmp;
		while(1)
		{
			fscanf(filep,"%s %s %s %s %s %s %s %s %s %s %s %s %s",tmp.loc,tmp.ip_src,tmp.ip_src_mask,tmp.port_src,tmp.port_src_mask,
			tmp.ip_dst,tmp.ip_dst_mask,tmp.port_dst,tmp.port_dst_mask,tmp.direction,tmp.protocol,tmp.log,tmp.behavior);
			if(feof(filep))
				break;
			insert_rule(fd,tmp.loc,tmp.ip_src,tmp.ip_src_mask,tmp.port_src,tmp.port_src_mask,
			tmp.ip_dst,tmp.ip_dst_mask,tmp.port_dst,tmp.port_dst_mask,tmp.direction,tmp.protocol,tmp.log,tmp.behavior);
		}
		fclose(filep);
	}
	else
	{
		printf("\
	--------------------------------------------------------------------------------------------------------------------\n \
	-a\t<插入序号位置> <源地址> <源地址掩码> <源地址端口> <端口掩码> <目标地址> <目标地址掩码> <目标地址端口> <目标地址端口掩码> <方向> <协议> \
	<是否log> <是否接收> 	|新增规则\n \
	-d\t\t\t|序号（从0开始）\n \
	-l\t\t\t|Show log info\n \
	-r\t\t\t|Show rule info\n \
	-s\t\t\t|Show status info\n \
	-c\t\t\t|Clear all settting lists\n \
	--------------------------------------------------------------------------------------------------------------------\n");
	}
	close(fd);
	return 0;
}
