#pragma once
#define MEM_CLEAR		1
#define INSERT_RULE		3
#define GET_RULE_NUM	5
#define GET_RULE		7
#define GET_LOG_NUM		9
#define GET_LOG			11
#define GET_STATE_NUM	13
#define GET_STATE		15
#define DEL_RULE		17

#define CHRMEM_SIZE		0x1000

//规则
typedef struct _rule_node
{
	unsigned int direction;
	unsigned int ip_src;
	unsigned char ip_src_mask; //0: use ip_src, 32: any
	unsigned short port_src;
	unsigned char port_src_mask; //0: use port_src, 16: any
	unsigned char protocol;
	unsigned int ip_dst;
	unsigned char ip_dst_mask; //0: use ip_src, 32: any
	unsigned short port_dst;
	unsigned char port_dst_mask; //0: use port_src, 16: any
	unsigned char log;
	unsigned char behavior;
	struct _rule_node *next;
}rule;

typedef rule* ruleptr;

//插入规则：位置&规则指针
typedef struct _insert_rule
{
	int loc;
	ruleptr rlptr;
}addrule;

//log
typedef struct _log_node
{
	char time[25];
	unsigned int ip_src;
	unsigned short port_src;
	unsigned char protocol;
	unsigned int ip_dst;
	unsigned short port_dst;
	unsigned char behavior;
	unsigned int direction;
	struct _log_node *next;
}log;

typedef log* logptr;
//状态
typedef struct _state
{
	unsigned int ip_src;
	unsigned short port_src;
	unsigned int ip_dst;
	unsigned short port_dst;
	unsigned char protocol;
}linkstate;
//NAT
typedef struct _nat
{
	unsigned int ip_out;
	unsigned short port_out;
	unsigned int ip_in;
	unsigned short port_in;
	struct _nat* next;
}nat;

typedef nat* natptr;





