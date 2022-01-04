#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/net.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_bridge.h>
#include <linux/netdevice.h>
#include <linux/stat.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/socket.h>
#include <linux/netlink.h>
#include <net/netlink.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/udp.h>
#include <linux/if_arp.h>
#include <linux/rtc.h>
#include <linux/if_ether.h>
#include <linux/types.h>
#include <linux/proc_fs.h>
#include <net/sock.h>
#include <net/ip.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include "hashmap.h"
#include "mydev.c"
MODULE_LICENSE("GPL");
MODULE_AUTHOR("lm");

int nat_port_num=20000;

static struct nf_hook_ops nfhoin,nfhoout;

void debugipport(unsigned int ip_src,unsigned short port_src,unsigned int ip_dst,unsigned short port_dst)
{
	printk("Src:%u.%u.%u.%u:%u,	Dst:%u.%u.%u.%u:%u\n",
						((unsigned char *)&ip_src)[0],
						((unsigned char *)&ip_src)[1],
						((unsigned char *)&ip_src)[2],
						((unsigned char *)&ip_src)[3],
						ntohs(port_src),
						((unsigned char *)&ip_dst)[0],
						((unsigned char *)&ip_dst)[1],
						((unsigned char *)&ip_dst)[2],
						((unsigned char *)&ip_dst)[3],
						ntohs(port_dst)
	);
}
void writelog(struct iphdr* iph,unsigned char behavior,unsigned char direction)
{
	struct tcphdr *tcph;
	struct icmphdr *icmph;
	logptr* headlogaddr;
	struct timex  txc; 
	struct rtc_time tm; 
	tcph=(void*)iph+iph->ihl*4;
	icmph=(void*)iph+iph->ihl*4;
	headlogaddr=&(memory->logp);
	while(*headlogaddr!=NULL)
	{
		headlogaddr=&((*headlogaddr)->next);
	}
	*headlogaddr=kmalloc(sizeof(log),GFP_KERNEL);
	do_gettimeofday(&(txc.time)); 
	rtc_time_to_tm(txc.time.tv_sec,&tm); 
	sprintf((*headlogaddr)->time,"%d-%d-%d %d:%d:%d",tm.tm_year+1900,tm.tm_mon, tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec);
	if(iph->protocol==IPPROTO_ICMP)
	{
		(*headlogaddr)->port_src=icmph->type;
		(*headlogaddr)->port_dst=icmph->code;
	}
	else
	{
		(*headlogaddr)->port_src=tcph->source;
		(*headlogaddr)->port_dst=tcph->dest;
	}
	(*headlogaddr)->ip_src=iph->saddr;
	(*headlogaddr)->ip_dst=iph->daddr;
	(*headlogaddr)->protocol=iph->protocol;
	(*headlogaddr)->behavior=behavior;
	(*headlogaddr)->direction=direction;
	(*headlogaddr)->next=NULL;
}

void intra_nattransform(struct iphdr* iph,struct sk_buff* skb)
{
	struct tcphdr *tcph;
	struct udphdr *udph;
	struct icmphdr *icmph;
	natptr* headnataddr;
	int iph_len,tot_len;
	tcph=(void*)iph+iph->ihl*4;
	udph=(void*)iph+iph->ihl*4;
	icmph=(void*)iph+iph->ihl*4;
	headnataddr=&memory->natp;
	iph_len=ip_hdrlen(skb);
	tot_len = ntohs(iph->tot_len);
	switch (iph->protocol)
	{
	case IPPROTO_ICMP:
		while(*headnataddr!=NULL)
		{
			if(iph->saddr==(*headnataddr)->ip_in)
				break;
			headnataddr=&(*headnataddr)->next;
		}
		if(*headnataddr==NULL)
		{
			*headnataddr=kmalloc(sizeof(nat),GFP_KERNEL);
			(*headnataddr)->ip_in=iph->saddr;
			(*headnataddr)->port_in=0;
			(*headnataddr)->ip_out=2162731200;  //inet_addr("192.168.232.128")
			(*headnataddr)->next=NULL;
		}
		(*headnataddr)->port_out=icmph->un.echo.id;
		iph->saddr=(*headnataddr)->ip_out;
		iph->check=0;
		iph->check=ip_fast_csum(iph,iph->ihl);
		break;
	case IPPROTO_TCP:
		while(*headnataddr!=NULL)
		{
			if(iph->saddr==(*headnataddr)->ip_in&&tcph->source==(*headnataddr)->port_in)
				break;
			headnataddr=&(*headnataddr)->next;
		}
		if(*headnataddr==NULL)
		{
			*headnataddr=kmalloc(sizeof(nat),GFP_KERNEL);
			(*headnataddr)->ip_in=iph->saddr;
			(*headnataddr)->port_in=tcph->source;
			(*headnataddr)->ip_out=2162731200;  //inet_addr("192.168.232.128")
			(*headnataddr)->port_out=htons(nat_port_num++);
			(*headnataddr)->next=NULL;
		}
		iph->saddr=(*headnataddr)->ip_out;
		iph->check=0;
		iph->check=ip_fast_csum(iph,iph->ihl);
		tcph->source = (*headnataddr)->port_out; 
		tcph->check = 0;
		skb->csum = csum_partial((unsigned char *)tcph, tot_len - iph_len,0);
		tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,ntohs(iph->tot_len) - iph_len,iph->protocol, skb->csum);
		break;
	default:
		printk("Unknown protocol\n");
		break;
	}
}
unsigned int extra_nattransform(struct iphdr* iph,struct sk_buff* skb)
{
	struct tcphdr *tcph;
	struct udphdr *udph;
	struct icmphdr *icmph;
	natptr* headnataddr;
	int iph_len,tot_len;
	tcph=(void*)iph+iph->ihl*4;
	udph=(void*)iph+iph->ihl*4;
	icmph=(void*)iph+iph->ihl*4;
	headnataddr=&memory->natp;
	iph_len=ip_hdrlen(skb);
	tot_len = ntohs(iph->tot_len);
	
	switch (iph->protocol)
	{
	case IPPROTO_ICMP:
		while(*headnataddr!=NULL)
		{
			if(iph->daddr==(*headnataddr)->ip_out&&(*headnataddr)->port_out==icmph->un.echo.id)
				break;
			headnataddr=&(*headnataddr)->next;
		}
		if(*headnataddr==NULL)
		{
			return 0;
		}
		iph->daddr=(*headnataddr)->ip_in;
		iph->check=0;
		iph->check=ip_fast_csum(iph,iph->ihl);
		break;
	case IPPROTO_TCP:
		while(*headnataddr!=NULL)
		{
			if(iph->daddr==(*headnataddr)->ip_out&&tcph->dest==(*headnataddr)->port_out)
				break;
			headnataddr=&(*headnataddr)->next;
		}
		if(*headnataddr==NULL)
		{//添加NAT规则
			return 0;
		}
		iph->daddr=(*headnataddr)->ip_in;
		iph->check=0;
		iph->check=ip_fast_csum(iph,iph->ihl);
		tcph->dest = (*headnataddr)->port_in;
		tcph->check = 0;
		skb->csum = csum_partial((unsigned char *)tcph, tot_len - iph_len,0);
		tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,ntohs(iph->tot_len) - iph_len,iph->protocol, skb->csum);
		break;
	default:
		printk("Unknown protocol\n");
		break;
	}
	return 1;
}

unsigned int filter(void *pr,struct sk_buff *skb,const struct nf_hook_state *state)
{

	struct iphdr *iph;
	struct tcphdr *tcph;	
	struct icmphdr *icmph;
	ruleptr headrule;
	linkstate lstate;
	hashnodeptr res;
	
	headrule=memory->rulep;

	iph=ip_hdr(skb);
	tcph=(void*)iph+iph->ihl*4;
	icmph=(void*)iph+iph->ihl*4;

	//外网到内�?NAT_rule    skb
	if(state->hook==NF_INET_PRE_ROUTING&&(iph->saddr&16777215)!=10&&(iph->daddr&16777215)!=10)
	{
		debugipport(iph->saddr,tcph->source,iph->daddr,tcph->dest);
		extra_nattransform(iph,skb);
		debugipport(iph->saddr,tcph->source,iph->daddr,tcph->dest);
	}

	if(iph->protocol!=IPPROTO_ICMP&&iph->protocol!=IPPROTO_UDP&&iph->protocol!=IPPROTO_TCP)
		return NF_ACCEPT;
	lstate.ip_src=iph->saddr;
	lstate.ip_dst=iph->daddr;
	lstate.protocol=iph->protocol;
	if(iph->protocol==IPPROTO_ICMP)
	{
		lstate.port_src=icmph->type;
		lstate.port_dst=icmph->code;
		
	}
	else
	{
		lstate.port_src=tcph->dest;
		lstate.port_dst=tcph->source;
	}

	//检查状态表
	if((iph->protocol==IPPROTO_TCP&&(tcph->syn==0&&tcph->ack==1||tcph->fin==1))||iph->protocol==IPPROTO_UDP||iph->protocol==IPPROTO_ICMP)
	{//in_pkg and out_pkg share one single linklist, therefore, we need find it twice
		res = hash_find(&memory->statemap,lstate);
		if(res!=NULL)
		{
			//内网到外�?NAT_rule
			if(state->hook==NF_INET_POST_ROUTING&&(iph->saddr&16777215)==10&&(iph->daddr&16777215)!=10&&iph->daddr!=2162731200)
				intra_nattransform(iph,skb);
			
			return NF_ACCEPT;
		}
	}

	//检查规则表
	while(headrule!=NULL)
	{
		if(state->hook==headrule->direction&&
			(headrule->ip_src_mask==32||(ntohl(iph->saddr)>>(unsigned int)headrule->ip_src_mask)==(ntohl(headrule->ip_src)>>(unsigned int)headrule->ip_src_mask))&&
			(headrule->ip_dst_mask==32||(ntohl(iph->daddr)>>(unsigned int)headrule->ip_dst_mask)==(ntohl(headrule->ip_dst)>>(unsigned int)headrule->ip_dst_mask))&&
			iph->protocol==headrule->protocol&&
			((iph->protocol==IPPROTO_TCP||iph->protocol==IPPROTO_UDP)&&
			(headrule->port_src_mask==16||(ntohs(tcph->source)>>headrule->port_src_mask)==(ntohs(headrule->port_src)>>headrule->port_src_mask))&&
			(headrule->port_dst_mask==16||(ntohs(tcph->dest)>>headrule->port_dst_mask)==(ntohs(headrule->port_dst)>>headrule->port_dst_mask))||
			iph->protocol==IPPROTO_ICMP&&(headrule->port_src_mask==16||(icmph->type>>headrule->port_src_mask)==(headrule->port_src>>headrule->port_src_mask))&&
			(headrule->port_dst_mask==16||(icmph->code>>headrule->port_dst_mask)==(headrule->port_dst>>headrule->port_dst_mask)))
			)
		{//已连接，则写log
			if(headrule->log==1)
			{
				printk("write log\n");
				writelog(iph,headrule->behavior,headrule->direction);
			}
			if(headrule->behavior==1)
			{//写入状态表
				if(iph->protocol==IPPROTO_TCP&&tcph->syn==1||iph->protocol==IPPROTO_UDP||iph->protocol==IPPROTO_ICMP)
				{
					hash_insert(&memory->statemap,lstate);
				}
				//内网到外�? 新NAT_rule
				if(state->hook==NF_INET_POST_ROUTING&&(iph->saddr&16777215)==10&&(iph->daddr&16777215)!=10&&iph->daddr!=2162731200)
				{
					debugipport(iph->saddr,tcph->source,iph->daddr,tcph->dest);
					intra_nattransform(iph,skb);
					debugipport(iph->saddr,tcph->source,iph->daddr,tcph->dest);
				}
				return NF_ACCEPT;
			}
			else
			{
				printk("Dropping Direction:%s\tSrc:%d.%d.%d.%d,%u\tDst:%d.%d.%d.%d,%u\n",
						headrule->direction==NF_INET_LOCAL_IN?"IN":"OUT",
						((unsigned char *)&iph->saddr)[0],
						((unsigned char *)&iph->saddr)[1],
						((unsigned char *)&iph->saddr)[2],
						((unsigned char *)&iph->saddr)[3],
						(((unsigned char*)&headrule->port_src)[0]<<8)+((unsigned char*)&headrule->port_src)[1],
						((unsigned char *)&iph->daddr)[0],
						((unsigned char *)&iph->daddr)[1],
						((unsigned char *)&iph->daddr)[2],
						((unsigned char *)&iph->daddr)[3],
						(((unsigned char*)&headrule->port_dst)[0]<<8)+((unsigned char*)&headrule->port_dst)[1]);
				return NF_DROP;
			}
		}
		headrule=headrule->next;
	}
	return NF_DROP;
}

static int myfw_init(void)
{
	//登记一个dev
	int result;
	dev_t ndev;
	struct net* n;
	result = alloc_chrdev_region(&ndev, 0, 1, "chr_dev");  
	if(result < 0 )  
	{  
		return result;  
	} 	
	printk("chr_dev: major = %d, minor = %d\n", MAJOR(ndev), MINOR(ndev));
    	chr_major = MAJOR(ndev);
	memory = kmalloc(sizeof(struct chr_dev), GFP_KERNEL);//为dev申请内存
	if(!memory)
	{
		result = -ENOMEM;
		unregister_chrdev_region(ndev, 1);
		return 0;
	}
	memset(memory, 0, sizeof(struct chr_dev));	//置全0
	hash_initial(&memory->statemap,HASHKEYSIZE);
	chr_setup_cdev(memory, 0);
	//登记hook程序
	printk("my firewall module loaded.\n");
	nfhoin.hook = filter;
	nfhoin.pf = PF_INET;
	nfhoin.hooknum = NF_INET_PRE_ROUTING;
	nfhoin.priority = NF_IP_PRI_FIRST;
	for_each_net(n)
		nf_register_net_hook(n,&nfhoin);
	nfhoout.hook = filter;
	nfhoout.pf = PF_INET;
	nfhoout.hooknum = NF_INET_POST_ROUTING;
	nfhoout.priority = NF_IP_PRI_FIRST;
	for_each_net(n)
		nf_register_net_hook(n,&nfhoout);
	return 0;
}

static void myfw_exit(void)
{
	struct net* n;
	//释放
	cdev_del(&memory->cdev);
	kfree(memory);
	unregister_chrdev_region(MKDEV(chr_major, 0), 1);//解除登记
	printk("my firewall module exit ...\n");
	for_each_net(n)
		nf_unregister_net_hook(n,&nfhoin);
	for_each_net(n)
		nf_unregister_net_hook(n,&nfhoout);
}

module_init(myfw_init);
module_exit(myfw_exit);
