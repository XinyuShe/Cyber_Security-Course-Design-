#include <linux/module.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <asm/io.h>
#include <asm/switch_to.h>
#include <asm/uaccess.h>
#include "mydev.h"

int chr_open(struct inode* inode, struct file* filp);
int chr_release(struct inode* inode, struct file* filp);
static long chr_ioctl(struct file* filp, unsigned int cmd, unsigned long arg);

struct chr_dev
{//memory for rule list, log list, and state list
	struct cdev cdev;
	ruleptr rulep;//规则表
	logptr logp;//log表
	hashmap statemap;//状态表
	natptr natp;//NAT表
};

static const struct file_operations chr_ops = 
{
	.owner    = THIS_MODULE,
	.unlocked_ioctl    = chr_ioctl,
	.open     = chr_open
};

static int chr_major;
struct chr_dev* memory;
//IO
static long chr_ioctl(struct file* filp, unsigned int cmd, unsigned long arg)
{

	struct chr_dev* dev = filp->private_data;

	ruleptr headrule;
	ruleptr tmprule;
	logptr headlog;
	logptr tmplog;
	hashnodeptr headstate;
	addrule* newrule;
	int i,num,size;
	ruleptr* headruleaddr;
	switch(cmd)
	{
		//清除rule/log/state
		case MEM_CLEAR:
			headrule=dev->rulep;
			if(headrule!=NULL)
			{
				tmprule=headrule->next;
				while(tmprule!=NULL)
				{
					kfree(headrule);
					headrule=tmprule;
					tmprule=tmprule->next;
				}
				kfree(headrule);
				dev->rulep=NULL;
			}

			headlog=dev->logp;
			if(headlog!=NULL)
			{
				tmplog=headlog->next;
				while(tmplog!=NULL)
				{
					kfree(headlog);
					headlog=tmplog;
					tmplog=tmplog->next;
				}
				kfree(headlog);
				dev->logp=NULL;
			}

			hash_release(&memory->statemap);
			break;
		//新规则
		case INSERT_RULE:
			//arg: addrule*
			printk("add a rule\n");
			newrule=kmalloc(sizeof(addrule),GFP_KERNEL);
			copy_from_user(newrule,arg,sizeof(addrule));
			headruleaddr=&(dev->rulep);
			i=0;
			while(i!=newrule->loc&&*headruleaddr!=NULL)
			{
				headruleaddr=&(*headruleaddr)->next;
				i++;
			}
			headrule=*headruleaddr;
			*headruleaddr=kmalloc(sizeof(rule),GFP_KERNEL);
			copy_from_user(*headruleaddr,newrule->rlptr,sizeof(rule));
			kfree(newrule);
			(*headruleaddr)->next=headrule;
			hash_release(&memory->statemap);
			break;
		
		case GET_RULE_NUM:
			//arg: ruleptr*
			headrule=dev->rulep;
			i=0;
			while(headrule!=NULL)
			{
				headrule=headrule->next;
				i++;
			}
			copy_to_user(arg,&i,4);
			break;
		case GET_RULE:
			printk("send rulelist\n");
			headrule=dev->rulep;
			i=0;
			while(headrule!=NULL)
			{
				copy_to_user(arg+i,headrule,sizeof(rule));
				i+=sizeof(rule);
				headrule=headrule->next;
			}
			break;
		case GET_LOG_NUM:
			headlog=dev->logp;
			i=0;
			while(headlog!=NULL)
			{
				headlog=headlog->next;
				i++;
			}
			copy_to_user(arg,&i,4);
			break;
		case GET_LOG:
			printk("send loglist\n");
			headlog=dev->logp;
			i=0;
			while(headlog!=NULL)
			{
				copy_to_user(arg+i,headlog,sizeof(log));
				i+=sizeof(log);
				headlog=headlog->next;
			}
			break;
		case GET_STATE_NUM:
			num=0;
			size=dev->statemap.size;
			for(i=0;i<size;i++)
			{
				headstate=(dev->statemap.map)[i];
				while(headstate!=NULL)
				{
					headstate=headstate->next;
					num++;
				}
			}
			copy_to_user(arg,&num,4);
			break;
		case GET_STATE:
			printk("send statelist\n");
			size=dev->statemap.size;
			i=0;
			for(num=0;num<size;num++)
			{
				headstate=(dev->statemap.map)[num];
				while(headstate!=NULL)
				{
					copy_to_user(arg+i,&headstate->s,sizeof(linkstate));
					i+=sizeof(linkstate);
					headstate=headstate->next;
				}
			}
			break;
		case DEL_RULE:
			printk("del a rule\n");
			copy_from_user(&i,arg,4);
			headruleaddr=&dev->rulep;
			num=0;
			while(num!=i&&*headruleaddr!=NULL)
			{
				headruleaddr=&(*headruleaddr)->next;
				num++;
			}
			if(*headruleaddr!=NULL)
			{
				tmprule=*headruleaddr;
				*headruleaddr=(*headruleaddr)->next;
				kfree(tmprule);
				//clear statelist
				hash_release(&memory->statemap);
			}
			break;
		default:
			return -EINVAL;
	}
	
	return 0;
}
//建立
static void chr_setup_cdev(struct chr_dev* dev, int index)
{
	int err;
	int devno = MKDEV(chr_major, index);
	
	cdev_init(&dev->cdev, &chr_ops);
	dev->cdev.owner = THIS_MODULE;
	
	err = cdev_add(&dev->cdev, devno, 1);
	if(err)
	{
		printk(KERN_NOTICE "Error happend!\n");
	}
}
//打开
int chr_open(struct inode* inode, struct file* filp)
{
	filp->private_data = memory;
	return 0;
}