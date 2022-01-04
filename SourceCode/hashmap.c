#include"hashmap.h"
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/skbuff.h>

hashkey ipport_to_hashkey(hashmap* map, linkstate val)
{
	return ((((unsigned long long)val.ip_src<<16)|val.port_src)^(((unsigned long long)val.port_src<<32)|val.ip_dst))% map->size;
}
void hash_initial(hashmap* map, hashkeysize size)
{
	map->map = (hashnodeptr*)kmalloc(sizeof(hashnodeptr) * size,GFP_KERNEL);
	map->size = size;
	int i;
	for (i = 0; i < size; i++)
	{
		(map->map)[i] = NULL;
	}
}
void hash_insert(hashmap* map, linkstate val)
{
	hashkey hashk = ipport_to_hashkey(map, val);
	hashnodeptr* head = &(map->map)[hashk];//addr of the ptr to the first node
	while (*head != NULL)
	{
		if(((*head)->s).ip_dst==val.ip_dst&&((*head)->s).ip_src==val.ip_src&&((*head)->s).port_dst==val.port_dst&&((*head)->s).port_src==val.port_src&&((*head)->s).protocol==val.protocol)
		{//if it exists, then return
			return;
		}
		head = &(*head)->next;
	}
	*head = (hashnodeptr)kmalloc(sizeof(hashnode),GFP_KERNEL);
	(*head)->next = NULL;
	(*head)->s=val;
}
void hash_erase(hashmap* map, linkstate val)
{
	hashkey hashk = ipport_to_hashkey(map, val);
	hashnodeptr *head = &(map->map)[hashk];
	while (*head != NULL && ((*head)->s).ip_dst==val.ip_dst&&((*head)->s).ip_src==val.ip_src&&((*head)->s).port_dst==val.port_dst&&((*head)->s).port_src==val.port_src&&((*head)->s).protocol==val.protocol)
	{
		head = &(*head)->next;
	}
	if (*head != NULL)
	{
		hashnodeptr tmp = *head;
		*head = (*head)->next;
		kfree(tmp);
	}
}
hashnodeptr hash_find(hashmap* map, linkstate val)
{
	hashkey hashk = ipport_to_hashkey(map, val);
	hashnodeptr head = (map->map)[hashk];
	while (head != NULL && (head->s).ip_dst==val.ip_dst&&(head->s).ip_src==val.ip_src&&(head->s).port_dst==val.port_dst&&(head->s).port_src==val.port_src&&(head->s).protocol==val.protocol)
	{
		head = head->next;
	}
	return head;
}
void hash_print(hashmap* map)
{
	int i;
	for (i = 0; i < map->size; i++)
	{
		hashnodeptr head = map->map[i];
		while (head != NULL)
		{
			printk("Src:%u:%u\tDst:%u:%u\tProtocol:%s\n",head->s.ip_src,head->s.port_src,head->s.ip_dst,head->s.port_dst,head->s.protocol==IPPROTO_TCP?"TCP":head->s.protocol==IPPROTO_UDP?"UDP":"ICMP");
			head = head->next;
		}
	}
}
void hash_release(hashmap* map)
{
	int i;
	for (i = 0; i < map->size; i++)
	{
		hashnodeptr head = (map->map)[i];
		if (head == NULL)
			continue;
		hashnodeptr tmp = head->next;
		while (tmp != NULL)
		{
			kfree(head);
			head = tmp;
			tmp = tmp->next;
		}
		kfree(head);
		(map->map)[i] = NULL;
	}
}