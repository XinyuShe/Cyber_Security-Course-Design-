
#include"mydev.h"
#include<linux/netfilter.h>
#include<linux/ip.h>
#define HASHKEYSIZE 1025
#pragma once

typedef unsigned int hashkey;
//状态表
typedef struct _node
{
	linkstate s;
	struct _node* next;
}hashnode;

typedef hashnode* hashnodeptr;	
typedef int hashkeysize;	//default: 1024

//hashmap
typedef struct _hashmap
{
	hashnodeptr* map;	// 指向hash列表
	hashkeysize size;	//default: 1024
}hashmap;


hashkey ipport_to_hashkey(hashmap* map, linkstate ip_port);

void hash_initial(hashmap* map, hashkeysize size);//初始化
void hash_insert(hashmap* map, linkstate val);//插入
void hash_erase(hashmap* map, linkstate val);//擦除
hashnodeptr hash_find(hashmap* map, linkstate val);
void hash_print(hashmap* map);//显示
void hash_release(hashmap* map);//释放
