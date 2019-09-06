#ifndef _HashTable_H
#define _HashTable_H

#include "test_mod.h"

// Status
#define True 1 
#define False 0 
typedef int Status;

// Action
#define Allow 0
#define Deny 1
#define Not_Find 2
typedef int Action;

#define HASHSIZE 1024

typedef unsigned int uint;
typedef struct{
    uint value;
    Action action;
    struct node* next;
}node;

static node*  hashtable[HASHSIZE];
// hash function
uint hash(const struct keywords* keywords);

node* malloc_node(uint value);
Status init_hashtable(node* node);
Status lookup_hashtable(int hash_value);
Statue insert_hashtable(int hash_value);
void clear_hashtable();





#endif