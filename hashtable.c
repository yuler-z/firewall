#include "hashtable.h"

// hash function
uint hash(const struct* keywords){
    uint hash_value;
    //TODO
    retrun hash_value;
}
node* malloc_node(uint value){
    node* np = (node*)kmalloc(sizeof(node), GFP_KERNEL);
    if(np == NULL) return NULL;
    return np;
}
Status init_hashtable(node** hashtable){
    for (int i = 0; i < HASHSIZE; i++){
        hashtable[i] = NULL;
    }
    
}
Action lookup_hashtable(node** hashtable, uint hash_value){
    node* np = hashtable[hash_value % HASHSIZE];
    while(np != NULL){
        if(np->value == hash_value){
            return np->action;
        }
    }
    return Not_Find;
}

Status insert_hashtable(node** hashtable, uint hash_value){
    node* np = malloc_node(hash_value);
    if(np == NULL) return False;
    np->next = hashtable[hash_value % HASHSIZE];
    hashtable[hash_value % HASHSIZE] = np;
    return True;
}
void clear_hashtable(node** hashtable){
	node * np; 
	node *tmp;//下一个结点
	//遍历表
	for (int i = 0; i < HASHSIZE; i++)
	{
		//获取其中一个元素
		np = hashtable[i];
		if (np != NULL)
		{
			hashtable[i] = NULL;
			tmp = np;
			tmp = tmp->next;
			kfree(np);
			while (tmp!=NULL)
			{
				np = tmp;
				kfree(np);
				tmp = tmp->next;
			}
		}
	}
}