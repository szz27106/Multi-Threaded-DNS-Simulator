/* A (reverse) trie with reader-writer locks. */

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include "trie.h"

struct trie_node {
  struct trie_node *next;  /* parent list */
  unsigned int strlen; /* Length of the key */
  int32_t ip4_address; /* 4 octets */
  struct trie_node *children; /* Sorted list of children */
  char key[64]; /* Up to 64 chars */
  pthread_cond_t squatting_condition;
  int waiting;
};

static struct trie_node * root = NULL;
static pthread_rwlock_t rwlock;
static pthread_mutex_t squatting_lock;
int allow_squatting;


struct trie_node * new_leaf (const char *string, size_t strlen, int32_t ip4_address) {
  struct trie_node *new_node = malloc(sizeof(struct trie_node));
  if (!new_node) {
    printf ("WARNING: Node memory allocation failed.  Results may be bogus.\n");
    return NULL;
  }
  assert(strlen < 64);
  assert(strlen > 0);
  new_node->next = NULL;
  new_node->strlen = strlen;
  strncpy(new_node->key, string, strlen);
  new_node->key[strlen] = '\0';
  new_node->ip4_address = ip4_address;
  new_node->children = NULL;
  
  int rv = pthread_cond_init(&(new_node->squatting_condition), NULL);
  assert(rv == 0);
  new_node->waiting = 0;

  return new_node;
}

int compare_keys (const char *string1, int len1, const char *string2, int len2, int *pKeylen) {
    int keylen, offset1, offset2;
    keylen = len1 < len2 ? len1 : len2;
    offset1 = len1 - keylen;
    offset2 = len2 - keylen;
    assert (keylen > 0);
    if (pKeylen)
      *pKeylen = keylen;
    return strncmp(&string1[offset1], &string2[offset2], keylen);
}

void init(int numthreads) {
    int old = -1;
	int rv = pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &old);
    rv = pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &old);
    root = NULL;
	
	// initailize rwlock
	rv = pthread_rwlock_init(&rwlock, NULL);
	assert(rv == 0);
	
	assert(allow_squatting == 1);
	
	// initialize squatting condition variable and lock
	// this needs to have a seperate mutex bc rwlocks
	// do not support waiting on a condition variable

	rv = pthread_mutex_init(&squatting_lock, NULL);
	assert(rv == 0);
}

/* Recursive helper function.
 * Returns a pointer to the node if found.
 * Stores an optional pointer to the 
 * parent, or what should be the parent if not found.
 * 
 * Not thread safe
 */
struct trie_node * 
_search (struct trie_node *node, const char *string, size_t strlen) {
	 
  int keylen, cmp;

  // First things first, check if we are NULL 
  if (node == NULL) return NULL;

  assert(node->strlen < 64);

  // See if this key is a substring of the string passed in
  cmp = compare_keys(node->key, node->strlen, string, strlen, &keylen);
  if (cmp == 0) {
    // Yes, either quit, or recur on the children

    // If this key is longer than our search string, the key isn't here
    if (node->strlen > keylen) {
      return NULL;
    } else if (strlen > keylen) {
      // Recur on children list
      return _search(node->children, string, strlen - keylen);
    } else {
      assert (strlen == keylen);

      return node;
    }

  } else if (cmp < 0) {
    // No, look right (the node's key is "less" than the search key)
    return _search(node->next, string, strlen);
  } else {
    // Quit early
    return 0;
  }

}


int search  (const char *string, size_t strlen, int32_t *ip4_address) {
  struct trie_node *found;

  // Skip strings of length 0
  if (strlen == 0)
    return 0;

	// critical area
	printf("wating for read lock\n");
  int lockAquired =	pthread_rwlock_rdlock(&rwlock); 
  assert(lockAquired == 0);
  printf("wating for read lock done\n");
  found = _search(root, string, strlen);
  
  if (found && ip4_address)
    *ip4_address = found->ip4_address;
  
  int rv = found != NULL;
  
  int lockReleased = pthread_rwlock_unlock(&rwlock);
  assert(lockReleased == 0);
  // end critical area
  return rv;
}

/* Recursive helper function 
 * Not thread safe
 */
int _insert (const char *string, size_t strlen, int32_t ip4_address, 
	     struct trie_node *node, struct trie_node *parent, struct trie_node *left) {

  int cmp, keylen;

  // First things first, check if we are NULL 
  assert (node != NULL);
  assert (node->strlen < 64);
  assert (node->strlen > 0);
  assert (strlen > 0);

  // Take the minimum of the two lengths
  cmp = compare_keys (node->key, node->strlen, string, strlen, &keylen);
  if (cmp == 0) {
    // Yes, either quit, or recur on the children

    // If this key is longer than our search string, we need to insert
    // "above" this node
    if (node->strlen > keylen) {
      struct trie_node *new_node;

      assert(keylen == strlen);
      assert((!parent) || parent->children == node);

      new_node = new_leaf (string, strlen, ip4_address);
      node->strlen -= keylen;
      new_node->children = node;

      assert ((!parent) || (!left));

      if (parent) {
	parent->children = new_node;
      } else if (left) {
	left->next = new_node;
      } else if ((!parent) || (!left)) {
	root = new_node;
      }
      return 1;

    } else if (strlen > keylen) {
      
      if (node->children == NULL) {
	// Insert leaf here
	struct trie_node *new_node = new_leaf (string, strlen - keylen, ip4_address);
	node->children = new_node;
	return 1;
      } else {
	// Recur on children list, store "parent" (loosely defined)
      return _insert(string, strlen - keylen, ip4_address,
		     node->children, node, NULL);
      }
    } 
	else 
	{
      assert (strlen == keylen);
      if (node->ip4_address == 0) 
	  {
	    node->ip4_address = ip4_address;
	    return 1;
      } 
	  else 
	  {
	    
	    
	    //TODO put in another function
	    if(allow_squatting)
		{
		  node->waiting++;
		  int inserted = 0;
		  while(!inserted)
		  {
			  int lockReleased = pthread_rwlock_unlock(&rwlock); 
			  assert(lockReleased == 0);
			  
			  printf("wating for squat lock\n");
			  int mutexAquired = pthread_mutex_lock(&squatting_lock);
			  assert(mutexAquired == 0);
			  printf("wating for squat lock done\n");
			  
			  //aquire waiting lock
			  while(node->ip4_address != 0)
			  {
				int rv = pthread_cond_wait(&(node->squatting_condition), &squatting_lock);
				assert(rv == 0);
			  }
			  
			  int mutexReleased = pthread_mutex_unlock(&squatting_lock);
			  assert(mutexReleased == 0);
			  
			  printf("wating for write lock\n");
			  int lockAquired = pthread_rwlock_wrlock(&rwlock); 
			  assert(lockAquired == 0);
			  printf("wating for write lock done\n");
			  
			  if(node->ip4_address == 0)
			  {
				  node->ip4_address = ip4_address;
				  node->waiting--;
				  inserted = 1;
			  }
		  }
			
	      return 1;
		}
	    
		return 0;
      }
    }

  } else {
    /* Is there any common substring? */
    int i, cmp2, keylen2, overlap = 0;
    for (i = 1; i < keylen; i++) {
	assert(node->strlen - i > 0);
	assert(strlen - i > 0);
      cmp2 = compare_keys (&node->key[i], node->strlen - i, 
			   &string[i], strlen - i, &keylen2);
      assert (keylen2 > 0);
      if (cmp2 == 0) {
	overlap = 1;
	break;
      }
    }

    if (overlap) {
      // Insert a common parent, recur
      struct trie_node *new_node = new_leaf (&string[i], strlen - i, 0);
      int diff = node->strlen - i;
      assert ((node->strlen - diff) > 0);
      node->strlen -= diff;
      new_node->children = node;
      assert ((!parent) || (!left));

      if (node == root) {
	new_node->next = node->next;
	node->next = NULL;
	root = new_node;
      } else if (parent) {
	assert(parent->children == node);
	new_node->next = NULL;
	parent->children = new_node;
      } else if (left) {
	new_node->next = node->next;
	node->next = NULL;
	left->next = new_node;
      } else if ((!parent) && (!left)) {
	root = new_node;
      }

      return _insert(string, i, ip4_address,
		     node, new_node, NULL);
    } else if (cmp < 0) {
      if (node->next == NULL) {
	// Insert here
	struct trie_node *new_node = new_leaf (string, strlen, ip4_address);
	node->next = new_node;
	return 1;
      } else {
	// No, recur right (the node's key is "greater" than  the search key)
	return _insert(string, strlen, ip4_address, node->next, NULL, node);
      }
    } else {
      // Insert here
      struct trie_node *new_node = new_leaf (string, strlen, ip4_address);
      new_node->next = node;
      if (node == root)
	root = new_node;
      else if (parent && parent->children == node)
	parent->children = new_node;
    }
    return 1;
  }
}

int insert (const char *string, size_t strlen, int32_t ip4_address) {
  // Skip strings of length 0
  if (strlen == 0)
    return 0;
	
  int inserted;
  
  int rwlockAquired =	pthread_rwlock_wrlock(&rwlock); 
  assert(rwlockAquired == 0);
  
  if (root == NULL) {
    root = new_leaf (string, strlen, ip4_address);
    inserted = 1;
  }
  else
  {
    inserted = _insert(string, strlen, ip4_address, root, NULL, NULL);
  }
  
  int rwlockReleased = pthread_rwlock_unlock(&rwlock);
  assert(rwlockReleased == 0);
  
  
  if(inserted)
  {
	printf("Inserted: %s\n", string);
  }
  else
  {
    printf("Insert Failed: %s\n", string);
  }
  
  return inserted;
}

/* Recursive helper function.
 * Returns a pointer to the node if found.
 * Stores an optional pointer to the 
 * parent, or what should be the parent if not found.
 * 
 * Not thread-safe! use delete() instead.
 */
struct trie_node * 
_delete (struct trie_node *node, const char *string, 
	 size_t strlen) {
  int keylen, cmp;

  // First things first, check if we are NULL 
  if (node == NULL) return NULL;

  assert(node->strlen < 64);

  // See if this key is a substring of the string passed in
  cmp = compare_keys (node->key, node->strlen, string, strlen, &keylen);
  if (cmp == 0) {
    // Yes, either quit, or recur on the children

    // If this key is longer than our search string, the key isn't here
    if (node->strlen > keylen) {
      return NULL;
    } else if (strlen > keylen) {
      struct trie_node *found =  _delete(node->children, string, strlen - keylen);
      if (found) {
	/* If the node doesn't have children, delete it.
	 * Otherwise, keep it around to find the kids */
	if (found->children == NULL && found->ip4_address == 0 && found->waiting == 0) {
	  assert(node->children == found);
	  node->children = found->next;
	  free(found);
	}
	
	/* Delete the root node if we empty the tree */
	if (node == root && node->children == NULL && node->ip4_address == 0 && node->waiting == 0) {
	  root = node->next;
	  free(node);
	}
	
	return node; /* Recursively delete needless interior nodes */
      } else 
	return NULL;
    } else {
      assert (strlen == keylen);

      /* We found it! Clear the ip4 address and return. */
      if (node->ip4_address) {
	  
	  printf("waiting to squat\n");
	  int mutexAquired = pthread_mutex_lock(&squatting_lock);
	  printf("waiting to squat done\n");
      assert(mutexAquired == 0);
	  
	  node->ip4_address = 0;
	  if(node->waiting > 0)
	  {
		pthread_cond_signal(&(node->squatting_condition));
	  }
	  
	  int mutexReleased = pthread_mutex_unlock(&squatting_lock);
      assert(mutexReleased == 0);

	/* Delete the root node if we empty the tree */
	if (node == root && node->children == NULL && node->ip4_address == 0 && node->waiting == 0) 
	{
	  root = node->next;
	  free(node);
	  return (struct trie_node *) 0x100100; /* XXX: Don't use this pointer for anything except 
						 * comparison with NULL, since the memory is freed.
						 * Return a "poison" pointer that will probably 
						 * segfault if used.
						 */
	}
	
	  return node;
      } else {
	/* Just an interior node with no value */
	return NULL;
      }
    }

  } else if (cmp < 0) {
    // No, look right (the node's key is "less" than  the search key)
    struct trie_node *found = _delete(node->next, string, strlen);
    if (found) {
      /* If the node doesn't have children, delete it.
       * Otherwise, keep it around to find the kids */
      if (found->children == NULL && found->ip4_address == 0 && found->waiting == 0) {
	    assert(node->next == found);
	    node->next = found->next;
	    free(found);
      }

      return node; /* Recursively delete needless interior nodes */
    }
    return NULL;
  } else {
    // Quit early
    return NULL;
  }

}

int delete  (const char *string, size_t strlen) {
  // Skip strings of length 0
  if (strlen == 0)
    return 0;
	
  printf("Waiting for write lock\n");
  int rwlockAquired =	pthread_rwlock_wrlock(&rwlock); 
  assert(rwlockAquired == 0);
  printf("Waiting for write lock done\n");
  
  int rv =(NULL != _delete(root, string, strlen));
  
  int rwlockReleased = pthread_rwlock_unlock(&rwlock);
  assert(rwlockReleased == 0);
  
  
  if(rv)
  {
	printf("Deleted: %s\n", string);
  }
  else
  {
    printf("Delete Failed: %s\n", string);
  }
  return rv;
}


void _print (struct trie_node *node) {
  printf ("Node at %p.  Key %.*s, IP %d.  Next %p, Children %p\n", 
	  node, node->strlen, node->key, node->ip4_address, node->next, node->children);
  if (node->children)
    _print(node->children);
  if (node->next)
    _print(node->next);
}

void print() {
  /* Do a simple depth-first search */
  printf("Waiting for read lock\n");
  int lockAquired =	pthread_rwlock_rdlock(&rwlock); 
  assert(lockAquired == 0);
  printf("Waiting for read lock\n");
  
  printf ("Root is at %p\n", root);
  /* Do a simple depth-first search */
  if (root)
    _print(root);

  
  int lockReleased = pthread_rwlock_unlock(&rwlock);
  assert(lockReleased == 0);
  
}

