#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "list.h"
#include "lib.h"

list constr(void *element, list l)
{
	list temp = malloc(sizeof(struct cell));
	temp->element = element;
	temp->next = l;
	return temp;
}

list cdr_and_free(list l)
{
	list temp = l->next; 
	free(l);
	return temp;
}
