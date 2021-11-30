#include <stdio.h>
#include <stdlib.h>
#include "queue.h"

int empty(struct queue_t * q) {
	return (q->size == 0);
}

void enqueue(struct queue_t * q, struct pcb_t * proc) {
	/* TODO: put a new process to queue [q] */	
	if (q->size == MAX_QUEUE_SIZE) return;
	q->proc[q->size++] = proc;
}

struct pcb_t * dequeue(struct queue_t * q) {
	/* TODO: return a pcb whose prioprity is the highest
	 * in the queue [q] and remember to remove it from q
	 * */
	if (!empty(q)){
		int max_i = 0;
		uint32_t max = q->proc[0]->priority;
		for (int i = 1; i < q->size; i++){
			if (q->proc[i]->priority > max) {
				max = q->proc[i]->priority;
				max_i = i;
			}	
		}
		//struct pcb_t * maxPCB = (struct pcb_t *)malloc(sizeof(struct pcb_t));
		maxPCB = q->proc[max_i];

		for (int i = max_i; i < q->(size-1); i++){
			q->proc[i] = q->proc[i + 1]; 
		}
		q->proc[q->size - 1] = NULL;
		q->size--;
		return maxPCB;
	}
	return NULL;
}

