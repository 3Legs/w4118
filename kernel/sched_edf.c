#include "linux/random.h"

#define for_each_sched_entity_edf(se) \
	for (; se; se = NULL)

static const struct sched_class edf_sched_class;

static inline struct task_struct *
edf_task_of(struct sched_edf_entity *se)
{
	return container_of(se, struct task_struct, edf_se);
}

static inline unsigned long
entity_key_edf(struct edf_rq *edf_rq, struct sched_edf_entity *se)
{
	return se->netlock_timeout;
}

static void
account_edf_entity_enqueue(struct edf_rq *edf_rq, struct sched_edf_entity *se)
{
	edf_rq->nr_running++;
	se->on_rq = 1;
}

static void
account_edf_entity_dequeue(struct edf_rq *edf_rq, struct sched_edf_entity *se)
{
	edf_rq->nr_running--;
	se->on_rq = 0;
}

static void
__enqueue_entity_edf(struct edf_rq *edf_rq, struct sched_edf_entity *se)
{
	struct rb_node **link = &edf_rq->task_root.rb_node;
	struct rb_node *parent = NULL;
	struct sched_edf_entity *entry;
	unsigned long  key = entity_key_edf(edf_rq, se);
	int leftmost = 1;

	while (*link) {
		parent = *link;
		entry = rb_entry(parent, struct sched_edf_entity, run_node);
		if (key < entity_key_edf(edf_rq, entry)) {
			link = &parent->rb_left;
		} else {
			link = &parent->rb_right;
			leftmost = 0;
		}
	}

	if (leftmost)
		edf_rq->rb_leftmost = &se->run_node;

	rb_link_node(&se->run_node, parent, link);
	rb_insert_color(&se->run_node, &edf_rq->task_root);
}

static void
__dequeue_entity_edf(struct edf_rq *edf_rq, struct sched_edf_entity *se)
{
	if (edf_rq->rb_leftmost == &se->run_node) {
		struct rb_node *next_node;

		next_node = rb_next(&se->run_node);
		edf_rq->rb_leftmost = next_node;
	}
	
	rb_erase(&se->run_node, &edf_rq->task_root);
}

static void
enqueue_entity_edf(struct edf_rq *edf_rq, struct sched_edf_entity *se)
{
	__enqueue_entity_edf(edf_rq, se);
	account_edf_entity_enqueue(edf_rq, se);
}

static void
dequeue_entity_edf(struct edf_rq *edf_rq, struct sched_edf_entity *se)
{
	__dequeue_entity_edf(edf_rq, se);
	account_edf_entity_dequeue(edf_rq, se);
}

static struct sched_edf_entity *__pick_next_entity_edf(struct edf_rq *edf_rq)
{
	struct rb_node *left = edf_rq->rb_leftmost;

	if (!left)
		return NULL;

	return rb_entry(left, struct sched_edf_entity, run_node);
}

static struct sched_edf_entity *pick_next_entity_edf(struct edf_rq *edf_rq)
{
	struct sched_edf_entity *se = __pick_next_entity_edf(edf_rq);
	return se;
}

static void
enqueue_task_edf(struct rq *rq, struct task_struct *p,int wakeup)
{
	struct edf_rq *edf_rq;
	struct sched_edf_entity *se = &p->edf_se;

	if (se && !se->on_rq) {
		edf_rq = &rq->edf;
		enqueue_entity_edf(edf_rq, se);
	}

	printk(KERN_ALERT "New EDF process %d enqueued, total number is %lu\n", edf_task_of(se)->pid, rq->edf.nr_running);
}

static void
dequeue_task_edf(struct rq *rq, struct task_struct *p, int sleep)
{
	struct edf_rq *edf_rq = &rq->edf;
	struct sched_edf_entity *se = &p->edf_se;

	if (se)
		dequeue_entity_edf(edf_rq, se);

	printk(KERN_ALERT "EDF process %d dequeued, total number is %lu\n", edf_task_of(se)->pid, edf_rq->nr_running);
}

static void
set_next_edf_entity(struct edf_rq *edf_rq, struct sched_edf_entity *se)
{
	edf_rq->curr = se;
}

static struct task_struct *pick_next_task_edf(struct rq *rq)
{
	struct task_struct *p;
	struct edf_rq *edf_rq = &rq->edf;
	struct sched_edf_entity *se;
	unsigned int rand;

	/* We set 20% probability to force EDF process yield next*/
	get_random_bytes(&rand, sizeof(unsigned int));
	rand = rand % 10;

	if ((rand <= 2) || !edf_rq || !edf_rq->nr_running) {
		return NULL;
	}

	se = pick_next_entity_edf(edf_rq);
	if (se) {
		set_next_edf_entity(edf_rq, se);
		p = edf_task_of(se);
		if (p)
			printk(KERN_ALERT "EDF task %d is picked, total number is %lu\n", p->pid, edf_rq->nr_running);
		return p;
	}
	return NULL;
}

static void put_prev_task_edf(struct rq *rq, struct task_struct *prev)
{
	printk(KERN_ALERT "EDF task %d is put\n", prev->pid);
}

static void
check_preempt_curr_edf(struct rq *rq, struct task_struct *p, int sync)
{
	struct task_struct *curr = rq->curr;
	struct sched_edf_entity *se = &curr->edf_se, *pse = &p->edf_se;
	struct edf_rq *edf_rq = &rq->edf;

	if (unlikely(curr == p)) {
		return;
	}

	if (curr->policy != SCHED_FIFO &&
		curr->policy != SCHED_RR &&
		curr->policy != SCHED_EDF &&
		p->policy == SCHED_EDF) {
		resched_task(curr);
		return;
	}

	if (curr->policy == SCHED_EDF && p->policy == SCHED_EDF) {
		if (entity_key_edf(edf_rq, pse) < entity_key_edf(edf_rq, se)) {
			/* new task has a earlier deadline */
			resched_task(curr);
		}
	}
}

static void
task_tick_edf (struct rq *rq, struct task_struct *curr, int queued)
{

}

static void
set_curr_task_edf (struct rq *rq)
{
	struct sched_edf_entity *se = &rq->curr->edf_se;
	if (se)
		set_next_edf_entity(&rq->edf, se);
}

static void
switched_to_edf (struct rq *this_rq, struct task_struct *task,
					 int running)
{
	printk(KERN_ALERT "Process %d switched to EDF ", task->pid);
	/* enqueue_task_edf(this_rq, task, running); */
	if (running) {
		printk(KERN_ALERT "Process %d is running\n", task->pid);
	}
	check_preempt_curr_edf(this_rq, task, 0);
}

static void
switched_from_edf (struct rq *rq, struct task_struct *p, int running) {

}

static const struct sched_class edf_sched_class = {
	.next = &fair_sched_class,
	.enqueue_task = enqueue_task_edf,
	.dequeue_task = dequeue_task_edf,
	.yield_task = yield_task_fair,

	.check_preempt_curr = check_preempt_curr_edf,

	.pick_next_task = pick_next_task_edf,
	.put_prev_task = put_prev_task_edf,

#ifdef COMFIG_SMP
	.select_task_rq = select_task_rq_edf,

	.load_balance   = load_balance_edf,
	.move_one_task = move_one_task_edf,
#endif

	.set_curr_task          = set_curr_task_edf,
	.task_tick		= task_tick_edf,
	/* .task_new		= task_new_edf, */

	/* .prio_changed		= prio_changed_edf, */
	.switched_to		= switched_to_edf,
	.switched_from      = switched_from_edf,
};
