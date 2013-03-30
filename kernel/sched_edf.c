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
    if (se != edf_rq->curr)
        __enqueue_entity_edf(edf_rq, se);
}

static void
dequeue_entity_edf(struct edf_rq *edf_rq, struct sched_edf_entity *se)
{
    if (se != edf_rq->curr)
        __dequeue_entity_edf(edf_rq, se);
}

static struct sched_edf_entity *__pick_next_entity_edf(struct edf_rq *edf_rq)
{
    struct rb_node *left = edf_rq->rb_leftmost;
    
    if(!left)
        return NULL;

    return rb_entry(left, struct sched_edf_entity, run_node);
}

static struct sched_edf_entity *pick_next_entity_edf(struct edf_rq *edf_rq)
{
    struct sched_edf_entity *se = __pick_next_entity_edf(edf_rq);
    return se;
}

static void 
put_prev_entity_edf(struct edf_rq *edf_rq, struct sched_edf_entity *se)
{
    edf_rq->curr = NULL;
}

static void 
enqueue_task_edf(struct rq *rq, struct task_struct *p,int wakeup)
{
    struct edf_rq *edf_rq;
    struct sched_edf_entity *se = &p->edf_se;

    for_each_sched_entity_edf(se) {
        if (se->on_rq)
            break;
        se->on_rq = 1;
        edf_rq = &rq->edf;
        enqueue_entity_edf(edf_rq, se);
    }
}

static void 
dequeue_task_edf(struct rq *rq, struct task_struct *p, int sleep)
{
    struct edf_rq *edf_rq;
    struct sched_edf_entity *se = &p->edf_se;

    for_each_sched_entity_edf(se) {
        edf_rq = &rq->edf;
        se->on_rq = 0;
        dequeue_entity_edf(edf_rq, se);
    }
}

static struct task_struct *pick_next_task_edf(struct rq *rq)
{
    struct task_struct *p;
    struct edf_rq *edf_rq = &rq->edf;
    struct sched_edf_entity *se;
    
    if (!edf_rq->nr_running)
        return NULL;

    se = pick_next_entity_edf(edf_rq);

    p = edf_task_of(se);
    return p;
}

static void put_prev_task_edf(struct rq *rq, struct task_struct *prev)
{
    /* nothing to be account for a EDF scheduling */
    struct sched_edf_entity *se = &prev->edf_se;
    struct edf_rq *edf_rq;
    
    if (se) {
        edf_rq = &rq->edf;
        put_prev_entity_edf(edf_rq, se);
    }
}

static void 
check_preempt_edf(struct rq *rq, struct task_struct *p, int sync)
{
}

static const struct sched_class edf_sched_class = {
    .next = &fair_sched_class,
    .enqueue_task = enqueue_task_edf,
    .dequeue_task = dequeue_task_edf,
    .yield_task = yield_task_fair,

    .check_preempt_curr = check_preempt_edf,

    .pick_next_task = pick_next_task_edf,
    .put_prev_task = put_prev_task_edf,

#ifdef COMFIG_SMP    
    .select_task_rq = select_task_rq_edf,

    .load_balance   = load_balance_edf,
    .move_one_task = move_one_task_edf,
#endif

	.set_curr_task          = set_curr_task_edf,
	.task_tick		= task_tick_edf,
	.task_new		= task_new_edf,

	.prio_changed		= prio_changed_edf,
	.switched_to		= switched_to_edf,
};
