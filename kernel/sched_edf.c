static inline unsigned long 
entity_key_edf(struct edf_rq *edf_rq, struct sched_entity *se)
{
    return se->netlock_timeout;
}

static inline struct edf_rq *edf_rq_of(struct sched_entity *se)
{
    return se->edf_rq;
}

static void
__enqueue_entity_edf(struct edf_rq *edf_rq, struct sched_entity *se)
{
    struct rb_node **link = &edf_rq->task_root.rb_node;
    struct rb_node *parent = NULL;
    struct sched_entity *entry;
    unsigned long  key = entity_key_edf(edf_rq, se);
    int leftmost = 1;

    while (*link) {
        parent = *link;
        entry = rb_entry(parent, struct sched_entity, run_node);
        
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
__dequeue_entity_edf(struct edf_rq *edf_rq, struct sched_entity *se)
{
    if (edf_rq->rb_leftmost == &se->run_node) {
        struct rb_node *next_node;

        next_node = rb_next(&se->run_node);
        edf_rq->rb_leftmost = next_node;
    }
    
    rb_erase(&se->run_node, &edf_rq->task_root);
}

static void
enqueue_entity_edf(struct edf_rq *edf_rq, struct sched_entity *se)
{
    if (se != edf_rq->curr)
        __enqueue_entity_edf(edf_rq, se);
}

static void
dequeue_entity_edf(struct edf_rq *edf_rq, struct sched_entity *se)
{
    if (se != edf_rq->curr)
        __dequeue_entity_edf(edf_rq, se);
}

static struct sched_entity *__pick_next_entity_edf(struct edf_rq *edf_rq)
{
    struct rb_node *left = edf_rq->rb_leftmost;
    
    if(!left)
        return NULL;

    return rb_entry(left, struct sched_entity, run_node);
}

static struct sched_entity *pick_next_entity_edf(struct edf_rq *edf_rq)
{
    struct sched_entity *se = __pick_next_entity_edf(edf_rq);
    return se;
}

static void 
put_prev_entity_edf(struct edf_rq *edf_rq, struct sched_entity *prev)
{
    edf_rq->curr = NULL;
}

static void enqueue_task_edf(struct rq *rq, struct task_struct *p,int wakeup)
{
    struct edf_rq *edf_rq;
    struct sched_entity *se = &p->se;

    if (se) {
        if (se->on_rq)
            break;
        edf_rq = edf_rq_of(se);
        enqueue_entity_edf(edf_rq, se);
    }
}

static void dequeue_task_edf(struct rq *rq, struct task_struct *p, int sleep)
{
    struct edf_rq *edf_rq;
    struct sched_entity *se = &p->se;

    if (se) {
        edf_rq = edf_rq_of(se);
        dequeue_entity_edf(edf_rq, se);
    }
}

static struct task_struct *pick_next_task_edf(struct rq *rq)
{
    struct task_struct *p;
    struct edf_rq *edf_rq = &rq->edf;
    struct sched_entity *se;
    
    if (!edf_rq->nr_running)
        return NULL;

    se = pick_next_entity_edf(edf_rq);

    p = task_of(se);
    return p;
}

static void put_prev_task_edf(struct rq *rq, struct task_struct *prev)
{
    /* nothing to be account for a EDF scheduling */
    struct sched_entity *se = &prev->se;
    struct edf_rq *edf_rq;
    
    if (se) {
        edf_rq = edf_rq_of(se);
        put_prev_entity_edf(edf_rq, se);
    }
}

static const struct sched_class edf_sched_class = {
    .next = &fair_sched_class,
    .enqueue_task = enqueue_task_edf,
    .dequeue_task = dequeue_task_edf,
    .yield_task = yield_task_fair,

    .pick_next_task = pick_next_task_edf,
    .put_prev_task = put_prev_task_edf,
    
};
