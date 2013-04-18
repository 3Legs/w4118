#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/spinlock.h>
#include <linux/cred.h>
#include <linux/rwsem.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <linux/slab.h>
#include <linux/backing-dev.h>
#include <linux/mm.h>
#include <linux/shm.h>
#include <linux/mman.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/syscalls.h>
#include <linux/capability.h>
#include <linux/init.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/personality.h>
#include <linux/security.h>
#include <linux/hugetlb.h>
#include <linux/profile.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/mempolicy.h>
#include <linux/rmap.h>
#include <linux/mmu_notifier.h>
#include <linux/bitmap.h>

#include <asm/uaccess.h>
#include <asm/cacheflush.h>
#include <asm/tlb.h>
#include <asm/mmu_context.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>

#include "internal.h"

/* macro define */
#define SSMEM_TEST_ALLOC(id) test_bit(id, ssmem_alloc)

#define SSMEM_SET_ALLOC(id) set_bit(id, ssmem_alloc)
#define SSMEM_UNSET_ALLOC(id) clear_bit(id, ssmem_alloc)

#define SSMEM_MASTER(ssmem) (ssmem->master)
#define deb(a) printk(KERN_ALERT "%d\n", a)

#define SSMEM_MAX 1024
#define SSMEM_FLAG_CREATE   0x1
#define SSMEM_FLAG_WRITE    0x2
#define SSMEM_FLAG_EXEC     0x4

/* global variable */

static atomic_t ssmem_count = ATOMIC_INIT(0);
DEFINE_MUTEX(ssmem_list_lock);
DECLARE_BITMAP(ssmem_alloc, SSMEM_MAX);

/* structures define */

struct ssmem_vm {
	struct vm_area_struct *vma;
	pid_t owner;
	struct list_head list;
};

struct ssmem_struct {
	int id; /*ssmem ID */
	size_t length; /* length of the ssmem */
	atomic_t mappers; /* number of mappers */
	pid_t master;
	struct ssmem_vm *vm_list; /* list of mappers */
	struct anon_vma *rmap; /* reverse map */
	struct list_head list;
    struct mutex ssmem_vm_list_lock;
};

/* function declare */

static int ssmem_fault(struct vm_area_struct *vma, struct vm_fault *vmf);
static void ssmem_close(struct vm_area_struct *area);

/* objects initialize */

struct ssmem_struct ssmem_head = {
	.id = -1,
	.list = LIST_HEAD_INIT(ssmem_head.list),
};

static struct vm_operations_struct ssmem_vm_ops = {
	.close = ssmem_close,
	.fault = ssmem_fault,
};

struct list_head *ssmem_list_head = &(ssmem_head.list);

static void ssmem_set_anon(struct ssmem_struct *ssmem, struct anon_vma *anon)
{
	ssmem->rmap = anon;
}

static struct ssmem_struct *
__get_ssmem(int id)
{
	struct ssmem_struct *cur, *next;
	list_for_each_entry_safe(cur, next, &(ssmem_head.list), list) {
		if (cur->id == id)
			return cur;
	}
	return NULL;
}

static struct ssmem_vm *
__get_ssmem_vm(struct vm_area_struct *vma)
{
	struct ssmem_vm *cur, *next;
	struct ssmem_struct *ssmem = vma->vm_private_data;
	if (!ssmem)
		return NULL;

	list_for_each_entry_safe(cur, next, &ssmem->vm_list->list, list) {
		if (cur->vma == vma)
			return cur;
	}

	return NULL;
}

static int 
__ssmem_fault_master(struct vm_area_struct *vma,
	struct ssmem_struct *data, void *addr)
{
	struct page *page;
	pte_t *page_table;
	spinlock_t *ptl;
	pte_t entry;

	if (unlikely(anon_vma_prepare(vma))) {
		printk(KERN_ALERT "ERROR after anon_vma_prepare!\n");
		return VM_FAULT_OOM;
	}

	anon_vma_link(vma);
	ssmem_set_anon(data, vma->anon_vma);

	page = alloc_page(GFP_USER);
	if (!page)
		return VM_FAULT_OOM;
	page_table = get_locked_pte(vma->vm_mm, (unsigned long)addr, &ptl);
	entry = mk_pte(page, vma->vm_page_prot);
	if (likely(vma->vm_flags & VM_WRITE))
		entry = pte_mkwrite(entry);
	get_page(page);

	inc_mm_counter(vma->vm_mm, anon_rss);
	page_add_new_anon_rmap(page, vma, (unsigned long)addr);
	set_pte_at(vma->vm_mm, (unsigned long)addr, page_table, entry);
	pte_unmap_unlock(page_table, ptl);

	return 0;
}

static int 
__ssmem_fault_slave(struct vm_area_struct *vma_s, struct vm_area_struct *vma_m,
	struct ssmem_struct *data, void *addr)
{
	spinlock_t *ptl_s, *ptl_m;
	pte_t *pte_s, *pte_m;

	pte_s = get_locked_pte(vma_s->vm_mm, (unsigned long)addr, &ptl_s);
	pte_m = get_locked_pte(vma_m->vm_mm, (unsigned long)(vma_m->vm_start + addr - vma_s->vm_start), &ptl_m);

	if (pte_none(*pte_m)) {
		__ssmem_fault_master(vma_m, data, vma_m->vm_start + addr - vma_s->vm_start);
	}

	set_pte_at(vma_s->vm_mm, (unsigned long)addr, pte_s, *pte_m);
	pte_unmap_unlock(pte_m, ptl_m);
	pte_unmap_unlock(pte_s, ptl_s);

	return 0;
}

static int ssmem_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct ssmem_struct *data = vma->vm_private_data;
	int result;
	struct ssmem_vm *cur, *next, *master_vm = NULL;

	if (data->master == current->pid) {
		result = __ssmem_fault_master(vma, data, vmf->virtual_address);
	} else {
		mutex_lock(&data->ssmem_vm_list_lock);

		list_for_each_entry_safe(cur, next, &data->vm_list->list, list) {
			if (SSMEM_MASTER(data) == cur->owner) {
				master_vm = cur;
				break;
			}
		}

		mutex_unlock(&data->ssmem_vm_list_lock);

		result = __ssmem_fault_slave(vma, master_vm->vma, data, vmf->virtual_address);
	}

	if (result) {
		printk("ERROR in ssmem_fault!\n");
	}
	return VM_FAULT_NOPAGE;
}


/*
 * __copy_page_table
 * 
 * copy one vma's page table entries to another vma
 */
static void 
__copy_page_table(struct vm_area_struct *source_vma,
		  struct vm_area_struct *target_vma)
{
	unsigned long source_start = source_vma->vm_start;
	unsigned long target_start = target_vma->vm_start;
	unsigned long len = source_vma->vm_end - source_start;
	unsigned long offset;
	spinlock_t *ptl_source, *ptl_target;
	pte_t *pte_source, *pte_target;

	for (offset = 0; offset < len; offset += PAGE_SIZE) {
		pte_source = get_locked_pte(source_vma->vm_mm, source_start + offset, &ptl_source);
		if (!pte_none(*pte_source)) {
			pte_target = get_locked_pte(target_vma->vm_mm, target_start + offset, &ptl_target);
			set_pte_at(target_vma->vm_mm, target_start + offset, pte_target, *pte_source);
			pte_unmap_unlock(pte_target, ptl_target);
		}
		pte_unmap_unlock(pte_source, ptl_source);
	}
}


/*
 * __assign_master
 *
 * assign the master of ssmem to another process
 * and copy old master's pte to new master.
 *
 */
static void __assign_master(struct ssmem_struct *ssmem)
{
	struct ssmem_vm *cur, *next, *master_vm;
	/* need to lock ssmem list */
	printk(KERN_ALERT "PID %d is out, need to reassign master\n", current->pid);
	mutex_lock(&ssmem->ssmem_vm_list_lock);

	list_for_each_entry_safe(cur, next, &ssmem->vm_list->list, list) {
		if (SSMEM_MASTER(ssmem) == cur->owner) {
			master_vm = cur;
			break;
		}
	}

	list_for_each_entry_safe(cur, next, &ssmem->vm_list->list, list) {
		if (SSMEM_MASTER(ssmem) != cur->owner) {
			__copy_page_table(master_vm->vma, cur->vma);
			ssmem->master = cur->owner;
			printk(KERN_ALERT "PID %d is the new master\n", ssmem->master);
			break;
		}
	}
	mutex_unlock(&ssmem->ssmem_vm_list_lock);
}

static inline void
__delete_ssmem(struct ssmem_struct *ssmem) {
	mutex_lock(&ssmem_list_lock);
	SSMEM_UNSET_ALLOC(ssmem->id);
	list_del(&(ssmem->list));
	atomic_dec(&ssmem_count);
	mutex_unlock(&ssmem_list_lock);
}



/*
 *__unmap_ssmem_region(struct mm_struct *mm, struct vm_area_struct *vma)
 *
 */
static void
__unmap_ssmem_region(struct mm_struct *mm, struct vm_area_struct *vma)
{
	unsigned long start, end;
	struct mmu_gather *tlb;
	unsigned long nr_accounted = 0;
	
	start = vma->vm_start;
	end = vma->vm_end;

	lru_add_drain();
	tlb = tlb_gather_mmu(mm, 0);
	update_hiwater_rss(mm);
	unmap_vmas(&tlb, vma, start, end, &nr_accounted, NULL);
	vm_unacct_memory(nr_accounted);
	free_pgtables(tlb, vma, start, end);
	tlb_finish_mmu(tlb, start, end);
}

/*
 * __detach_ssmem_vma_to_be_unmapped
 *
 */
static void
__detach_ssmem_vma_to_be_unmapped(struct mm_struct *mm,
				  struct vm_area_struct *vma)
{
	unsigned long addr;
	struct vm_area_struct *prev, *next;
	
	find_vma_prev(mm, vma->vm_start, &prev);

	rb_erase(&vma->vm_rb, &mm->mm_rb);
	mm->map_count--;

	next = vma->vm_next;
	prev->vm_next = next;
	vma->vm_next = NULL;

	addr = next ? next->vm_start : mm->mmap_base;

	mm->unmap_area(mm, addr);
	mm->mmap_cache = NULL;
}

/*
 * __do_ssmem_munmap
 *
 *
 */

static void __do_ssmem_munmap(struct vm_area_struct *vma)
{
	struct mm_struct *mm = vma->vm_mm;
	long nrpages = vma_pages(vma);

	if (mm->locked_vm && (vma->vm_flags & VM_LOCKED)) {
		mm->locked_vm -= vma_pages(vma);
		munlock_vma_pages_all(vma);
	}

	__detach_ssmem_vma_to_be_unmapped(mm, vma);
	__unmap_ssmem_region(mm, vma);

	update_hiwater_vm(mm);
	mm->total_vm -= nrpages;
	vm_stat_account(mm, vma->vm_flags, vma->vm_file, -nrpages);
	mpol_put(vma_policy(vma));
	kmem_cache_free(vm_area_cachep, vma);
}

/*
 * ssmem_close
 * callback routine when a process need to close the vma
 * 
 * 1. Check whether the current ssmem_struct is shared by
 *    processes.
 * 2. If it's the last(only) one, do the actual close
 */

static void ssmem_close(struct vm_area_struct *area)
{
	struct ssmem_struct *ssmem = area->vm_private_data;
	struct ssmem_vm *s_vm;
	mutex_lock(&ssmem->ssmem_vm_list_lock);
	s_vm = __get_ssmem_vm(area);
	if (s_vm) {
		list_del(&s_vm->list);
		atomic_dec(&ssmem->mappers);
	}
	if (atomic_dec_return(&ssmem->mappers)) {
		if (SSMEM_MASTER(ssmem) == current->pid) {
			__assign_master(ssmem);
		}
	} else {
		printk(KERN_ALERT "PID %d is the last one out\n");
		__delete_ssmem(ssmem); 
	}
	mutex_unlock(&ssmem->ssmem_vm_list_lock);
}


static inline void
__vma_link_list(struct mm_struct *mm, struct vm_area_struct *vma,
		struct vm_area_struct *prev, struct rb_node *rb_parent)
{
	if (prev) {
		vma->vm_next = prev->vm_next;
		prev->vm_next = vma;
	} else {
		mm->mmap = vma;
		if (rb_parent)
			vma->vm_next = rb_entry(rb_parent,
						struct vm_area_struct, vm_rb);
		else
			vma->vm_next = NULL;
	}
}

static void
__vma_link(struct mm_struct *mm, struct vm_area_struct *vma,
	   struct vm_area_struct *prev, struct rb_node **rb_link,
	   struct rb_node *rb_parent)
{
	__vma_link_list(mm, vma, prev, rb_parent);
	__vma_link_rb(mm, vma, rb_link, rb_parent);
	__anon_vma_link(vma);
}

static void vma_link(struct mm_struct *mm, struct vm_area_struct *vma,
		     struct vm_area_struct *prev, struct rb_node **rb_link,
		     struct rb_node *rb_parent)
{
	anon_vma_lock(vma);
	__vma_link(mm, vma, prev, rb_link, rb_parent);
	anon_vma_unlock(vma);
}


static struct vm_area_struct *
find_vma_prepare(struct mm_struct *mm, unsigned long addr,
		 struct vm_area_struct **pprev, struct rb_node ***rb_link,
		 struct rb_node ** rb_parent)
{
	struct vm_area_struct * vma;
	struct rb_node ** __rb_link, * __rb_parent, * rb_prev;

	__rb_link = &mm->mm_rb.rb_node;
	rb_prev = __rb_parent = NULL;
	vma = NULL;

	while (*__rb_link) {
		struct vm_area_struct *vma_tmp;

		__rb_parent = *__rb_link;
		vma_tmp = rb_entry(__rb_parent, struct vm_area_struct, vm_rb);

		if (vma_tmp->vm_end > addr) {
			vma = vma_tmp;
			if (vma_tmp->vm_start <= addr)
				break;
			__rb_link = &__rb_parent->rb_left;
		} else {
			rb_prev = __rb_parent;
			__rb_link = &__rb_parent->rb_right;
		}
	}

	*pprev = NULL;
	if (rb_prev)
		*pprev = rb_entry(rb_prev, struct vm_area_struct, vm_rb);
	*rb_link = __rb_link;
	*rb_parent = __rb_parent;
	return vma;
}

static inline struct ssmem_struct * __create_ssmem(int id, size_t length)
{
	struct ssmem_struct *node;

	node = kmalloc(sizeof(struct ssmem_struct), GFP_KERNEL);
	if (!node) {
		printk(KERN_ALERT "ERROR in ssmem_attach: kmalloc error!\n");
		return NULL;
	}
	mutex_init(&node->ssmem_vm_list_lock);
	node->id = id;
	node->length = length;
	atomic_set(&node->mappers, 0);
	node->vm_list = kmalloc(sizeof(struct ssmem_vm), GFP_KERNEL);
	node->vm_list->vma = NULL;
	node->vm_list->owner = 0;
	node->master = current->pid;
	INIT_LIST_HEAD(&node->vm_list->list);

	return node;
}

static inline struct ssmem_vm *__create_ssmem_vm(struct vm_area_struct *vma)
{
	struct ssmem_vm *vm_node;
	vm_node = kmalloc(sizeof(struct ssmem_vm), GFP_KERNEL);
	if (!vm_node) {
		return NULL;
	}
	vm_node->vma = vma;
	vm_node->owner = current->pid;

	return vm_node;
}

SYSCALL_DEFINE3(ssmem_attach, int, id, int, flags, size_t, length) {
	size_t len = length;
	unsigned long addr;
	unsigned long vm_flags = 0;
	int valid_create = 0;
	struct vm_area_struct *vma, *prev;
	struct rb_node **rb_link, *rb_parent;
	struct ssmem_struct *node;
	struct ssmem_vm *vm_node;

	/* check if id is valid */
	if (id < 0 || id > SSMEM_MAX-1) {
		printk(KERN_ALERT "ERROR in ssmem_attach: Invalid id.\n");
		return -EINVAL;
	}

	if (atomic_read(&ssmem_count) >= SSMEM_MAX) {
		printk(KERN_ALERT "ERROR in ssmem_attach: Too many ssmem exist.\n");
		return -EINVAL;
	}

	if (current->mm->map_count > sysctl_max_map_count) {
		printk(KERN_ALERT "ERROR in ssmem_attach: Too many mappings!\n");
		return -ENOMEM;
	}

	/* If id doesn't exist */
	if (!SSMEM_TEST_ALLOC(id)) {
		if (length == 0) {
			printk(KERN_ALERT "ERROR in ssmem_attach: Invalid length!\n");
			return -EINVAL;
		}

		len = PAGE_ALIGN(len);
		if (len == 0 || len > TASK_SIZE) {
			printk(KERN_ALERT "ERROR in ssmem_attach: Invalid length!\n");
			return -ENOMEM;
		}

		node = __create_ssmem(id, length);
		if (!node) {
			return -ENOMEM;
		}

		valid_create = 1;
		mutex_lock(&ssmem_list_lock);
		list_add(&(node->list), ssmem_list_head);
		SSMEM_SET_ALLOC(id); /* set allocation bit to 1 */
		atomic_inc(&ssmem_count);
		mutex_unlock(&ssmem_list_lock);

	} else {
		valid_create = 0;
		node = __get_ssmem(id);
		if (!node) {
			/* this should not happen */
			printk(KERN_ALERT "SOMETHING WRONG!\n");
			return -EFAULT;
		}
		len = PAGE_ALIGN(node->length);
	}

	vm_flags |= (VM_SHARED|VM_READ);
	if (flags & SSMEM_FLAG_WRITE) {
		vm_flags |= VM_WRITE;
	}

	if (flags & SSMEM_FLAG_EXEC) {
		vm_flags |= VM_EXEC;
	}

	addr = get_unmapped_area(NULL, 0, len, 0, vm_flags);
	if (addr & ~PAGE_MASK) {
		printk(KERN_ALERT "ERROR in ssmem_attach: VMA not aligned!");
		return -EFAULT;
	}
	for ( ; ; ) {
		vma = find_vma_prepare(current->mm, addr, &prev, &rb_link, &rb_parent);
		if (!vma || vma->vm_start >= addr+len)
			break;
	}

	vma = kmem_cache_zalloc(vm_area_cachep, GFP_KERNEL);
	if (!vma) {
		printk(KERN_ALERT "ERROR in ssmem: kmem_cache_zalloc error!\n");
		return -ENOMEM;
	}

	vma->vm_mm = current->mm;
	vma->vm_start = addr;
	vma->vm_end = addr + len;
	vma->vm_flags = vm_flags;
	vma->vm_page_prot = PAGE_SHARED;
	vma->vm_ops = &ssmem_vm_ops;

	if (!valid_create) {
		vma->anon_vma = node->rmap;
		anon_vma_link(vma);
	}

	vma_link(current->mm, vma, prev, rb_link, rb_parent);
	current->mm->total_vm += len >> PAGE_SHIFT;
		
	vm_node = __create_ssmem_vm(vma);

	if (!vm_node) {
		return -ENOMEM;
	}
	mutex_lock(&node->ssmem_vm_list_lock);
	list_add(&vm_node->list, &node->vm_list->list);
	atomic_inc(&node->mappers);
	mutex_unlock(&node->ssmem_vm_list_lock);
	vma->vm_private_data = node;

	return addr;
}

/*
 * ssmem_detach
 *
 * 1. If caller is master, we need to re-assign master
 * 2. If it's the last one attached, we need to delete segment
 * 3. Remove vma from caller's mm
 *
 */
SYSCALL_DEFINE1(ssmem_detach, void *, addr) {
	struct vm_area_struct *vma;
	struct mm_struct *mm = current->mm;
	unsigned long start = (unsigned long) addr;

	if (start > TASK_SIZE)
		return -EFAULT;

	vma = find_vma(mm, start);
	if (!vma || start < vma->vm_start || !vma->vm_private_data) {
		printk(KERN_ALERT "No ssmem vma on %lu \n", start);
		return -EFAULT;
	}

	
	down_write(&mm->mmap_sem);
	__do_ssmem_munmap(vma);
	ssmem_close(vma);
	up_write(&mm->mmap_sem);
	return 0;

}
