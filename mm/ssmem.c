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

/* macro define */
#define SSMEM_TEST_ALLOC(id) test_bit(id, ssmem_alloc)
#define SSMEM_SET_ALLOC(id) set_bit(id, ssmem_alloc)
#define SSMEM_UNSET_ALLOC(id) unset_bit(id, ssmem_alloc)

#define SSMEM_MASTER(ssmem) (ssmem->master)

#define SSMEM_MAX 1024
#define SSMEM_FLAG_CREATE   0x1
#define SSMEM_FLAG_WRITE    0x2
#define SSMEM_FLAG_EXEC     0x4

/* global variable */

static atomic_t ssmem_count = ATOMIC_INIT(0);
DEFINE_MUTEX(ssmem_lock);
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
	unsigned int mappers; /* number of mappers */
	pid_t master;
	struct ssmem_vm *vm_list; /* list of mappers */
	struct list_head list;
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

static int ssmem_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{

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
	/* there's only one mapper, which has to be master */
        /* we do nothing */
	if (ssmem->mappers <= 1)
		return;
	/* need to lock ssmem list */
	mutex_lock(&ssmem_list_lock);

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
			break;
		}
	}
	mutex_unlock(&ssmem_list_lock);
}


static void __unmap_region(struct mm_struct *mm, 
		struct vm_area_struct *vma)
{
	struct mmu_gather *tlb;
	unsigned long nr_accounted = 0;

	lru_add_drain();
	tlb = tlb_gather_mmu(mm, 0);
	update_hiwater_rss(mm);
	umap_vmas(&tlb, vma, vma->vm_start, vma->vm_end, &nr_accounted, NULL);
	vm_unacct_memory(nr_accounted);
	free_pgtables(tlb, vma, vma->vm_start, vma->vm_end);
	tlb_finish_mmu(tlb, vma->vm_start, vma->vm_end);
}

/*
 * __do_close: actual close ssmem routine
 * 
 * 1. Unmap the pages.
 * 2. Remove vma from mm
 */
static void  __do_munmap(struct vm_area_struct *area)
{
	struct mm_struct *mm = current->mm;
	unsigned long addr = area->vm_start;

	if (mm->locked_vm) {
		mm->locked_vm -= vma_pages(area);
		munlock_vma_pages_all(area);
	}
	
	mm->unmap_area(mm, addr);
	mm->mmap_cache = NULL;

	/* get rid of page table information;*/ 
	__unmap_region(mm, area);
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

	mutex_lock(&ssmem_lock); /* need to protect ssmem_struct */
	if (SSMEM_MASTER(ssmem) == current->pid) {
		__assign_master(ssmem);
	}

	if (!(--ssmem->mappers)) {
		/* the last(only) mappers, need to do actual close */
		__do_munmap(area);
	}
	mutex_unlock(&ssmem_lock);
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

SYSCALL_DEFINE3(ssmem_attach, int, id, int, flags, size_t, length) {
	size_t len = length;
	unsigned long begin = TASK_UNMAPPED_BASE;
	unsigned long addr, start_addr;
	unsigned long vm_flags = 0;
	struct vm_area_struct *vma, *prev;
	struct rb_node **rb_link, *rb_parent;
	struct ssmem_struct *node;

	if (id < 0 || id > SSMEM_MAX-1) {
		printk(KERN_ALERT "ERROR in ssmem_attach: Invalid id.\n");
		return -EINVAL;
	}

	/* check if id exist */
	if (SSMEM_TEST_ALLOC(id))
		goto _ATTACH_ROUTINE;

	if (flags & SSMEM_FLAG_CREATE) {
		if (atomic_read(&ssmem_count) >= SSMEM_MAX) {
			printk(KERN_ALERT "ERROR in ssmem_attach: Too many ssmem exist.\n");
			return -EINVAL;
		}

		if (length == 0) {
			printk(KERN_ALERT "ERROR in ssmem_attach: Invalid length!\n");
			return -EINVAL;
		}

		len = PAGE_ALIGN(len);
		if (len == 0 || len > TASK_SIZE) {
			printk(KERN_ALERT "ERROR in ssmem_attach: Invalid length!\n");
			return -ENOMEM;
		}

		if (current->mm->map_count > sysctl_max_map_count) {
			printk(KERN_ALERT "ERROR in ssmem_attach: Too many mappings!\n");
			return -ENOMEM;
		}

		vm_flags |= (VM_SHARED|VM_READ);

		if (flags & SSMEM_FLAG_WRITE) {
			vm_flags |= VM_WRITE;
		}

		if (flags & SSMEM_FLAG_EXEC) {
			vm_flags |= VM_EXEC;
		}

		/* current->mm->free_area_cache = begin;
		addr = start_addr = begin;

		for (vma = find_vma(current->mm, addr); ;vma = vma->vm_next) {
			if (addr + len > TASK_SIZE) {
				printk(KERN_ALERT "ERROR in ssmem_attach: Not enough memory!\n");
				return -ENOMEM;
			}
			if (!vma || addr + len <= vma->vm_start) {
				current->mm->free_area_cache = addr + len;
				break;
			}
			addr = vma->vm_end;
			} */

		addr = get_unmapped_area(NULL, 0, len, 0, vm_flags);

		if (addr & ~PAGE_MASK) {
			printk(KERN_ALERT "ERROR in ssmem_attach: VMA not aligned!");
			return -EFAULT;
		}

		for ( ; ; ) {
			vma = find_vma_prepare(current->mm, addr, &prev, &rb_link, &rb_parent);
			if (!vma || vma->vm_start >= addr+len)
				break;
			/* ssmem_unmap() */
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
		vma->vm_ops = &ssmem_vm_ops;

		vma_link(current->mm, vma, prev, rb_link, rb_parent);
		current->mm->total_vm += len >> PAGE_SHIFT;

		//make_pages_present(addr, addr+len);
		node = kmalloc(sizeof(struct ssmem_struct), GFP_KERNEL);
		if (!node) {
			printk(KERN_ALERT "ERROR in ssmem_attach: kmalloc error!\n");
			return -ENOMEM;
		}

		SSMEM_SET_ALLOC(id); /* set allocation bit to 1 */

		node->id = id;
		node->length = length;
		node->mappers = 1;
		node->vm_list = kmalloc(sizeof(struct ssmem_vm), GFP_KERNEL);
		node->vm_list->vma = vma;
		node->vm_list->owner = current->pid;

		node->master = current->pid;

		list_add(&(node->list), ssmem_list_head); /* add node to ssmem list */

		vma->vm_private_data = node; /* add node(ssmem_struct) to corresponding vma */

		return addr;
	}

_ATTACH_ROUTINE:
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
	struct vm_area_struct *vma, *prev;
	struct mm_struct *mm = current->mm;
	unsigned long end;
	unsigned long start = (unsigned long) addr;

	if ((start & ~PAGE_MASK) || start > TASK_SIZE)
		return -EFAULT;

	vma = find_vma_prev(mm, start, &prev);
	if (!vma || !vma->vm_private_data) 
/* no vma on this address or vma is not a ssmem segment*/
		return -EFAULT;

	down_write(&mm->mmap_sem);
	ssmem_close(vma);
	up_write(&mm->mmap_sem);

	return 0;
}
