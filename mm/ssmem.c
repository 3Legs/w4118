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
#include <asm/uaccess.h>
#include <asm/cacheflush.h>
#include <asm/tlb.h>
#include <asm/mmu_context.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>

/* macro define */
#define SSMEM_MAX 1024
#define SSMEM_FLAG_CREATE   0x1
#define SSMEM_FLAG_WRITE    0x2
#define SSMEM_FLAG_EXEC     0x4

/* global variable */

static atomic_t ssmem_count = ATOMIC_INIT(0);

/* structures define */

struct ssmem_vm {
   struct vm_area_struct *vma;
   struct list_head list;
};

struct ssmem_struct {
   int id; /*ssmem ID */
   int length; /* length of the ssmem */
   int mappers; /* number of mappers */
   struct ssmem_vm *vm_list; /* list of mappers */
   struct list_head list;
};

/* function declare */

static int ssmem_fault(struct vm_area_struct *vma, struct vm_fault *vmf);

/* objects initialize */

struct ssmem_struct ssmem_head = {
   .id = -1,
   .list = LIST_HEAD_INIT(ssmem_head.list),
};

static struct vm_operations_struct ssmem_vm_ops = {
   .fault      = ssmem_fault,
};

struct list_head *ssmem_list_head = &(ssmem_head.list);

/* function definations */

static int ssmem_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{

   return VM_FAULT_NOPAGE;
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
   unsigned long len = length;
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

      current->mm->free_area_cache = begin;
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
      }

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
      node->id = id;
      node->length = length;
      node->mappers = 1;
      node->vm_list = kmalloc(sizeof(struct ssmem_vm), GFP_KERNEL);
      node->vm_list->vma = vma;
      list_add(&(node->list), ssmem_list_head);

      return addr;
   } else {

   }
}

SYSCALL_DEFINE1(ssmem_detach, void *, addr) {
	return 0;
}
