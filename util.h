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
 * util.h contains the definition of all the required utility functions
 * to perform the replay attack. The functions include:
 * 1) tracking page tables of a requested virtual address
 * 2) perform the nuke which completly flushes all
 *  page table entries and data from the caches for a specified address.
 * 3) create kernel level mapping to process level memory
 * 4) perform a flush+reload side channel
 * 5) other utility functions used for the attack
 */

#ifndef UTIL_H
#define UTIL_H

#include <asm/cacheflush.h>
#include <asm/io.h>
#include <asm/mmu_context.h>
#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>
#include <asm/uaccess.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/hrtimer.h>
#include <linux/hugetlb.h>
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
#include <linux/string.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/syscalls.h>
#include <linux/timer.h>

#define DEBUG 1

/*
 * attack_info is a utility struct that maintains all the necessary
 * information to perform the attack. Not all fields are used for
 * the current release.
 */
struct attack_info {
  uint64_t nuke_addr;                  // VA to be nuked of the victim process
  void *nuke_kaddr;                    // Kernel mapping of the nuke_addr
  struct task_struct *nuke_tsk;        // task_struct of the victim
  pid_t nuke_pid;                      // pid of the victim
  struct mm_struct *nuke_mm;           // mm_struct of the victim
  struct vm_area_struct *monitor_vma;  // vma of the monitor
  uint64_t monitor_addr[64];           // VA to be monitored currently
  uint64_t monitor_addr_start[64];     // VA to be monitored
  void *monitor_kaddr[64];             // Kernel mapping of the monitor_addr
  struct page *monitor_page[64];       // the page of the monitor_addr
  pgd_t *nuke_pgd;                     // page tables of the nuke_addr
  pud_t *nuke_pud;
  pmd_t *nuke_pmd;
  pte_t *nuke_ptep;
  void *pgd_maddr;  // kernel mappings for page tables, vma, page
  struct vm_area_struct *pgd_vma;
  struct page *pgd_page;
  void *pud_maddr;
  struct vm_area_struct *pud_vma;
  struct page *pud_page;
  void *pmd_maddr;
  struct vm_area_struct *pmd_vma;
  struct page *pmd_page;
  void *ptep_maddr;
  struct vm_area_struct *ptep_vma;
  struct page *ptep_page;
  spinlock_t **ptlp;  // splinlock used for locking page table entries
  uint32_t error;     // used to track errors at different stages
  uint32_t monitors;
};

/******************************************************/
/*
 * functions implemented in the memory.c of the kernel
 */

/*
 * set_attack configures the page fault handler to track
 * the specified pte for page faults and enables the attack
 * @victim_pte is pte entry that the attack will be performed on
 * @value enables/disables the attack (0 -> False)
 */
void set_attack(pte_t *victim_pte, int value);

/*
 * set_attack_pte configures the page fault handler to track
 * the specified pte for page faults
 * @victim_pte is pte entry that the attack will be performed on
 * @value is ignored in poc_v0
 */
void set_attack_pte(pte_t *victim_pte, int value);

/*
 * set_attack_value configures the page fault handler to track
 * the specified pte for page faults
 * @victim_pte is ignored in poc_v0
 * @value enables/disables the attack (0 -> False)
 */
void set_attack_value(pte_t *victim_pte, int value);

/*
 * check_attack performs physical address comparison of
 * the current page faulting pte and pte under attack
 * the final result is based on the pte_same
 * @fault_pte is the currently faulting pte
 */
int check_attack(pte_t *fault_pte);

/*
 * set_print_msg_attack enables or disabled message printing
 * WARNING: When enabled every page fault will dump information
 * use only for debugging purposes.
 * @value enables/disables printing (0 -> False)
 */
void set_print_msg_attack(int value);

/*
 * get_pf_status reutrns the status of the attack in case we want to bypass
 * an other attacking thread. Not used for poc_v0
 */
int get_pf_status(void);

/*
 * set_pf_status sets the status of the attack in we want to bypass
 * an other attacking thread. Not used for poc_v0
 */
int set_pf_status(int val);

/******************************************************/

/******************************************************/
/*
 * functions implemented in the util.c
 */

/*
 * asm_clflush implementation of clflush in assembly. It will evict from the
 * caches the cacheline that holds the specified address.
 * @addr is the VA to be flushed
 */
void asm_clflush(uint64_t addr);

/*
 * asm_cctime meassure access time of a specified address
 * through fenced assembly.
 * @addr is the VA to be measured
 */
uint32_t asm_cctime(uint64_t addr);

/*
 * setup_nuke_structs configures the attack info struct with the information
 * of the address to be nuked. In addition, it creates a kernel mapping to
 * the address of the process.
 * @info ptr to the attack info struct
 * @addr is the VA to be nuked
 */
void setup_nuke_structs(struct attack_info *info, uint64_t address);

/*
 * setup_monitor_structs configures the attack info struct with the information
 * of the address to be monitored. In addition, it creates a kernel mapping to
 * the address of the process and stores all the page table entries.
 * @info ptr to the attack info struct
 * @addr is the VA to be monitored through a side channel
 * @index selects the monitoring addresses location
 */
void setup_monitor_structs(struct attack_info *info, uint64_t address, uint32_t index);

/*
 * pf_prep prepares the page fault by orchestrating the page fault
 * handler and the kernel module. In addition, it flushes the monitor
 * address from the caches.
 * @info ptr to the attack info struct
 * @addr is the VA to page fault (same as nuked)
 * @tot_monitor total monitoring addresses
 */
void pf_prep(struct attack_info *info, uint64_t address, uint32_t tot_monitor);
void pf_prep_no_monitor_flush(struct attack_info *info, uint64_t address);
void pf_prep_lockless(struct attack_info *info, uint64_t address);
void pf_redo(struct attack_info *info, uint64_t address);
/*
 * map_general_page creates a kernel page mapping of a user level
 * page.
 * @tsk is the task_struct of the process
 * @mm is the mm_struct of the process
 * @addr is the VA we want to create a mapping for
 * @write defines if the kernel will write to the page
 * @maddr is the kernel mapping to be created and points to
 * the beggining of the page frame.
 */
int map_general_page(struct task_struct *tsk, struct mm_struct *mm, uint64_t addr,
                     int write, void **maddr);
/*
 * map_general_address creates a kernel page mapping of a user level
 * address.
 * @tsk is the task_struct of the process
 * @mm is the mm_struct of the process
 * @addr is the VA we want to create a mapping for
 * @write defines if the kernel will write to the page
 * @maddr is the kernel mapping to be created and points to
 * the same point as the @addr (same offset with the page)
 */
int map_general_address(struct task_struct *tsk, struct mm_struct *mm, uint64_t addr,
                        int write, void **maddr);
/*
 * user_memory_op performs a read or a write to user process address
 * @addr is the address that the operation will be performed on
 * @buf buffer to read/copy the result
 * @len is the length of the operation
 * @write defines a read or a write (0 -> read)
 * @page is kernel mapping of the page to perform the write on
 * @maddr is the kernel mapping of the address to perform the write on
 * @vma is the vma_area_struct of that the VA belongs to
 */
void user_memory_op(uint64_t addr, void *buf, int len, int write, struct page *page,
                    void *maddr, struct vm_area_struct *vma);

/*
 * map_pgt_4level finds and stores the address of the page tables
 * given a 4KB pages without grabing a lock. The function uses the nuke address
 * stored in the attack_info to perform the search.
 * @info is the attack_info that the address will stored
 */
int map_pgt_4level(struct attack_info *info);

/*
 * map_pgt_4level_lock finds and stores the address of the page tables
 * given a 4KB pages with a lock. The function uses the nuke address
 * stored in the attack_info to perform the search.
 * @info is the attack_info that the address will stored
 * @ptlp is the splinlock to be used to lock the page tables with
 */
int map_pgt_4level_lock(struct attack_info *info, spinlock_t **ptlp);

uint64_t get_physical(struct mm_struct *mm, uint64_t address, pte_t **ptepp,
                      spinlock_t **ptlp, int present);

/*
 * nuke_lock finds the address of the page tables
 * given a 4KB pages with a lock. The data and all the page table entries
 * are then flushed from the cache. The next time this memory access is
 * performed from the victim process five memory access will be performed
 * to fetch the data. If @present is non-zero the present bit of the PTE
 * is cleared.
 * @mm is the mm_struct of the process
 * @address is the addres we are searching
 * @ptepp a pointer to the pte, this will be set at the end of the search
 * with the pte we nuked
 * @ptlp is the splinlock to be used to lock the page tables with
 * @present if non-zero the Present bit of the pte is cleared
 */
int nuke_lock(struct mm_struct *mm, uint64_t address, pte_t **ptepp, spinlock_t **ptlp,
              int present);

/*
 * nuke_lockless finds the address of the page tables
 * given a 4KB pages without grabbing a lock. The page table
 * entries are then flushed from the cache. The next time this memory access is
 * performed from the victim process at least four memory access will be
 * performed to fetch the data.
 * @mm is the mm_struct of the process
 * @address is the addres we are searching
 * @ptepp a pointer to the pte, this will be set at the end of the search
 * with the pte we nuked
 * @ptlp is the splinlock to be used to lock the page tables with
 * @present if non-zero the Present bit of the pte is cleared
 */
int nuke_lockless(struct mm_struct *mm, uint64_t address, pte_t **ptepp, int present);

int nuke_lockless_partial(struct mm_struct *mm, uint64_t address, pte_t **ptepp,
                          int present);
/*
 * check_side_channel_single performs the reload step of the flush+reload
 * side channel.
 * @address is the address we are measuring its access time
 * @index is used for output purposes only
 */
uint64_t check_side_channel_single(uint64_t address, uint32_t index);

/*
 * print_info performs outputs someof the attack_info struct information
 * @info is the attack info struct
 */
void print_info(struct attack_info *info);

/******************************************************/
#endif
