#include <linux/module.h>  /* Needed by all kernel modules */
#include <linux/kernel.h>  /* Needed for loglevels (KERN_WARNING, KERN_EMERG, KERN_INFO, etc.) */
#include <linux/init.h>    /* Needed for __init and __exit macros. */

#include <linux/unistd.h> /* sys_call_table __NR_* system call function indices */

#include <asm/paravirt.h> /* write_cr0 */

#include "hooks.h"


/*
 * TODO Find a way to resolve this address dynamically.
 */
unsigned long *syscall_table = (unsigned long *)0xffffffff81801400;
asmlinkage int (*original_write)(unsigned int, const char __user *, size_t);
asmlinkage int new_write (unsigned int x, const char __user *y, size_t size) {
  printk(KERN_EMERG "[+] write() hooked.");

  return original_write(x, y, size);
}

static int __init onload(void) {
  printk(KERN_WARNING "Hello world!\n");

  write_cr0 (read_cr0 () & (~ 0x10000));
  original_write = (void *)syscall_table[__NR_write];
  syscall_table[__NR_write] = &new_write;
  write_cr0 (read_cr0 () | 0x10000);

  /*
   * A non 0 return means init_module failed; module can't be loaded.
   */
  return 0;
}

static void __exit onunload(void) {
  write_cr0 (read_cr0 () & (~ 0x10000));
  syscall_table[__NR_write] = original_write;
  write_cr0 (read_cr0 () | 0x10000);

  printk(KERN_INFO "Goodbye world!\n");
}

module_init(onload);
module_exit(onunload);
