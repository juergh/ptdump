#include <linux/device.h>
#include <linux/fs.h>
#include <linux/kallsyms.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/uaccess.h>

#include <asm/pgtable.h>

#include "ptdump.h"

static int ptdump_major;
static struct class *ptdump_class;
static struct mm_struct *__init_mm;

#define PT_LEVEL_CR3 0
#define PT_LEVEL_PGD 1
#define PT_LEVEL_PUD 2
#define PT_LEVEL_PMD 3
#define PT_LEVEL_PTE 4

static const char * const PT_LEVEL_NAME[] = {
	"cr3", "pgd", "pud", "pmd", "pte"
};

static void printk_prot(pgprot_t prot, int level)
{
        pgprotval_t pr = pgprot_val(prot);

	if (!pgprot_val(prot)) {
                printk(KERN_CONT "                              ");
		goto out;
	}
	
	printk(KERN_CONT "%s ", (pr & _PAGE_USER) ? "USR" : "   ");
	printk(KERN_CONT "%s ", (pr & _PAGE_RW) ? "RW" : "ro");
	printk(KERN_CONT "%s ", (pr & _PAGE_PWT) ? "PWT" : "   ");
	printk(KERN_CONT "%s ", (pr & _PAGE_PCD) ? "PCD" : "   ");
	printk(KERN_CONT "%s ", (pr & _PAGE_PSE && level <= 3) ?
	       "PSE" : "   ");
	printk(KERN_CONT "%s ", ((pr & _PAGE_PAT_LARGE &&
				  (level == 2 || level == 3)) ||
				 (pr & _PAGE_PAT && level == 4)) ?
	       "PAT" : "   ");
	printk(KERN_CONT "%s ", (pr & _PAGE_GLOBAL) ? "GLB" : "   ");
	printk(KERN_CONT "%s ", (pr & _PAGE_NX) ? "NX" : "x ");

out:
        printk(KERN_CONT "%s\n", PT_LEVEL_NAME[level]);
}

static const char * const PG_LEVEL_NAME[] = {
	"none", "4K", "2M", "1G"
};

static void printk_pagetable(unsigned long addr)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd = NULL;
	pte_t *pte = NULL;
	unsigned int level = PG_LEVEL_4K;
	unsigned long phys_addr, offset;
	struct page *page = virt_to_page(addr);

	printk("  ------------------------------\n");
	printk("  virtual addr: %016lx\n", addr);
	printk("  page: %016lx\n", (unsigned long)page);

        if (addr > PAGE_OFFSET) {
                /* kernel virtual address */
                pgd = pgd_offset(__init_mm, addr);
        } else {
                /* user (process) virtual address */
                pgd = pgd_offset(current->mm, addr);
        }
	printk("  pgd: %016lx (%016lx) ", (unsigned long)pgd, pgd_val(*pgd));
	printk_prot(__pgprot(pgd_flags(*pgd)), PT_LEVEL_PGD);
	
	pud = pud_offset(pgd, addr);
	printk("  pud: %016lx (%016lx) ", (unsigned long)pud, pud_val(*pud));
	printk_prot(__pgprot(pud_flags(*pud)), PT_LEVEL_PUD);
        if (pud_large(*pud) || !pud_present(*pud)) {
		level = PG_LEVEL_1G;
		phys_addr = (unsigned long)pud_pfn(*pud) << PAGE_SHIFT;
                offset = addr & ~PUD_PAGE_MASK;
		goto out;
	}

	pmd = pmd_offset(pud, addr);
	printk("  pmd: %016lx (%016lx) ", (unsigned long)pmd, pmd_val(*pmd));
	printk_prot(__pgprot(pmd_flags(*pmd)), PT_LEVEL_PMD);
        if (pmd_large(*pmd) || !pmd_present(*pmd)) {
		level = PG_LEVEL_2M;
                phys_addr = (unsigned long)pmd_pfn(*pmd) << PAGE_SHIFT;
                offset = addr & ~PMD_PAGE_MASK;
                goto out;
	}

	pte =  pte_offset_kernel(pmd, addr);
	printk("  pte: %016lx (%016lx) ", (unsigned long)pte, pte_val(*pte));
	printk_prot(__pgprot(pte_flags(*pte)), PT_LEVEL_PTE);
	phys_addr = (unsigned long)pte_pfn(*pte) << PAGE_SHIFT;
	offset = addr & ~PAGE_MASK;

out:
	printk("  pud_page: %016lx\n", (unsigned long)pud_page(*pud));
	if (pmd)
		printk("  pmd_page: %016lx\n", (unsigned long)pmd_page(*pmd));
	if (pte)
		printk("  pte_page: %016lx\n", (unsigned long)pte_page(*pte));
	printk("  physical addr: %016lx\n",
	       (unsigned long)(phys_addr | offset));
	printk("  page addr: %016lx\n", phys_addr);
	printk("  page size: %s\n", PG_LEVEL_NAME[level]);
	printk("  ------------------------------\n");
}

/*
 * Copy of lookup_address_in_pgd() from arch/x86/mm/pageattr.c
 */
static pte_t *__lookup_addr_in_pgd(pgd_t *pgd, unsigned long addr,
                                   unsigned int *level)
{
        pud_t *pud;
        pmd_t *pmd;

        *level = PG_LEVEL_NONE;

        if (pgd_none(*pgd))
                return NULL;

        pud = pud_offset(pgd, addr);
        if (pud_none(*pud))
                return NULL;

        *level = PG_LEVEL_1G;
        if (pud_large(*pud) || !pud_present(*pud))
                return (pte_t *)pud;

        pmd = pmd_offset(pud, addr);
        if (pmd_none(*pmd))
                return NULL;

        *level = PG_LEVEL_2M;
        if (pmd_large(*pmd) || !pmd_present(*pmd))
                return (pte_t *)pmd;

        *level = PG_LEVEL_4K;

        return pte_offset_kernel(pmd, addr);
}

/*
 * Look up a virtual (process or kernel) address and return its PTE
 *
 * Based on lookup_address() from arch/x86/mm/pageattr.c
 */
static pte_t *__lookup_addr(unsigned long addr, unsigned int *level)
{
        pgd_t *pgd;

        if (addr > PAGE_OFFSET) {
                /* kernel virtual address */
                pgd = pgd_offset(__init_mm, addr);
        } else {
                /* user (process) virtual address */
                pgd = pgd_offset(current->mm, addr);
        }

	return __lookup_addr_in_pgd(pgd, addr, level);
}

/*
 * Convert a virtual (process or kernel) address to a physical address
 *
 * Based on slow_virt_to_phys() from arch/x86/mm/pageattr.c
 */
static unsigned long any_virt_to_phys(unsigned long addr)
{
        unsigned long phys_addr;
        unsigned long offset;
        unsigned int level;
        pte_t *pte;

        pte = __lookup_addr(addr, &level);
        if (!pte)
                return 0;

        /*
         * pXX_pfn() returns unsigned long, which must be cast to phys_addr_t
         * before being left-shifted PAGE_SHIFT bits -- this trick is to
         * make 32-PAE kernel work correctly.
         */
        switch (level) {
        case PG_LEVEL_1G:
                phys_addr = (unsigned long)pud_pfn(*(pud_t *)pte) << PAGE_SHIFT;
                offset = addr & ~PUD_PAGE_MASK;
                break;
        case PG_LEVEL_2M:
                phys_addr = (unsigned long)pmd_pfn(*(pmd_t *)pte) << PAGE_SHIFT;
                offset = addr & ~PMD_PAGE_MASK;
                break;
        default:
                phys_addr = (unsigned long)pte_pfn(*pte) << PAGE_SHIFT;
                offset = addr & ~PAGE_MASK;
        }

        return (phys_addr | offset);
}

/*
 * Convert a physical address to a kernel virtual address
 */
static unsigned long phys_to_kern(unsigned long phys_addr)
{
        return (unsigned long)phys_to_virt(phys_addr);
}

static int ptdump_open(struct inode *i, struct file *f)
{
        return 0;
}

static int ptdump_release(struct inode *i, struct file *f)
{
        return 0;
}

static long ptdump_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct ptdump_req *req = (struct ptdump_req *)arg;
	unsigned long phys_addr, kern_addr;
	unsigned long buf;

	printk("--------------------------------------------------------------"
	       "-----------------\n");
        printk("pid: %d, comm: %s\n", current->pid, current->comm);
	printk("user addr: %016lx, order: %d\n", req->addr,
	       req->order);
	printk("user data: %s\n", (char *)req->addr);
	printk_pagetable(req->addr);
	
	switch (cmd) {

	case PTDUMP_DUMP:
		printk("ioctl cmd: PTDUMP_DUMP\n");

		phys_addr = any_virt_to_phys(req->addr);
		kern_addr = phys_to_kern(phys_addr);
		printk("kernel addr: %016lx\n", kern_addr);
		printk("kernel data: %s\n", (char *)kern_addr);
		printk_pagetable(kern_addr);

		break;

	case PTDUMP_WRITE:
		printk("ioctl cmd: PTDUMP_WRITE\n");

		buf = __get_free_pages(GFP_KERNEL, req->order);
		if (!buf) {
			printk("failed to __get_free_pages()\n");
			return -ENOMEM;
		}
		printk("buf addr: %016lx\n", buf);
		if (copy_from_user((char *)buf, (char *)req->addr,
				   PAGE_SIZE * (1 << req->order))) {
			printk("failed to copy_from_user()\n");
			return -EFAULT;
		}
		printk("buf data: %s\n", (char *)buf);
		printk_pagetable(buf);
		free_pages(buf, req->order);

		break;

	default:
		printk("ioctl cmd: UNKNOWN\n");
		break;
	}

	return 0;
}

static struct file_operations ptdump_fops = {
        .open = ptdump_open,
        .release = ptdump_release,
        .unlocked_ioctl = ptdump_ioctl,
};

static int __init ptdump_init(void)
{
	int ret;

        printk("=============================================================="
	       "=================\n");

        __init_mm = (struct mm_struct *)kallsyms_lookup_name("init_mm");
        if (!__init_mm) {
                printk("failed to lookup 'init_mm'\n");
                ret = -ENXIO;
                goto out;
        }
        printk("init_mm: %p\n", __init_mm);

        ptdump_major = register_chrdev(0, "ptdump", &ptdump_fops);
        if (ptdump_major < 0) {
                printk("failed to register device\n");
                ret = ptdump_major;
                goto out;
        }

        ptdump_class = class_create(THIS_MODULE, "ptdump");
        if (IS_ERR(ptdump_class)) {
                printk("failed to create class\n");
                ret = PTR_ERR(ptdump_class);
                goto out_unregister;
        }

        device_create(ptdump_class, NULL, MKDEV(ptdump_major, 0), NULL,
		      "ptdump");

        printk("ptdump module loaded\n");
        return 0;

out_unregister:
        unregister_chrdev(ptdump_major, "ptdump");
out:
        return ret;

}

static void __exit ptdump_exit(void)
{
	device_destroy(ptdump_class, MKDEV(ptdump_major, 0));
        class_destroy(ptdump_class);
        unregister_chrdev(ptdump_major, "ptdump");

        printk("ptdump module unloaded\n");
        printk("=============================================================="
	       "=================\n");
}

module_init(ptdump_init);
module_exit(ptdump_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Juerg Haefliger <juerg.haefliger@hpe.com>");
