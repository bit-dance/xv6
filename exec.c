#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"
#include "defs.h"
#include "x86.h"
#include "elf.h"
int
exec(char *path, char **argv)
{
    char *s, *last;
    int i, off;
    uint argc, sz, stack_pos, sp, ustack[3 + MAXARG + 1];
    struct elfhdr elf;
    struct inode *ip;
    struct proghdr ph;
    pde_t *pgdir, *oldpgdir;
    struct proc *curproc = myproc();

    begin_op();

    if ((ip = namei(path)) == 0)
    {
        end_op();
        cprintf("exec: fail\n");
        return -1;
    }
    ilock(ip);
    pgdir = 0;

    // Check ELF header
    //打开可执行文件
    if (readi(ip, (char *) &elf, 0, sizeof(elf)) != sizeof(elf))
        goto bad;
    if (elf.magic != ELF_MAGIC)
        goto bad;
    //初始化内核内存
    if ((pgdir = setupkvm()) == 0)
        goto bad;

    // Load program into memory.
    sz = 0;
    for (i = 0, off = elf.phoff; i < elf.phnum; i++, off += sizeof(ph))
    {
        if (readi(ip, (char *) &ph, off, sizeof(ph)) != sizeof(ph))
            goto bad;
        if (ph.type != ELF_PROG_LOAD)
            continue;
        if (ph.memsz < ph.filesz)
            goto bad;
        if (ph.vaddr + ph.memsz < ph.vaddr)
            goto bad;
        //这里的sz就相当于进程大小
        //sz是用来跟踪虚拟地址空间的末尾
        //我们按顺序填充地址空间
        if ((sz = allocuvm(pgdir, sz, ph.vaddr + ph.memsz)) == 0)
            goto bad;
        if (ph.vaddr % PGSIZE != 0)
            goto bad;
        //将程序的每个部分装入内存中,为每个部分创建内存页并映射到地址空间
        if (loaduvm(pgdir, (char *) ph.vaddr, ip, ph.off, ph.filesz) < 0)
            goto bad;
    }
    iunlockput(ip);
    end_op();
    ip = 0;

    // Allocate two pages at the next page boundary.
    // Make the first inaccessible.  Use the second as the user stack.
    //原来用户栈分配,第一个不可访问,第二个是用户栈
    sz = PGROUNDUP(sz);
    //初始化页表项和物理内存,提供虚拟地址映射
    if ((stack_pos = allocuvm(pgdir, KERNBASE - 2 * PGSIZE, KERNBASE - PGSIZE)) == 0)
        goto bad;
    //clearpteu(pgdir, (char *) (stack_pos - 2 * PGSIZE));
    sp = stack_pos;
    stack_pos -= PGSIZE;

    // Push argument strings, prepare rest of stack in ustack.
    for (argc = 0; argv[argc]; argc++)
    {
        if (argc >= MAXARG)
            goto bad;
        sp = (sp - (strlen(argv[argc]) + 1)) & ~3;
        if (copyout(pgdir, sp, argv[argc], strlen(argv[argc]) + 1) < 0)
            goto bad;
        ustack[3 + argc] = sp;
    }
    ustack[3 + argc] = 0;

    ustack[0] = 0xffffffff;  // fake return PC
    ustack[1] = argc;
    ustack[2] = sp - (argc + 1) * 4;  // argv pointer

    sp -= (3 + argc + 1) * 4;
    if (copyout(pgdir, sp, ustack, (3 + argc + 1) * 4) < 0)
        goto bad;

    // Save program name for debugging.
    for (last = s = path; *s; s++)
        if (*s == '/')
            last = s + 1;
    safestrcpy(curproc->name, last, sizeof(curproc->name));

    // Commit to the user image.
    oldpgdir = curproc->pgdir;
    curproc->pgdir = pgdir;
    curproc->sz = sz;
    curproc->tf->eip = elf.entry;  // main
    curproc->tf->esp = sp;

    curproc->stack_pos = stack_pos;

    switchuvm(curproc);
    freevm(oldpgdir);
    return 0;

    bad:
    if (pgdir)
        freevm(pgdir);
    if (ip)
    {
        iunlockput(ip);
        end_op();
    }
    return -1;
}