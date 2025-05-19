#include "ksignal.h"

#include <defs.h>
#include <proc.h>
#include <trap.h>
/**
 * @brief init the signal struct inside a PCB.
 * 
 * @param p 
 * @return int 
 */
int siginit(struct proc *p) {
        // init default
    for (int i = SIGMIN; i <= SIGMAX; i++) {
        p->signal.sa[i].sa_sigaction = SIG_DFL;
        p->signal.sa[i].sa_mask = 0;
        p->signal.sa[i].sa_restorer = NULL;
    }
    
    // SIGCHLD->ignore
    p->signal.sa[SIGCHLD].sa_sigaction = SIG_IGN;
    p->signal.sigmask = 0;
    p->signal.sigpending = 0;
    memset(p->signal.siginfos, 0, sizeof(p->signal.siginfos));
    
    return 0;
}

int siginit_fork(struct proc *parent, struct proc *child) {
    return 0;
}

int siginit_exec(struct proc *p) {
    return 0;
}

int do_signal(void) {
    assert(!intr_get()); 
    
    struct proc *p = curr_proc();
    struct mm *mm = p->mm;
    sigset_t pending = p->signal.sigpending & ~p->signal.sigmask;
    if (pending == 0)
        return 0;
    // process signal
    int signo;
    for (signo = SIGMIN; signo <= SIGMAX; signo++) {
        if (pending & sigmask(signo))
            break;
    }
    // delete pending
    p->signal.sigpending &= ~sigmask(signo);
    
    sigaction_t *sa = &p->signal.sa[signo];
    
    if (sa->sa_sigaction == SIG_DFL) {
        switch (signo) {
            case SIGKILL:
                setkilled(p, -10 - signo);
                return 0;
                
            case SIGTERM:
            case SIGUSR0:
            case SIGUSR1:
            case SIGUSR2:
            case SIGSEGV:
            case SIGINT:
                // Term
                setkilled(p, -10 - signo);
                return 0;
                
            case SIGSTOP:
                p->state = SLEEPING;
                sched();
                return 0;
                
            case SIGCONT:
                if (p->state == SLEEPING) {
                p->state = RUNNABLE;
                add_task(p);
            }
                return 0;
                
            case SIGCHLD:
                return 0;
        }
        return 0;
    }
    
    if (sa->sa_sigaction == SIG_IGN) {
        if (signo == SIGKILL || signo == SIGSTOP) {
            setkilled(p, -10 - signo);
            return 0;
        }
        return 0;
    }
    
    if (signo == SIGKILL || signo == SIGSTOP) {
        setkilled(p, -10 - signo);
        return 0;
    }

    sigset_t old_mask = p->signal.sigmask;

    p->signal.sigmask |= (sa->sa_mask | sigmask(signo));

    struct trapframe *tf = p->trapframe;
    uint64 old_sp = tf->sp;    
    uint64 sp = old_sp & ~0xf;
    
    sp -= sizeof(struct ucontext);
    sp &= ~0xf;  
    uint64 ucontext_addr = sp;

    sp -= sizeof(siginfo_t);
    sp &= ~0xf;  
    uint64 siginfo_addr = sp;
    
    sp -= 16;  

    struct ucontext kcontext;
    kcontext.uc_sigmask = old_mask;
    kcontext.uc_mcontext.epc = tf->epc;
    
    // save register
    memmove(kcontext.uc_mcontext.regs, &tf->ra, 31 * sizeof(uint64));
    
    
     // copy ucontext and siginfo
    acquire(&mm->lock);
    if (copy_to_user(mm, ucontext_addr, (char*)&kcontext, sizeof(struct ucontext)) < 0 ||
        copy_to_user(mm, siginfo_addr, (char*)&p->signal.siginfos[signo], sizeof(siginfo_t)) < 0) {
        release(&mm->lock);
        p->signal.sigmask = old_mask; 
        return -1;
    }
    release(&mm->lock);
    
    // Modify trapframe 
    tf->sp = sp;  
    tf->epc = (uint64)sa->sa_sigaction; 
    tf->ra = (uint64)sa->sa_restorer;
    
    tf->a0 = signo;  // First argument: signal number
    tf->a1 = siginfo_addr;  // Second argument: pointer to siginfo struct
    tf->a2 = ucontext_addr; // Third argument: pointer to ucontext struct
    
    return 0;
}

// syscall handlers:
int sys_sigaction(int signo, const sigaction_t __user *act, sigaction_t __user *oldact) {
    struct proc *p = curr_proc();
    struct mm *mm = p->mm;

    if (signo < SIGMIN || signo > SIGMAX)
        return -1;

    if (oldact != NULL) {
        acquire(&mm->lock);
        if (copy_to_user(mm, (uint64)oldact, (char*)&p->signal.sa[signo], sizeof(sigaction_t)) < 0) {
            release(&mm->lock);
            return -1;
        }
        release(&mm->lock);
    }

    if (act == NULL)
        return 0;
        
    if (signo == SIGKILL || signo == SIGSTOP)
        return -1;
        
    // Get the new handler
    sigaction_t kact;
    acquire(&mm->lock);
    if (copy_from_user(mm, (char*)&kact, (uint64)act, sizeof(sigaction_t)) < 0) {
        release(&mm->lock);
        return -1;
    }
    release(&mm->lock);
    p->signal.sa[signo] = kact;
    
    return 0;
}

int sys_sigreturn() {
    struct proc *p = curr_proc();
    struct trapframe *tf = p->trapframe;
    struct ucontext kcontext;
    uint64 sp = tf->sp;
    
    // Skip the siginfo_t struct and the space reserved for arguments
    sp += 16;
    sp += sizeof(siginfo_t);
    sp = (sp + 0xf) & ~0xf;
    
    // Retrieve ucontext
    acquire(&p->mm->lock);
    int ret = copy_from_user(p->mm, (char*)&kcontext, sp, sizeof(struct ucontext));
    release(&p->mm->lock);
    if (ret < 0) {
        return -1;
    }
    p->signal.sigmask = kcontext.uc_sigmask;
    memmove(&tf->ra,kcontext.uc_mcontext.regs, 31 * sizeof(uint64));
    
    return 0;
}

int sys_sigprocmask(int how, const sigset_t __user *set, sigset_t __user *oldset) {
    struct proc *p = curr_proc();
    struct mm *mm = p->mm;
    sigset_t old_mask = p->signal.sigmask;
    if (oldset != NULL) {
        acquire(&mm->lock);
        int ret = copy_to_user(mm, (uint64)oldset, (char*)&old_mask, sizeof(sigset_t));
        release(&mm->lock);
        if (ret < 0) {
            return -1;
        }
    }

    if (set == NULL)
        return 0;

    sigset_t new_mask;
    acquire(&mm->lock);
    int ret = copy_from_user(mm, (char*)&new_mask, (uint64)set, sizeof(sigset_t));
    release(&mm->lock);
    if (ret < 0) {
        return -1;
    }

    switch (how) {
        case SIG_BLOCK:
            p->signal.sigmask |= new_mask;
            break;
        case SIG_UNBLOCK:
            p->signal.sigmask &= ~new_mask;
            break;
        case SIG_SETMASK:
            p->signal.sigmask = new_mask;
            break;
        default:
            return -1;
    }
    
    // SIGKILL and SIGSTOP cannot be blocked
    p->signal.sigmask &= ~(sigmask(SIGKILL) | sigmask(SIGSTOP));
    
    return 0;
}

int sys_sigpending(sigset_t __user *set) {
    if (set == NULL)
        return -1;
        
    struct proc *p = curr_proc();
    struct mm *mm = p->mm;
    acquire(&mm->lock);
    int ret = copy_to_user(mm, (uint64)set, (char*)&p->signal.sigpending, sizeof(sigset_t));
    release(&mm->lock);
    if (ret < 0) {
        return -1;
    }
        
    return 0;
}

int sys_sigkill(int pid, int signo, int code) {
    if (signo < SIGMIN || signo > SIGMAX)
        return -1;

    // Traverse the process pool to find the target process
    for (int i = 0; i < NPROC; i++) {
        struct proc *p = pool[i];
        acquire(&p->lock);
        if (p->pid == pid) {
            p->signal.sigpending |= sigmask(signo);
            p->signal.siginfos[signo].si_signo = signo;
            p->signal.siginfos[signo].si_code = code;
            p->signal.siginfos[signo].si_pid = curr_proc()->pid;

            if (p->state == SLEEPING) {
                p->state = RUNNABLE;
                add_task(p);
            }
            
            release(&p->lock);
            return 0;
        }
        release(&p->lock);
    }
    
    return -1;  // Target process not found
}
