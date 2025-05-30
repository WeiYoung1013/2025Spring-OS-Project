#include "ksignal.h"

#include <defs.h>
#include <proc.h>
#include <trap.h>
#include <string.h>
#include <vm.h>
#include <timer.h>

// 定义alarm状态结构体
struct {
    struct spinlock lock;
    uint64 alarm_time;  // 以CPU周期为单位的alarm时间
} alarm_state;

/**
 * @brief init the signal struct inside a PCB.
 * 
 * @param p 
 * @return int 
 */
int siginit(struct proc *p) {
    // 初始化信号处理方式为默认
    for (int i = SIGMIN; i <= SIGMAX; i++) {
        p->signal.sa[i].sa_sigaction = SIG_DFL;
        p->signal.sa[i].sa_mask = 0;
        p->signal.sa[i].sa_restorer = NULL;
    }
    
    // 设置SIGCHLD的默认处理方式为忽略
    // p->signal.sa[SIGCHLD].sa_sigaction = SIG_IGN;
    
    // 清空信号掩码和待处理信号
    p->signal.sigmask = 0;
    p->signal.sigpending = 0;
    
    // 清空siginfo
    memset(p->signal.siginfos, 0, sizeof(p->signal.siginfos));
    
    // 初始化alarm状态
    spinlock_init(&alarm_state.lock, "alarm");
    alarm_state.alarm_time = 0;
    
    return 0;
}

int siginit_fork(struct proc *parent, struct proc *child) {
    // 复制父进程的信号处理方式和信号掩码
    for (int i = SIGMIN; i <= SIGMAX; i++) {
        child->signal.sa[i] = parent->signal.sa[i];
    }
    
    // 继承父进程的信号掩码
    child->signal.sigmask = parent->signal.sigmask;
    
    // 清空所有pending信号
    child->signal.sigpending = 0;
    memset(child->signal.siginfos, 0, sizeof(child->signal.siginfos));
    
    return 0;
}

int siginit_exec(struct proc *p) {
    // 保存当前的信号掩码和pending信号
    sigset_t old_mask = p->signal.sigmask;
    sigset_t old_pending = p->signal.sigpending;
    siginfo_t old_infos[SIGMAX + 1];
    memmove(old_infos, p->signal.siginfos, sizeof(old_infos));
    
    // 重置所有信号处理方式为默认，除了被忽略的信号
    for (int i = SIGMIN; i <= SIGMAX; i++) {
        if (p->signal.sa[i].sa_sigaction != SIG_IGN) {
            p->signal.sa[i].sa_sigaction = SIG_DFL;
            p->signal.sa[i].sa_mask = 0;
            p->signal.sa[i].sa_restorer = NULL;
        }
    }
    
    // 恢复信号掩码和pending信号
    p->signal.sigmask = old_mask;
    p->signal.sigpending = old_pending;
    memmove(p->signal.siginfos, old_infos, sizeof(old_infos));
    
    return 0;
}

int do_signal(void) {
    assert(!intr_get()); 
    
    struct proc *p = curr_proc();
    struct mm *mm = p->mm;
    sigset_t pending = p->signal.sigpending & ~p->signal.sigmask;
    
    // 如果没有未被屏蔽的待处理信号，直接返回
    if (pending == 0)
        return 0;

    // 按照编号顺序（优先级）处理信号
    int signo;
    for (signo = SIGMIN; signo <= SIGMAX; signo++) {
        if (pending & sigmask(signo))
            break;
    }
    
    // 清除pending标志
    p->signal.sigpending &= ~sigmask(signo);
    
    // 获取信号处理方式
    sigaction_t *sa = &p->signal.sa[signo];
    
    // 处理默认行为
    if (sa->sa_sigaction == SIG_DFL) {
        switch (signo) {
            case SIGKILL:
                // SIGKILL必须终止进程
                setkilled(p, -10 - signo);
                return 0;
                
            case SIGTERM:
            case SIGUSR0:
            case SIGUSR1:
            case SIGUSR2:
            case SIGSEGV:
            case SIGINT:
                // Term: 终止进程
                setkilled(p, -10 - signo);
                return 0;
                
            case SIGSTOP:
                // Stop: 停止进程（暂未实现）
                p->state = SLEEPING;  // 将进程状态设置为SLEEPING
                sched();
                return 0;
                
            case SIGCONT:
                // Continue: 继续进程（暂未实现）
                if (p->state == SLEEPING) {
                p->state = RUNNABLE;
                add_task(p);  // 将进程添加到运行队列
            }
                return 0;
                
            case SIGCHLD:
                // Ign: 忽略信号
                return 0;
        }
        return 0;
    }
    
    // 如果是忽略信号
    if (sa->sa_sigaction == SIG_IGN) {
        // SIGKILL和SIGSTOP不能被忽略
        if (signo == SIGKILL || signo == SIGSTOP) {
            setkilled(p, -10 - signo);
            return 0;
        }
        return 0;
    }
    
    // SIGKILL和SIGSTOP不能被捕获
    if (signo == SIGKILL || signo == SIGSTOP) {
        setkilled(p, -10 - signo);
        return 0;
    }
    
    // 需要调用用户定义的处理函数
    // 1. 保存当前的信号掩码
    sigset_t old_mask = p->signal.sigmask;
    
    // 2. 设置新的信号掩码（在处理函数执行期间屏蔽当前信号和sa_mask中的信号）
    p->signal.sigmask |= (sa->sa_mask | sigmask(signo));
    
    // 3. 在用户栈上构造ucontext和siginfo
    struct trapframe *tf = p->trapframe;
    uint64 old_sp = tf->sp;    
    // 确保栈指针16字节对齐
    uint64 sp = old_sp & ~0xf;
    
    // 为ucontext预留空间
    sp -= sizeof(struct ucontext);
    sp &= ~0xf;  // 16字节对齐
    uint64 ucontext_addr = sp;
    
  
    siginfo_t *kinfo = &p->signal.siginfos[signo];
    kinfo->si_signo  = signo;
    // 如果 si_pid 已由 sys_sigkill 设置则保持，否则置为 -1（内核触发）
    kinfo->si_pid    = (kinfo->si_pid != 0 ? kinfo->si_pid : -1);
    if(kinfo->si_signo != SIGCHLD){
        kinfo->si_code   = 0;
        kinfo->si_status = 0;
    }
    kinfo->addr      = NULL;
    printf("do_signal: signo=%d, pid=%d, code=%d, status=%d\n", 
                    signo, 
                    kinfo->si_pid, 
                    kinfo->si_code, 
                    kinfo->si_status);

    // 为siginfo预留空间
    sp -= sizeof(siginfo_t);
    sp &= ~0xf;  // 16字节对齐
    uint64 siginfo_addr = sp;
    
    // 为函数参数预留空间（保持栈16字节对齐）
    sp -= 16;  // 为三个参数预留空间
    
    // 4. 填充ucontext
    struct ucontext kcontext;
    kcontext.uc_sigmask = old_mask;
    kcontext.uc_mcontext.epc = tf->epc;
    
    // 保存通用寄存器
    memmove(kcontext.uc_mcontext.regs, &tf->ra, 31 * sizeof(uint64));
    
    
    // 5. 复制ucontext和siginfo到用户栈
    acquire(&mm->lock);
    if (copy_to_user(mm, ucontext_addr, (char*)&kcontext, sizeof(struct ucontext)) < 0 ||
        copy_to_user(mm, siginfo_addr, (char*)kinfo, sizeof(siginfo_t)) < 0) {
        release(&mm->lock);
        p->signal.sigmask = old_mask;  // 恢复原来的信号掩码
        return -1;
    }
    release(&mm->lock);
    
    // 6. 修改trapframe，使得返回用户态时执行信号处理函数
    tf->sp = sp;  // 新的栈顶
    tf->epc = (uint64)sa->sa_sigaction;  // 信号处理函数地址
    tf->ra = (uint64)sa->sa_restorer;  // ra: 恢复函数地址
    
    // 设置信号处理函数的参数
    tf->a0 = signo;  // 第一个参数：信号编号
    tf->a1 = siginfo_addr;  // 第二个参数：siginfo结构体指针
    tf->a2 = ucontext_addr;  // 第三个参数：ucontext结构体指针
    
    // 检查alarm是否到期
    acquire(&alarm_state.lock);
    uint64 current_time = r_time();
    if (alarm_state.alarm_time > 0 && current_time >= alarm_state.alarm_time) {
        // 发送SIGALRM信号
        p->signal.sigpending |= sigmask(SIGALRM);
        p->signal.siginfos[SIGALRM].si_signo = SIGALRM;
        p->signal.siginfos[SIGALRM].si_pid = p->pid;
        
        // 清除alarm时间
        alarm_state.alarm_time = 0;
    }
    release(&alarm_state.lock);
    
    return 0;
}

// syscall handlers:
//  sys_* functions are called by syscall.c

int sys_sigaction(int signo, const sigaction_t __user *act, sigaction_t __user *oldact) {
    struct proc *p = curr_proc();
    struct mm *mm = p->mm;
    
    // 检查信号编号是否有效
    if (signo < SIGMIN || signo > SIGMAX)
        return -1;
        
    // 如果需要，保存旧的处理方式
    if (oldact != NULL) {
        acquire(&mm->lock);
        if (copy_to_user(mm, (uint64)oldact, (char*)&p->signal.sa[signo], sizeof(sigaction_t)) < 0) {
            release(&mm->lock);
            return -1;
        }
        release(&mm->lock);
    }
    
    // 如果set为NULL，仅返回旧的处理方式
    if (act == NULL)
        return 0;
        
    // SIGKILL和SIGSTOP不能被捕获或忽略
    if (signo == SIGKILL || signo == SIGSTOP)
        return -1;
        
    // 获取新的处理方式
    sigaction_t kact;
    acquire(&mm->lock);
    if (copy_from_user(mm, (char*)&kact, (uint64)act, sizeof(sigaction_t)) < 0) {
        release(&mm->lock);
        return -1;
    }
    release(&mm->lock);
        
    // 设置新的处理方式
    p->signal.sa[signo] = kact;
    
    return 0;
}

int sys_sigreturn() {
    struct proc *p = curr_proc();
    struct trapframe *tf = p->trapframe;
    
    // 从用户栈上获取ucontext
    struct ucontext kcontext;
    uint64 sp = tf->sp;
    
    // 跳过为参数预留的空间
    sp += 16;
    
    // 跳过siginfo_t结构体
    sp += sizeof(siginfo_t);
    sp = (sp + 0xf) & ~0xf;  // 16字节对齐
    
    // 获取ucontext
    acquire(&p->mm->lock);
    int ret = copy_from_user(p->mm, (char*)&kcontext, sp, sizeof(struct ucontext));
    release(&p->mm->lock);
    if (ret < 0) {
        return -1;
    }
        
    // 恢复信号掩码
    p->signal.sigmask = kcontext.uc_sigmask;
    
    // 恢复通用寄存器
    memmove(&tf->ra,kcontext.uc_mcontext.regs, 31 * sizeof(uint64));
    
    return 0;
}

int sys_sigprocmask(int how, const sigset_t __user *set, sigset_t __user *oldset) {
    struct proc *p = curr_proc();
    struct mm *mm = p->mm;
    sigset_t old_mask = p->signal.sigmask;
    
    // 如果需要，保存旧的信号掩码
    if (oldset != NULL) {
        acquire(&mm->lock);
        int ret = copy_to_user(mm, (uint64)oldset, (char*)&old_mask, sizeof(sigset_t));
        release(&mm->lock);
        if (ret < 0) {
            return -1;
        }
    }

    // 如果set为NULL，仅返回旧的信号掩码
    if (set == NULL)
        return 0;
        
    // 获取新的信号掩码
    sigset_t new_mask;
    acquire(&mm->lock);
    int ret = copy_from_user(mm, (char*)&new_mask, (uint64)set, sizeof(sigset_t));
    release(&mm->lock);
    if (ret < 0) {
        return -1;
    }
        
    // 在sys_sigprocmask中，确保SIGKILL不能被阻塞
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
    
    // SIGKILL和SIGSTOP不能被屏蔽
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
    // 检查信号编号是否有效
    if (signo < SIGMIN || signo > SIGMAX)
        return -1;

    // 遍历进程池查找目标进程
    for (int i = 0; i < NPROC; i++) {
        struct proc *p = pool[i];
        acquire(&p->lock);
        if (p->pid == pid) {
            // 设置pending信号
            p->signal.sigpending |= sigmask(signo);
            
            printf("original_siginfo: signo=%d, pid=%d, code=%d, status=%d\n", 
                p->signal.siginfos[signo].si_signo,
                p->signal.siginfos[signo].si_pid, 
                p->signal.siginfos[signo].si_code,
                p->signal.siginfos[signo].si_status);

            // 设置siginfo
            p->signal.siginfos[signo].si_pid = curr_proc()->pid;
            p->signal.siginfos[signo].si_signo = signo;
            p->signal.siginfos[signo].si_code = code;
            
            // 如果进程在睡眠，唤醒它
            if (p->state == SLEEPING) {
                p->state = RUNNABLE;
                add_task(p);
            }
            
            release(&p->lock);
            return 0;
        }
        release(&p->lock);
    }
    
    return -1;  // 未找到目标进程
}

// 添加alarm系统调用实现
unsigned int alarm(unsigned int seconds) {
    struct proc *p = curr_proc();
    uint64 current_time = r_time();
    unsigned int remaining = 0;
    
    acquire(&alarm_state.lock);
    
    // 如果seconds为0，取消现有的alarm
    if (seconds == 0) {
        if (alarm_state.alarm_time > current_time) {
            // 将CPU周期数转换为秒数
            remaining = (alarm_state.alarm_time - current_time) / CPU_FREQ;
        }
        alarm_state.alarm_time = 0;
    } else {
        // 计算新的alarm时间（以CPU周期为单位）
        uint64 new_alarm_time = current_time + seconds * CPU_FREQ;
        
        // 如果已有alarm，计算剩余时间
        if (alarm_state.alarm_time > current_time) {
            remaining = (alarm_state.alarm_time - current_time) / CPU_FREQ;
        }
        
        // 设置新的alarm时间
        alarm_state.alarm_time = new_alarm_time;
    }
    
    release(&alarm_state.lock);
    return remaining;
}

// 在定时器中断处理程序中检查alarm
void check_alarm(void) {
    struct proc *p = curr_proc();
    if (p == NULL) {
        return;  // 如果没有当前进程，直接返回
    }
    
    uint64 current_time = r_time();
    
    acquire(&alarm_state.lock);
    if (alarm_state.alarm_time > 0 && current_time >= alarm_state.alarm_time) {
        // 发送SIGALRM信号
        acquire(&p->lock);
        p->signal.sigpending |= sigmask(SIGALRM);
        p->signal.siginfos[SIGALRM].si_signo = SIGALRM;
        p->signal.siginfos[SIGALRM].si_pid = p->pid;
        release(&p->lock);
        
        // 清除alarm时间
        alarm_state.alarm_time = 0;
    }
    release(&alarm_state.lock);
}