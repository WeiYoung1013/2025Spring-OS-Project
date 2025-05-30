#include "../../os/ktest/ktest.h"
#include "../lib/user.h"

// Base Checkpoint 1: sigaction, sigkill, and sigreturn

// send SIGUSR0 to a child process, which default action is to terminate it.
void basic1(char* s) {
    int pid = fork();
    if (pid == 0) {
        // child
        sleep(10);
        exit(1);
    } else {
        // parent
        sigkill(pid, SIGUSR0, 0);
        int ret;
        wait(0, &ret);
        assert(ret == -10 - SIGUSR0);
    }
}

// send SIGUSR0 to a child process, but should be ignored.
void basic2(char* s) {
    int pid = fork();
    if (pid == 0) {
        // child
        sigaction_t sa = {
            .sa_sigaction = SIG_IGN,
            .sa_mask      = 0,
            .sa_restorer  = NULL,
        };
        sigaction(SIGUSR0, &sa, 0);
        sleep(10);
        sleep(10);
        sleep(10);
        exit(1);
    } else {
        // parent
        sleep(5);
        sigkill(pid, SIGUSR0, 0);
        int ret;
        wait(0, &ret);
        assert(ret == 1);
    }
}

void handler3(int signo, siginfo_t* info, void* ctx2) {
    assert(signo == SIGUSR0);
    getpid();
    sleep(1);
    exit(103);
}

// set handler for SIGUSR0, which call exits to terminate the process.
//  this handler will not return, so sigreturn should not be called.
void basic3(char* s) {
    int pid = fork();
    if (pid == 0) {
        // child
        sigaction_t sa = {
            .sa_sigaction = handler3,
            .sa_restorer  = sigreturn,
        };
        sigemptyset(&sa.sa_mask);
        sigaction(SIGUSR0, &sa, 0);
        while (1);
        exit(1);
    } else {
        // parent
        sleep(10);
        sigkill(pid, SIGUSR0, 0);
        int ret;
        wait(0, &ret);
        assert_eq(ret, 103);
    }
}

volatile int handler4_flag = 0;
void handler4(int signo, siginfo_t* info, void* ctx2) {
    assert(signo == SIGUSR0);
    sleep(1);
    sleep(1);
    fprintf(1, "handler4 triggered\n");
    handler4_flag = 1;
}

// set handler for SIGUSR0, and return from handler.
void basic4(char* s) {
    int pid = fork();
    if (pid == 0) {
        // child
        sigaction_t sa = {
            .sa_sigaction = handler4,
            .sa_restorer  = sigreturn,
        };
        sigemptyset(&sa.sa_mask);
        sigaction(SIGUSR0, &sa, 0);
        while (handler4_flag == 0);
        exit(104);
    } else {
        // parent
        sleep(10);
        sigkill(pid, SIGUSR0, 0);
        int ret;
        wait(0, &ret);
        assert_eq(ret, 104);
    }
}

static volatile int handler5_cnt = 0;
void handler5(int signo, siginfo_t* info, void* ctx2) {
    assert(signo == SIGUSR0);
    static volatile int nonreentrace = 0;
    assert(!nonreentrace);    // non-reentrance
    nonreentrace = 1;
    sleep(5);
    sleep(5);
    if (handler5_cnt < 5)
        sigkill(getpid(), SIGUSR0, 0);
    sleep(5);
    sleep(5);
    fprintf(1, "handler5 triggered\n");
    nonreentrace = 0;
    handler5_cnt++;
}

// signal handler itself should not be reentrant.
//  when the signal handler is called for SIGUSR0, it should block all SIGUSR0.
//  after the signal handler returns, the signal should be unblocked.
//   then, the signal handler should be called again. (5 times)
// set handler for SIGUSR0, kernel should block it from re-entrance.
void basic5(char* s) {
    int pid = fork();
    if (pid == 0) {
        // child
        sigaction_t sa = {
            .sa_sigaction = handler5,
            .sa_restorer  = sigreturn,
        };
        sigemptyset(&sa.sa_mask);
        sigaction(SIGUSR0, &sa, 0);
        while (handler5_cnt < 5);
        exit(105);
    } else {
        // parent
        sleep(10);
        sigkill(pid, SIGUSR0, 0);
        int ret;
        wait(0, &ret);
        assert_eq(ret, 105);
    }
}

volatile int handler6_flag = 0;
void handler6(int signo, siginfo_t* info, void* ctx2) {
    assert(signo == SIGUSR0);
    handler6_flag = 1;
    fprintf(1, "handler6 triggered due to %d\n", signo);
    sleep(30);
    assert(handler6_flag == 2);
    handler6_flag = 3;
}

void handler6_2(int signo, siginfo_t* info, void* ctx2) {
    assert(signo == SIGUSR1);
    assert(handler6_flag == 1);
    handler6_flag = 2;
    fprintf(1, "handler6_2 triggered due to %d\n", signo);
}

// signal handler can be nested.
void basic6(char* s) {
    int pid = fork();
    if (pid == 0) {
        // child
        sigaction_t sa = {
            .sa_sigaction = handler6,
            .sa_restorer  = sigreturn,
        };
        sigemptyset(&sa.sa_mask);
        sigaction(SIGUSR0, &sa, 0);
        sigaction_t sa2 = {
            .sa_sigaction = handler6_2,
            .sa_restorer  = sigreturn,
        };
        sigemptyset(&sa2.sa_mask);
        sigaction(SIGUSR1, &sa2, 0);
        while (handler6_flag != 3);
        exit(106);
    } else {
        // parent
        sleep(10);
        sigkill(pid, SIGUSR0, 0);
        sleep(5);
        sigkill(pid, SIGUSR1, 0);
        sleep(5);
        int ret;
        wait(0, &ret);
        assert_eq(ret, 106);
    }
}

volatile int handler7_flag = 0;
void handler7(int signo, siginfo_t* info, void* ctx2) {
    assert(signo == SIGUSR0);
    handler7_flag = 1;
    fprintf(1, "handler7 triggered due to %d\n", signo);
    sleep(30);
    sigset_t pending;
    sigpending(&pending);
    assert_eq(pending, sigmask(SIGUSR1));
    assert(handler7_flag == 1); // handler7 should not interrupted by SIGUSR1 (handler7_2)
    handler7_flag = 2;
}

void handler7_2(int signo, siginfo_t* info, void* ctx2) {
    assert(signo == SIGUSR1);
    assert(handler7_flag == 2);
    handler7_flag = 3;
    fprintf(1, "handler7_2 triggered due to %d\n", signo);
}

// signal handler can be nested.
void basic7(char* s) {
    int pid = fork();
    if (pid == 0) {
        // child
        sigaction_t sa = {
            .sa_sigaction = handler7,
            .sa_restorer  = sigreturn,
        };
        sigemptyset(&sa.sa_mask);
        sigaddset(&sa.sa_mask, SIGUSR1); // block SIGUSR1 when handling SIGUSR0
        sigaction(SIGUSR0, &sa, 0);

        sigaction_t sa2 = {
            .sa_sigaction = handler7_2,
            .sa_restorer  = sigreturn,
        };
        sigemptyset(&sa2.sa_mask);
        sigaction(SIGUSR1, &sa2, 0);

        while (handler7_flag != 3);
        exit(107);
    } else {
        // parent
        sleep(10);
        sigkill(pid, SIGUSR0, 0);
        sleep(5);
        sigkill(pid, SIGUSR1, 0);
        sleep(5);
        int ret;
        wait(0, &ret);
        assert_eq(ret, 107);
    }
}

// SIG_IGN and SIG_DFL
void basic8(char* s) {
    int pid = fork();
    if (pid == 0) {
        // child
        sigaction_t sa = {
            .sa_sigaction = SIG_IGN,
            .sa_restorer  = NULL,
        };
        sigaction(SIGUSR0, &sa, 0);
        sigkill(getpid(), SIGUSR0, 0); // should have no effect

        sigaction_t sa2 = {
            .sa_sigaction = SIG_DFL,
            .sa_restorer  = NULL,
        };
        sigaction(SIGUSR1, &sa2, 0);
        sigkill(getpid(), SIGUSR1, 0); // should terminate the process

        exit(1);
    } else {
        // parent
        sigkill(pid, SIGUSR0, 0);
        int ret;
        wait(0, &ret);
        assert(ret == -10 - SIGUSR1); // child terminated by SIGUSR1
    }
}


// Base Checkpoint 2: SIGKILL

void handler10(int signo, siginfo_t* info, void* ctx2) {
    exit(2);
}

// child process is killed by signal: SIGKILL, which cannot be handled, ignored and blocked.
void basic10(char* s) {
    int pid = fork();
    if (pid == 0) {
        // child
        sigaction_t sa = {
            .sa_sigaction = handler10,
            .sa_restorer  = NULL,
        };
        sigaction(SIGKILL, &sa, 0); 
        // set handler for SIGKILL, which should not be called
        while (1);
        exit(1);
    } else {
        // parent
        sleep(20);
        sigkill(pid, SIGKILL, 0);
        int ret;
        wait(0, &ret);
        assert(ret == -10 - SIGKILL);
    }
}

// child process is killed by signal: SIGKILL, which cannot be handled, ignored and blocked.
void basic11(char* s) {
    int pid = fork();
    if (pid == 0) {
        // child
        sigset_t mask;
        sigemptyset(&mask);
        sigaddset(&mask, SIGKILL);
        sigprocmask(SIG_BLOCK, &mask, NULL);
        // set handler for SIGKILL, which should not be called
        while (1);
        exit(1);
    } else {
        // parent
        sleep(20);
        sigkill(pid, SIGKILL, 0);
        int ret;
        wait(0, &ret);
        assert(ret == -10 - SIGKILL);
    }
}

// Base Checkpoint 3: signals under fork & exec

void basic20(char *s) {
    // our modification does not affect our parent process.
    // because `run` method in the testsuite will do fork for us.

    sigaction_t sa = {
        .sa_sigaction = SIG_IGN,
        .sa_restorer  = NULL,
    };
    sigaction(SIGUSR0, &sa, 0);
    // ignore SIGUSR0.

    int pid = fork();
    if (pid == 0) {
        // child
        sigkill(getpid(), SIGUSR0, 0); 
        // should have no effect, because parent ignores it.
        exit(1);
    } else {
        // parent
        int ret;
        wait(0, &ret);
        assert(ret == 1); // child should not be terminated by SIGUSR0
    }
}

// Base Checkpoint 4: alarm system call

// alarm信号处理函数
void handler_alarm(int signo, siginfo_t* info, void* ctx) {
    assert(signo == SIGALRM);
    assert(info->si_signo == SIGALRM);
    assert(info->si_pid == getpid());
    fprintf(1, "SIGALRM handler triggered!\n");
    fprintf(1, "Signal number: %d\n", signo);
    fprintf(1, "Process ID: %d\n", info->si_pid);
    exit(200);
}

// 测试alarm系统调用
void basic_alarm(char* s) {
    int pid = fork();
    if (pid == 0) {
        // 子进程
        fprintf(1, "Child process started\n");
        
        // 测试1：设置SIGALRM信号处理函数
        sigaction_t sa = {
            .sa_sigaction = handler_alarm,
            .sa_restorer = sigreturn,
        };
        sigemptyset(&sa.sa_mask);
        sigaction(SIGALRM, &sa, 0);
        fprintf(1, "SIGALRM handler set\n");
        
        // 测试2：首次设置alarm，应该返回0（之前没有alarm）
        fprintf(1, "Setting first alarm for 5 seconds...\n");
        unsigned int remaining = alarm(5);
        fprintf(1, "Previous alarm remaining time: %d seconds\n", remaining);
        assert_eq(remaining, 0);  // 之前没有alarm，应该返回0
        
        // 测试3：在alarm到期前设置新的alarm，应该返回剩余时间
        sleep(2);  // 等待2秒
        fprintf(1, "Setting new alarm for 3 seconds...\n");
        remaining = alarm(3);
        fprintf(1, "Previous alarm remaining time: %d seconds\n", remaining);
        assert(remaining > 0);  // 应该返回剩余时间（约3秒）
        
        // 测试4：取消alarm，应该返回剩余时间
        sleep(1);  // 等待1秒
        fprintf(1, "Canceling alarm...\n");
        remaining = alarm(0);
        fprintf(1, "Previous alarm remaining time: %d seconds\n", remaining);
        assert(remaining > 0);  // 应该返回剩余时间（约2秒）
        
        // 测试5：设置新的alarm，应该返回0（之前的alarm已被取消）
        fprintf(1, "Setting final alarm for 2 seconds...\n");
        remaining = alarm(2);
        fprintf(1, "Previous alarm remaining time: %d seconds\n", remaining);
        assert_eq(remaining, 0);  // 之前的alarm已被取消，应该返回0
        
        // 等待alarm信号
        fprintf(1, "Waiting for alarm...\n");
        while(1);
        exit(1);
    } else {
        // 父进程
        fprintf(1, "Parent process waiting for child...\n");
        int ret;
        wait(0, &ret);
        fprintf(1, "Child process exited with code: %d\n", ret);
        assert_eq(ret, 200);  // 信号处理函数应该返回200
    }
}

// 验证 siginfo_t 结构体的各字段：
// si_signo  应是 SIGUSR1
// si_pid    应是发送者（parent）的 pid
// si_code   应为 0
// si_status 应为 0
// addr      应为 NULL
void siginfo_handler(int signo, siginfo_t *info, void *ctx) {
    printf("Check signo=%d, pid=%d, code=%d, status=%d\n", info->si_signo, info->si_pid, info->si_code, info->si_status);

    // 检查信号编号
    assert(signo == SIGUSR1);
    // 检查 si_signo
    assert(info->si_signo == SIGUSR1);
    // 检查 si_pid（父进程发送）
    int ppid = getppid();
    assert(info->si_pid == ppid);
    // 检查其他字段
    assert(info->si_code == 0);
    assert(info->si_status == 0);
    assert(info->addr == NULL);

    // 如果都通过，则退出并返回特定码
    exit(123);
}

void basic_siginfo_check(char *s) {
    // 在子进程安装 handler
    int pid = fork();
    if (pid == 0) {
        sigaction_t sa = {
            .sa_sigaction = siginfo_handler,
            .sa_restorer  = sigreturn,
        };
        sigemptyset(&sa.sa_mask);
        sigaction(SIGUSR1, &sa, NULL);

        // 等待信号
        while (1) sleep(1);
    } else {
        // 父进程稍等，让子进程安装好 handler
        sleep(5);
        // 由父进程发送 SIGUSR1
        sigkill(pid, SIGUSR1, 2);

        // 等待子进程退出并检查它的 exit code
        int status;
        wait(0, &status);
        // 我们在 handler 里用 exit(123)，因此这里应该收到 123
        assert_eq(status, 123);
    }
}


// 验证由内核发送 SIGCHLD 信号时，siginfo_t 的 si_pid 字段应为子进程 pid
void siginfo_chld_handler(int signo, siginfo_t *info, void *ctx) {
    assert(signo == SIGCHLD);
    assert(info->si_signo == SIGCHLD);
    // si_pid 应为子进程 pid
    assert(info->si_pid > 0);
    // 其余字段通常为 0
    assert(info->si_code == 0);
    assert(info->si_status == 0);
    assert(info->addr == NULL);
    exit(125);
}

void basic_siginfo_chld_check(char *s) {
    int pid = fork();
    if (pid == 0) {
        exit(77); // 子进程直接退出
    } else {
        sigaction_t sa = {
            .sa_sigaction = siginfo_chld_handler,
            .sa_restorer  = sigreturn,
        };
        sigemptyset(&sa.sa_mask);
        sigaction(SIGCHLD, &sa, NULL);

        // 等待 handler 被触发
        int status;
        wait(0, &status);
        // handler exit(125) 后父进程应退出
        assert_eq(status, 125);
    }
}

