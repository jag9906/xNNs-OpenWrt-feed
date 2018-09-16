/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Portions copyright 2005-2013 Steinar H. Gunderson <sgunderson@bigfoot.com>.
 * Licensed under the same terms as the rest of Apache.
 */

#include "ap_config.h"
#include "httpd.h"
#include "http_log.h"
#include "http_main.h"

#if defined(__linux__) && (defined(__i386__) || defined(__x86_64__))

#define SECCOMP_BPF_SUPPORTED 1

#include <stddef.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/unistd.h>
#include <linux/types.h>
#include <sys/prctl.h>

/* These definitions are from <linux/seccomp.h>, which we do not include
 * because it is not very commonly installed yet.
 */
#define SECCOMP_RET_KILL 0x00000000U
#define SECCOMP_RET_ERRNO 0x00050000U
#define SECCOMP_RET_ALLOW 0x7fff0000U
#define SECCOMP_MODE_FILTER 2
struct seccomp_data {
    int nr;
    __u32 arch;
    __u64 instruction_pointer;
    __u64 args[6];
};

#define syscall_arg(_n) (offsetof(struct seccomp_data, args[_n]))
#define syscall_nr (offsetof(struct seccomp_data, nr))
#define arch_nr (offsetof(struct seccomp_data, arch))

/* Note that we assume little-endian in the BPF (we assume the first 32 bits of
 * the argument contain the lower 32 bits, whether we are on 32- or 64-bit).
 */
#if defined(__i386__)
#define ARCH_NR AUDIT_ARCH_I386
#elif defined(__amd64__)
#define ARCH_NR AUDIT_ARCH_X86_64
#endif

#endif

#if SECCOMP_BPF_SUPPORTED

static int apply_seccomp_filter(struct sock_filter *filter, int len)
{
    struct sock_fprog seccomp_prog = {
        .len = len,
        .filter = filter,
    };
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &seccomp_prog) != 0) {
        ap_log_error(APLOG_MARK, APLOG_INFO, APR_SUCCESS, ap_server_conf,
                     "Installing seccomp filter failed (probably due to too old kernel); "
                     "unable to restrict setuid privileges. Error was: %s",
                     strerror(errno));
        return 1;
    } else {
        return 0;
    }
}

static void add_bpf_stmt(struct sock_filter *filter, int *pos, __u16 code, __u32 k)
{
    struct sock_filter stmt = BPF_STMT(code, k);
    filter[*pos] = stmt;
    ++*pos;
}

static void add_bpf_jump(struct sock_filter *filter, int *pos, __u16 code, __u32 k, __u8 jt, __u8 jf)
{
    struct sock_filter stmt = BPF_JUMP(code, k, jt, jf);
    filter[*pos] = stmt;
    ++*pos;
}

static int limit_syscall_range(int syscall_to_match, int nr_args, __u32 min, __u32 max, __u32 or_eq)
{
    static struct sock_filter syscall_filter[BPF_MAXINSNS];

    int pos = 0;

    /* If we don't match the syscall number, return immediately. */
    add_bpf_stmt(syscall_filter, &pos, BPF_LD + BPF_W + BPF_ABS, syscall_nr);
    add_bpf_jump(syscall_filter, &pos, BPF_JMP + BPF_JEQ + BPF_K, syscall_to_match, 1, 0);
    add_bpf_stmt(syscall_filter, &pos, BPF_RET + BPF_K, SECCOMP_RET_ALLOW);

    for (int i = 0; i < nr_args; ++i) {
        add_bpf_stmt(syscall_filter, &pos, BPF_LD + BPF_W + BPF_ABS, syscall_arg(i));
        if (or_eq != 0) {
            add_bpf_jump(syscall_filter, &pos, BPF_JMP + BPF_JEQ + BPF_K, or_eq, 4, 0);
        }
        add_bpf_jump(syscall_filter, &pos, BPF_JMP + BPF_JGE + BPF_K, min, 1, 0);
        add_bpf_stmt(syscall_filter, &pos, BPF_RET + BPF_K, SECCOMP_RET_ERRNO | EPERM);
        add_bpf_jump(syscall_filter, &pos, BPF_JMP + BPF_JGT + BPF_K, max, 0, 1);
        add_bpf_stmt(syscall_filter, &pos, BPF_RET + BPF_K, SECCOMP_RET_ERRNO | EPERM);
    }

    add_bpf_stmt(syscall_filter, &pos, BPF_RET + BPF_K, SECCOMP_RET_ALLOW);
    return apply_seccomp_filter(syscall_filter, pos);
}

#endif

void restrict_setuid_range(uid_t min_uid, uid_t max_uid, gid_t min_gid, gid_t max_gid)
{
#if SECCOMP_BPF_SUPPORTED
    uid_t min_uid16 = (min_uid > 65535) ? 65535 : min_uid;
    uid_t max_uid16 = (max_uid > 65535) ? 65535 : max_uid;
    gid_t min_gid16 = (min_gid > 65535) ? 65535 : min_gid;
    gid_t max_gid16 = (max_gid > 65535) ? 65535 : max_gid;

    uid_t minus_one = (uid_t) -1;
#ifdef __i386__
    __u16 minus_one16 = (__u16) -1;
#endif // defined(__i386__)

    /* Apply a seccomp BPF to ourselves that disallows all setuid- and
     * setgid-like calls if the first argument is 0.  The list of calls comes from
     * the descriptions of CAP_SETUID and CAP_SETGID in capabilities(7), although
     * CAP_SETGID is underdocumented.
     */
    struct sock_filter arch_filter[] = {
        /* Validate that the syscall is of the right architecture,
         * so that an attacker cannot circumvent our syscall protection
         * by changing to a different personality.
         */
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, arch_nr),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ARCH_NR, 1, 0),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
    };
    if (apply_seccomp_filter(arch_filter, sizeof(arch_filter) / sizeof(arch_filter[0])) != 0) {
        return;
    }

#ifdef __i386__
    /* Newer, 32-bit uid_t/gid_t syscalls. */
    limit_syscall_range(__NR_setfsuid32, 1, min_uid, max_uid, minus_one);
    limit_syscall_range(__NR_setuid32, 1, min_uid, max_uid, 0);
    limit_syscall_range(__NR_setreuid32, 2, min_uid, max_uid, minus_one);
    limit_syscall_range(__NR_setresuid32, 3, min_uid, max_uid, minus_one);

    limit_syscall_range(__NR_setfsgid32, 1, min_gid, max_gid, minus_one);
    limit_syscall_range(__NR_setgid32, 1, min_gid, max_gid, 0);
    limit_syscall_range(__NR_setregid32, 2, min_gid, max_gid, minus_one);
    limit_syscall_range(__NR_setresgid32, 3, min_gid, max_gid, minus_one);

    /* Older 16-bit old_uid_t/old_gid_t syscalls. */
    limit_syscall_range(__NR_setfsuid, 1, min_uid16, max_uid16, minus_one16);
    limit_syscall_range(__NR_setuid, 1, min_uid16, max_uid16, 0);
    limit_syscall_range(__NR_setreuid, 2, min_uid16, max_uid16, minus_one16);
    limit_syscall_range(__NR_setresuid, 3, min_uid16, max_uid16, minus_one16);

    limit_syscall_range(__NR_setfsgid, 1, min_gid16, max_gid16, minus_one16);
    limit_syscall_range(__NR_setgid, 1, min_gid16, max_gid16, 0);
    limit_syscall_range(__NR_setregid, 2, min_gid16, max_gid16, minus_one16);
    limit_syscall_range(__NR_setresgid, 3, min_gid16, max_gid16, minus_one16);

#else // not defined(__i386__)
    /* Just one set of 32-bit uid_t/gid_t syscalls to worry about. */
    limit_syscall_range(__NR_setfsuid, 1, min_uid, max_uid, minus_one);
    limit_syscall_range(__NR_setuid, 1, min_uid, max_uid, 0);
    limit_syscall_range(__NR_setreuid, 2, min_uid, max_uid, minus_one);
    limit_syscall_range(__NR_setresuid, 3, min_uid, max_uid, minus_one);

    limit_syscall_range(__NR_setfsgid, 1, min_gid, max_gid, minus_one);
    limit_syscall_range(__NR_setgid, 1, min_gid, max_gid, 0);
    limit_syscall_range(__NR_setregid, 2, min_gid, max_gid, minus_one);
    limit_syscall_range(__NR_setresgid, 3, min_gid, max_gid, minus_one);
#endif

#else
    ap_log_error(APLOG_MARK, APLOG_INFO, APR_SUCCESS, ap_server_conf,
                 "Your platform or architecture does not support seccomp v2; "
                 "unable to restrict setuid privileges.");
#endif
}
