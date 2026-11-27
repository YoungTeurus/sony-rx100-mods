/* Stage 7.3 Phase B SD worker preload hook for Sony DSC-RX100M7 1.00.
 * Freestanding ARMv7 EABI (-nostdlib -shared -fPIC): zero libc/DT_NEEDED imports.
 * Triggers ONLY when /proc/self/exe == "/usr/bin/bsa_server" (spawned automatically
 * after both WBI battery-pull resume and S2R power-switch resume when Bluetooth is ON).
 * All other processes (/sbin/init, im.elf, sen.elf, /bin/busybox, ash, ud_*.elf)
 * return immediately after a single readlink() syscall.
 */
#define TARGET_BSA   "/usr/bin/bsa_server"
#define DISABLE_FLAG "/setting/disable_sd_boot"
#define WORKER       "/setting/mlv2_sd_boot.sh"
#define BUSYBOX      "/bin/busybox"

static inline long sc0(long n) {
    register long r7 __asm__("r7") = n, r0 __asm__("r0") = 0;
    __asm__ volatile("svc 0" : "+r"(r0) : "r"(r7) : "memory", "cc");
    return r0;
}
static inline long sc1(long n, long a) {
    register long r7 __asm__("r7") = n, r0 __asm__("r0") = a;
    __asm__ volatile("svc 0" : "+r"(r0) : "r"(r7) : "memory", "cc");
    return r0;
}
static inline long sc2(long n, long a, long b) {
    register long r7 __asm__("r7") = n, r0 __asm__("r0") = a, r1 __asm__("r1") = b;
    __asm__ volatile("svc 0" : "+r"(r0) : "r"(r7), "r"(r1) : "memory", "cc");
    return r0;
}
static inline long sc3(long n, long a, long b, long c) {
    register long r7 __asm__("r7") = n, r0 __asm__("r0") = a, r1 __asm__("r1") = b, r2 __asm__("r2") = c;
    __asm__ volatile("svc 0" : "+r"(r0) : "r"(r7), "r"(r1), "r"(r2) : "memory", "cc");
    return r0;
}
static inline long sc4(long n, long a, long b, long c, long d) {
    register long r7 __asm__("r7") = n, r0 __asm__("r0") = a, r1 __asm__("r1") = b;
    register long r2 __asm__("r2") = c, r3 __asm__("r3") = d;
    __asm__ volatile("svc 0" : "+r"(r0) : "r"(r7), "r"(r1), "r"(r2), "r"(r3) : "memory", "cc");
    return r0;
}

static int eq_n(const char *a, const char *b, long n) {
    for (long i = 0; i < n; i++) {
        if (a[i] != b[i]) return 0;
    }
    return 1;
}

__attribute__((constructor, visibility("hidden"))) static void mlv2_sd_boot_launch(void) {
    char exe[64];
    long n = sc3(85 /* SYS_readlink */, (long)"/proc/self/exe", (long)exe, (long)sizeof(exe));
    if (n != (long)(sizeof(TARGET_BSA) - 1) || !eq_n(exe, TARGET_BSA, n)) return;
    if (sc0(199 /* SYS_getuid32 */) != 0) return;
    if (sc2(33 /* SYS_access */, (long)DISABLE_FLAG, 0 /* F_OK */) == 0) return;
    if (sc2(33 /* SYS_access */, (long)WORKER, 4 /* R_OK */) != 0) return;

    long child = sc0(2 /* SYS_fork */);
    if (child < 0) return;
    if (child > 0) {
        while (sc4(114 /* SYS_wait4 */, child, 0, 0, 0) == -4 /* -EINTR */) {}
        return;
    }
    if (sc0(2 /* SYS_fork */) != 0) sc1(1 /* SYS_exit */, 0);
    if (sc0(66 /* SYS_setsid */) < 0) sc1(1 /* SYS_exit */, 1);
    for (long fd = 0; fd < 256; fd++) sc1(6 /* SYS_close */, fd);
    if (sc3(5 /* SYS_open */, (long)"/dev/null", 0 /* O_RDONLY */, 0) != 0 ||
        sc3(5 /* SYS_open */, (long)"/dev/null", 1 /* O_WRONLY */, 0) != 1 ||
        sc2(63 /* SYS_dup2 */, 1, 2) != 2) {
        sc1(1 /* SYS_exit */, 1);
    }

    const char *argv[4];
    argv[0] = "busybox";
    argv[1] = "sh";
    argv[2] = WORKER;
    argv[3] = 0;
    const char *envp[2];
    envp[0] = "PATH=/usr/bin:/bin:/sbin:/usr/sbin";
    envp[1] = 0;
    sc3(11 /* SYS_execve */, (long)BUSYBOX, (long)argv, (long)envp);
    sc1(1 /* SYS_exit */, 127);
}
