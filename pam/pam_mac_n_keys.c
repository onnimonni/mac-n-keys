/*
 * pam_mac_n_keys.c - PAM module for sudo with Touch ID and process info
 *
 * Shows a Touch ID prompt with the command being run and the requesting terminal.
 *
 * Build: make
 * Install: sudo cp pam_mac_n_keys.so /usr/lib/pam/
 * Configure: Add to /etc/pam.d/sudo:
 *   auth sufficient pam_mac_n_keys.so
 */

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libproc.h>
#include <sys/sysctl.h>

/* Forward declarations for LocalAuthentication - linked via framework */
#include <CoreFoundation/CoreFoundation.h>

/* We use the Objective-C runtime to call LAContext without importing the header */
#include <objc/objc.h>
#include <objc/runtime.h>
#include <objc/message.h>

/* LAPolicy enum value for deviceOwnerAuthenticationWithBiometrics */
#define LAPolicyDeviceOwnerAuthenticationWithBiometrics 1
#define LAPolicyDeviceOwnerAuthentication 2

static void get_process_name(pid_t pid, char *buf, size_t buflen) {
    char path[PROC_PIDPATHINFO_MAXSIZE];
    if (proc_pidpath(pid, path, sizeof(path)) > 0) {
        /* Extract just the binary name from the path */
        char *name = strrchr(path, '/');
        if (name) {
            strlcpy(buf, name + 1, buflen);
        } else {
            strlcpy(buf, path, buflen);
        }
    } else {
        snprintf(buf, buflen, "pid %d", pid);
    }
}

static void get_command_line(pid_t pid, char *buf, size_t buflen) {
    /* Use sysctl to get process arguments */
    int mib[3] = { CTL_KERN, KERN_PROCARGS2, pid };
    size_t argmax = 0;
    size_t size = sizeof(argmax);

    if (sysctl((int[]){CTL_KERN, KERN_ARGMAX}, 2, &argmax, &size, NULL, 0) != 0) {
        snprintf(buf, buflen, "(unknown)");
        return;
    }

    char *procargs = malloc(argmax);
    if (!procargs) {
        snprintf(buf, buflen, "(unknown)");
        return;
    }

    size = argmax;
    if (sysctl(mib, 3, procargs, &size, NULL, 0) != 0) {
        free(procargs);
        snprintf(buf, buflen, "(unknown)");
        return;
    }

    /* Skip argc (first 4 bytes) and the exec path, then collect args */
    int argc;
    memcpy(&argc, procargs, sizeof(argc));
    char *p = procargs + sizeof(argc);

    /* Skip exec path */
    while (p < procargs + size && *p != '\0') p++;
    while (p < procargs + size && *p == '\0') p++;

    /* Collect arguments */
    buf[0] = '\0';
    size_t pos = 0;
    size_t remaining;
    for (int i = 0; i < argc && p < procargs + size; i++) {
        remaining = (size_t)(procargs + size - p);
        size_t len = strnlen(p, remaining);
        if (pos + len + 2 < buflen) {
            if (pos > 0) { buf[pos++] = ' '; }
            memcpy(buf + pos, p, len);
            pos += len;
            buf[pos] = '\0';
        }
        if (len == remaining) break; /* no null terminator found, stop */
        p += len + 1;
    }

    free(procargs);
}

/*
 * SECURITY NOTE (TOCTOU): There is an inherent time-of-check/time-of-use gap
 * between reading the process arguments (get_command_line) and the actual
 * execution of the authenticated command. A malicious process could
 * theoretically modify its argv between these points. This is a fundamental
 * limitation of process inspection via sysctl/procfs — the information is
 * advisory only and should not be relied upon for access control decisions.
 * The Touch ID prompt displays the command for user awareness, not enforcement.
 */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                    int argc, const char **argv) {
    /* Parse PAM arguments: allow_passcode enables password fallback */
    long policy = LAPolicyDeviceOwnerAuthenticationWithBiometrics;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "allow_passcode") == 0) {
            policy = LAPolicyDeviceOwnerAuthentication;
        }
    }

    /* Get caller info */
    pid_t caller_pid = getppid();
    char caller_name[256];
    char cmd_line[1024];
    const char *tty = NULL;

    get_process_name(caller_pid, caller_name, sizeof(caller_name));
    get_command_line(caller_pid, cmd_line, sizeof(cmd_line));
    pam_get_item(pamh, PAM_TTY, (const void **)&tty);

    /* Build the Touch ID prompt reason */
    char reason[2048];
    if (cmd_line[0] != '\0') {
        snprintf(reason, sizeof(reason), "sudo %s requested by %s (pid %d)",
                 cmd_line, caller_name, caller_pid);
    } else {
        snprintf(reason, sizeof(reason), "sudo requested by %s (pid %d)",
                 caller_name, caller_pid);
    }

    /* Create LAContext and evaluate policy */
    id laContextClass = (id)objc_getClass("LAContext");
    if (!laContextClass) {
        return PAM_AUTH_ERR;
    }

    id context = ((id (*)(id, SEL))objc_msgSend)(laContextClass, sel_registerName("alloc"));
    context = ((id (*)(id, SEL))objc_msgSend)(context, sel_registerName("init"));

    /* Check if biometric auth is available */
    NSError *error = nil;
    BOOL canEval = ((BOOL (*)(id, SEL, long, id *))objc_msgSend)(
        context, sel_registerName("canEvaluatePolicy:error:"),
        policy, &error);

    if (!canEval) {
        return PAM_AUTH_ERR;
    }

    /* Create NSString for reason */
    id reasonStr = ((id (*)(id, SEL, const char *))objc_msgSend)(
        (id)objc_getClass("NSString"),
        sel_registerName("stringWithUTF8String:"),
        reason);

    /* Evaluate synchronously using a semaphore */
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    __block BOOL auth_success = NO;

    ((void (*)(id, SEL, long, id, void (^)(BOOL, id)))objc_msgSend)(
        context, sel_registerName("evaluatePolicy:localizedReason:reply:"),
        policy,
        reasonStr,
        ^(BOOL success, id authError) {
            auth_success = success;
            dispatch_semaphore_signal(sem);
        });

    dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);

    return auth_success ? PAM_SUCCESS : PAM_AUTH_ERR;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                               int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
                                  int argc, const char **argv) {
    return PAM_SUCCESS;
}
