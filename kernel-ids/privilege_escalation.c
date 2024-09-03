#include "ids.h"
#include <linux/cred.h>

/* Monitor and log any suspicious changes in user and group IDs */
void detect_privilege_escalation(void) {
    const struct cred *cred = current_cred();

    if (cred->uid.val == 0 && cred->euid.val != 0) {
        printk(KERN_ALERT "IDS: Privilege escalation attempt detected (UID: %d, EUID: %d).\n",
               cred->uid.val, cred->euid.val);
    }

    if (cred->gid.val == 0 && cred->egid.val != 0) {
        printk(KERN_ALERT "IDS: Privilege escalation attempt detected (GID: %d, EGID: %d).\n",
               cred->gid.val, cred->egid.val);
    }
}
