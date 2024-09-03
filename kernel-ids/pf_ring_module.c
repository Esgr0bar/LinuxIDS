#include "ids.h"

/* PF_RING setup and configuration */
void pf_ring_setup(void) {
    int rc;
    pf_ring *ring;

    ring = pfring_open("eth0", 1500, PF_RING_PROMISC);
    if (ring == NULL) {
        printk(KERN_ERR "IDS: Unable to open PF_RING on eth0\n");
        return;
    }

    pfring_set_direction(ring, rx_and_tx_direction);
    pfring_set_socket_mode(ring, PACKET_RECV_DNA);

    rc = pfring_enable_ring(ring);
    if (rc != 0) {
        printk(KERN_ERR "IDS: Unable to enable PF_RING\n");
        pfring_close(ring);
        return;
    }

    printk(KERN_INFO "IDS: PF_RING setup complete on eth0\n");
}
