# Kernel-Level Intrusion Detection System (IDS)

This repository contains a comprehensive kernel-level Intrusion Detection System (IDS) designed to detect and mitigate security threats such as buffer overflows, rootkits, and unauthorized kernel interactions. The system is enhanced with advanced features like eBPF-based packet filtering, PF_RING for high-speed packet acquisition, and a user-level daemon for efficient communication and management.

## Features

- **File Access Monitoring**: Hooks into the `sys_open` system call to detect and log file access attempts.
- **Network Traffic Monitoring**: Utilizes Netfilter hooks and eBPF for in-kernel packet filtering and inspection.
- **Buffer Overflow Detection**: Monitors stack canary values to detect potential stack overflows.
- **Rootkit Detection**: Verifies the integrity of the syscall table to detect modifications indicative of rootkits.
- **Unauthorized Kernel Interaction Detection**: Monitors the system call table and checks for hidden processes.
- **Kernel Integrity Monitoring**: Ensures the integrity of critical kernel structures such as the syscall table, IDT, and GDT.
- **Runtime Kernel Integrity Checks**: Implements Linux Integrity Measurement Architecture (IMA) for runtime integrity verification.
- **Control Flow Integrity (CFI)**: Protects against control-flow hijacking attacks.
- **Memory Protection Enhancements**: Utilizes hardened memory allocators and Kernel Address Space Layout Randomization (KASLR).
- **Syscall Filtering and Restriction**: Implements seccomp filters to restrict dangerous syscalls and prevent privilege escalation.
- **Detection of Privilege Escalation Attempts**: Monitors user and group ID changes, particularly focusing on transitions to privileged states.
- **High-Speed Packet Acquisition**: Uses PF_RING for efficient packet capture on high-speed networks, ensuring low latency and high throughput.
- **User-Level Daemon**: A user-level daemon communicates with the kernel module via Netlink sockets, handling IDS operations, logging, and configuration management.

## Installation

### Prerequisites

1. **Linux Kernel Headers**: Ensure that the kernel headers are installed on your system.
   ```sh
   sudo apt-get install linux-headers-$(uname -r)


2. **GNU Make and GCC**: Ensure you have the necessary tools for building the module.
```sh
sudo apt-get install build-essential
```

3. **PF_RING and eBPF Tools**: Install PF_RING and eBPF tools.

```sh
sudo apt-get install pfring
sudo apt-get install bpfcc-tools
```

4. **Netlink Library**: Install the Netlink library for the user-level daemon.

```sh
sudo apt-get install libnl-3-dev libnl-genl-3-dev
```

5. **Building the Kernel Module**
Clone the Repository:

```sh
git clone https://github.com/Esgr0bar/kernel-ids.git
cd kernel-ids
```

**Build the Kernel Module**:

```sh
make
```

**Load the Kernel Module**:

```sh
sudo insmod ids_module.ko
```

6. **Building and Running the User-Level Daemon**
**Compile the User-Level Daemon**:

```sh
gcc -o ids_daemon ids_daemon.c -lnl-3 -lnl-genl-3
```

**Run the Daemon**:

```sh
sudo ./ids_daemon
```

7. **Unloading the Kernel Module**
**To unload the module from the kernel**:

```sh
sudo rmmod ids_module
```

8. **Cleaning Up**
**To clean the built files**:

```sh
make clean
```

## Explanation of the System
   ### Overview
   
This Kernel-Level IDS project integrates multiple advanced security features directly into the Linux kernel to detect and mitigate security threats efficiently. By leveraging eBPF, the system can perform packet filtering within the kernel, reducing the overhead typically associated with user-space detection methods. PF_RING is utilized for high-speed packet acquisition, making the system capable of handling large volumes of network traffic with minimal packet loss.

The system also includes a user-level daemon, inspired by the principles of efficient remote procedure calls (RPC) as described in the paper "Implementing Efficient Remote Procedure Calls in Networked Systems" by Anirudh Jain et al. This daemon interacts with the kernel module using Netlink sockets, enabling efficient communication and management of IDS operations from user space.

**Sources and Inspirations**
This project was inspired and guided by several key sources:

iKern: Advanced Intrusion Detection and Prevention at the Kernel Level Using eBPF: This paper provided the foundation for using eBPF and PF_RING in the IDS, allowing for efficient in-kernel packet filtering and high-speed data acquisition.

Créer un Système de Détection d'Intrusion (IDS) au Niveau Kernel : Un Guide Simplifié by Wardeners

Implementing Efficient Remote Procedure Calls in Networked Systems by Anirudh Jain et al.: This paper inspired the creation of a user-level daemon that interacts efficiently with the kernel module, optimizing the communication and control mechanisms between user space and kernel space.

These sources collectively contributed to the development of a robust, efficient, and scalable IDS capable of operating in high-performance network environments.
