# Kernel-Level Intrusion Detection System (IDS)

This repository contains a kernel-level Intrusion Detection System (IDS) with enhanced features for detecting buffer overflows, rootkits, and unauthorized kernel interactions.

## Features

- **File Access Monitoring**: Hooks into the `sys_open` system call to detect and log file access attempts.
- **Network Traffic Monitoring**: Uses Netfilter hooks to inspect incoming TCP and UDP packets, logging their source and destination addresses.
- **Buffer Overflow Detection**: Monitors stack canary values to detect potential stack overflows.
- **Rootkit Detection**: Verifies the integrity of the syscall table to detect modifications typical of rootkits.
- **Unauthorized Kernel Interaction Detection**: Monitors the system call table and checks for hidden processes.

## Installation

### Prerequisites

- Linux kernel headers installed.
- GNU make and GCC.

### Building the Module

1. Clone the repository:
   ```sh
   git clone https://github.com/yourusername/kernel-ids.git
   cd kernel-ids
