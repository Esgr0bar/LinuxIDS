# Kernel-Level Intrusion Detection System (IDS)

This repository contains a simple kernel-level Intrusion Detection System (IDS) implemented as a Linux kernel module. The module monitors file accesses and network traffic, logging suspicious activities.

## Features

- **File Access Monitoring**: Hooks into the `sys_open` system call to detect and log file access attempts.
- **Network Traffic Monitoring**: Uses Netfilter hooks to inspect incoming TCP and UDP packets, logging their source and destination addresses.

## Installation

### Prerequisites

- Linux kernel headers installed.
- GNU make and GCC.

### Building the Module

1. Clone the repository:
   ```sh
   git clone https://github.com/yourusername/kernel-ids.git
   cd kernel-ids
