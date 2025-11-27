import random
import time
import json
import argparse
import threading
import signal
import sys
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Dict, Tuple, Optional


class Severity(Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    NOTICE = "NOTICE"
    WARN = "WARN"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"
    ALERT = "ALERT"
    EMERGENCY = "EMERGENCY"

class LogGenerator:
    def __init__(self, output_file = "linux_syslogs.log", anomaly_rate = 0.05):
        self.output_file = output_file
        self.anomaly_rate = anomaly_rate
        self.running = True
        self.current_anomaly = None
        self.anomaly_countdown = 0
        
        # Service persistence identifiers (pids)
        self.pids = {
            "sshd": random.randint(800, 1200),
            "systemd": 1,
            "kernel": 0,
            "cron": random.randint(1201, 1500),
            "NetworkManager": random.randint(1501, 1800),
            "systemd-logind": random.randint(400, 600),
            "systemd-resolved": random.randint(601, 800),
            "systemd-timesyncd": random.randint(801, 1000),
            "auditd": random.randint(1801, 2000),
            "rsyslogd": random.randint(2001, 2200),
            "dbus": random.randint(2201, 2400),
            "polkitd": random.randint(2401, 2600),
            "chronyd": random.randint(2601, 2800)
        }

        # Common IPs
        self.normal_ips = [
            "192.168.1.100", "192.168.1.101", "10.0.0.50",
            "203.0.113.45", "198.51.100.23", "172.16.0.10"
        ]

        # Suspicious IPs
        self.suspicious_ips = ["45.142.182.100", "185.220.101.45", "171.25.193.20"]

        # Users
        self.system_users = ["root", "systemd-network", "systemd-resolve", "messagebus", "syslog", "daemon"]
        self.normal_users = ["admin", "ubuntu"]
        self.suspicious_users = ["oracle", "postgres", "test123", "guest", "nobody"]

        # Critical system files
        self.system_files = [
            "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/sshd_config",
            "/boot/vmlinuz", "/etc/systemd/system.conf", "/var/log/auth.log"
        ]

        # Kernel modules
        self.kernel_modules = [
            "ext4", "nf_conntrack", "iptable_filter", "bridge",
            "overlay", "x86_pkg_temp_thermal", "intel_powerclamp"
        ]

        # System states
        self.cpu_temp = 45
        self.memory_usage = 40
        self.disk_usage = 60
        self.load_average = 0.5

    def get_timestamp(self) -> str:
        return datetime.now().strftime("%b %d %H:%M:%S") # syslog format timestamp
    
    def get_iso_timestamp(self) -> str:
        return datetime.now().isoformat() # ISO format timestamp

    def generatoe_kernel_boot_sequence(self) -> List[Dict]:
        '''System boot sequence logs'''
        logs = []

        logs.append({
            'severity': Severity.INFO,
            'service': 'kernel',
            'pid': 0,
            'message': "Linux version 5.15.0-88-generic (buildd@lcy02-amd64-051) (gcc-11)",
            'is_anomaly': False
        })
        
        logs.append({
            'severity': Severity.INFO,
            'service': 'kernel',
            'pid': 0,
            'message': "Command line: BOOT_IMAGE=/vmlinuz-5.15.0-88-generic root=/dev/mapper/ubuntu--vg-root ro quiet splash",
            'is_anomaly': False
        })
        
        logs.append({
            'severity': Severity.INFO,
            'service': 'kernel',
            'pid': 0,
            'message': f"Memory: {random.randint(8, 32)}GB RAM available",
            'is_anomaly': False
        })
        
        for module in random.sample(self.kernel_modules, 3):
            logs.append({
                'severity': Severity.INFO,
                'service': 'kernel',
                'pid': 0,
                'message': f"Loading module {module}",
                'is_anomaly': False
            })
        
        logs.append({
            'severity': Severity.INFO,
            'service': 'systemd',
            'pid': 1,
            'message': "Started Journal Service",
            'is_anomaly': False
        })
        
        return logs
    
    def generate_normal_auth_logs(self) -> List[Dict]:
        """Generate normal authentication logs (PAM, sudo, su)"""
        logs = []
        user = random.choice(self.normal_users)
        
        auth_type = random.choice(['sudo', 'su', 'ssh'])
        
        if auth_type == 'sudo':
            logs.append({
                'severity': Severity.INFO,
                'service': 'sudo',
                'pid': random.randint(3000, 4000),
                'message': f"{user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/usr/bin/apt update",
                'is_anomaly': False
            })
            
            logs.append({
                'severity': Severity.INFO,
                'service': 'sudo',
                'pid': random.randint(3000, 4000),
                'message': f"pam_unix(sudo:session): session opened for user root by {user}(uid=1000)",
                'is_anomaly': False
            })
            
        elif auth_type == 'su':
            logs.append({
                'severity': Severity.INFO,
                'service': 'su',
                'pid': random.randint(3000, 4000),
                'message': f"Successful su for root by {user}",
                'is_anomaly': False
            })
            
            logs.append({
                'severity': Severity.INFO,
                'service': 'su',
                'pid': random.randint(3000, 4000),
                'message': f"+ pts/0 {user}:root",
                'is_anomaly': False
            })
            
        else:  # ssh
            ip = random.choice(self.normal_ips)
            logs.append({
                'severity': Severity.INFO,
                'service': 'sshd',
                'pid': self.pids['sshd'],
                'message': f"Accepted publickey for {user} from {ip} port {random.randint(40000, 60000)} ssh2",
                'is_anomaly': False
            })
            
            logs.append({
                'severity': Severity.INFO,
                'service': 'systemd-logind',
                'pid': self.pids['systemd-logind'],
                'message': f"New session 12 of user {user}",
                'is_anomaly': False
            })
        
        return logs

    def generate_privilege_escalation_attempt(self) -> List[Dict]:
        """Generate privilege escalation anomaly"""
        logs = []
        user = random.choice(self.suspicious_users)
        
        # Multiple sudo attempts
        for i in range(5):
            logs.append({
                'severity': Severity.WARN,
                'service': 'sudo',
                'pid': random.randint(3000, 4000),
                'message': f"{user} : user NOT in sudoers ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash",
                'is_anomaly': True
            })
        
        # Suspicious file access
        for file in ['/etc/shadow', '/etc/sudoers']:
            logs.append({
                'severity': Severity.ALERT,
                'service': 'auditd',
                'pid': self.pids['auditd'],
                'message': f"Unauthorized access attempt to {file} by uid={random.randint(1000, 2000)}",
                'is_anomaly': True
            })
        
        # Kernel exploit attempt
        logs.append({
            'severity': Severity.CRITICAL,
            'service': 'kernel',
            'pid': 0,
            'message': f"Detected potential privilege escalation: PTRACE_POKEDATA attempt by {user}",
            'is_anomaly': True
        })
        
        return logs

    def generate_memory_pressure_anomaly(self) -> List[Dict]:
        """Generate memory pressure and OOM killer activation"""
        logs = []
        
        # Gradual memory increase
        memory_levels = [70, 80, 85, 90, 95, 98]
        for level in memory_levels:
            severity = Severity.WARN if level < 85 else Severity.ERROR if level < 95 else Severity.CRITICAL
            logs.append({
                'severity': severity,
                'service': 'kernel',
                'pid': 0,
                'message': f"Memory pressure: {level}% used ({level*80}MB / 8192MB)",
                'is_anomaly': True
            })
        
        # Page allocation failures
        logs.append({
            'severity': Severity.ERROR,
            'service': 'kernel',
            'pid': 0,
            'message': "page allocation failure: order:0, mode:0x1080020(GFP_ATOMIC), nodemask=(null)",
            'is_anomaly': True
        })
        
        # OOM killer activation
        victim_process = random.choice(['mysqld', 'java', 'python3', 'node'])
        logs.append({
            'severity': Severity.CRITICAL,
            'service': 'kernel',
            'pid': 0,
            'message': f"Out of memory: Kill process {random.randint(5000, 9000)} ({victim_process}) score 850 or sacrifice child",
            'is_anomaly': True
        })
        
        logs.append({
            'severity': Severity.ALERT,
            'service': 'kernel',
            'pid': 0,
            'message': f"Killed process {random.randint(5000, 9000)} ({victim_process}) total-vm:4048576kB",
            'is_anomaly': True
        })
        
        return logs

    def generate_disk_io_anomaly(self) -> List[Dict]:
        """Generate disk I/O errors and filesystem issues"""
        logs = []
        device = random.choice(['sda', 'sdb', 'nvme0n1'])
        
        # I/O errors
        for i in range(3):
            logs.append({
                'severity': Severity.ERROR,
                'service': 'kernel',
                'pid': 0,
                'message': f"blk_update_request: I/O error, dev {device}, sector {random.randint(1000000, 9999999)}",
                'is_anomaly': True
            })
        
        # Filesystem errors
        logs.append({
            'severity': Severity.ERROR,
            'service': 'kernel',
            'pid': 0,
            'message': f"EXT4-fs error (device {device}1): ext4_lookup:1576: inode #{random.randint(1000, 9999)}: comm systemd: corrupted",
            'is_anomaly': True
        })
        
        # Remount read-only
        logs.append({
            'severity': Severity.CRITICAL,
            'service': 'kernel',
            'pid': 0,
            'message': f"EXT4-fs ({device}1): Remounting filesystem read-only",
            'is_anomaly': True
        })
        
        # SMART warnings
        logs.append({
            'severity': Severity.WARN,
            'service': 'smartd',
            'pid': random.randint(1000, 2000),
            'message': f"Device: /dev/{device}, SMART Prefailure Attribute: 5 Reallocated_Sector_Ct changed from 100 to 90",
            'is_anomaly': True
        })
        
        return logs

    def generate_network_intrusion_attempt(self) -> List[Dict]:
        """Generate network intrusion detection logs"""
        logs = []
        attacker_ip = random.choice(self.suspicious_ips)
        
        # Port scanning detection
        for port in [22, 23, 445, 3389, 8080]:
            logs.append({
                'severity': Severity.WARN,
                'service': 'kernel',
                'pid': 0,
                'message': f"[UFW BLOCK] IN=eth0 SRC={attacker_ip} DST=10.0.0.50 PROTO=TCP DPT={port}",
                'is_anomaly': True
            })
        
        # SSH brute force
        for i in range(10):
            logs.append({
                'severity': Severity.WARN,
                'service': 'sshd',
                'pid': self.pids['sshd'],
                'message': f"Failed password for invalid user {random.choice(self.suspicious_users)} from {attacker_ip}",
                'is_anomaly': True
            })
        
        # Connection flood
        logs.append({
            'severity': Severity.ERROR,
            'service': 'kernel',
            'pid': 0,
            'message': f"possible SYN flooding on port 22. Sending cookies.",
            'is_anomaly': True
        })
        
        # IDS alert
        logs.append({
            'severity': Severity.ALERT,
            'service': 'auditd',
            'pid': self.pids['auditd'],
            'message': f"ALERT: Potential intrusion detected from {attacker_ip} - pattern matches known exploit",
            'is_anomaly': True
        })
        
        return logs

    def generate_kernel_panic_sequence(self) -> List[Dict]:
        """Generate kernel panic sequence"""
        logs = []
        
        # Warning signs
        logs.append({
            'severity': Severity.WARN,
            'service': 'kernel',
            'pid': 0,
            'message': "BUG: soft lockup - CPU#0 stuck for 22s!",
            'is_anomaly': True
        })
        
        logs.append({
            'severity': Severity.ERROR,
            'service': 'kernel',
            'pid': 0,
            'message': "general protection fault: 0000 [#1] SMP PTI",
            'is_anomaly': True
        })
        
        # Stack trace (simplified)
        logs.append({
            'severity': Severity.EMERGENCY,
            'service': 'kernel',
            'pid': 0,
            'message': "Kernel panic - not syncing: Fatal exception in interrupt",
            'is_anomaly': True
        })
        
        logs.append({
            'severity': Severity.EMERGENCY,
            'service': 'kernel',
            'pid': 0,
            'message': "CPU: 0 PID: 0 Comm: swapper/0 Not tainted 5.15.0-88-generic",
            'is_anomaly': True
        })
        
        logs.append({
            'severity': Severity.EMERGENCY,
            'service': 'kernel',
            'pid': 0,
            'message': "Hardware name: Dell Inc. PowerEdge R740/08D89F",
            'is_anomaly': True
        })
        
        return logs

    def generate_normal_system_operations(self) -> List[Dict]:
        """Generate routine system operation logs"""
        logs = []
        
        operation_type = random.choice(['cron', 'systemd', 'network', 'time', 'audit'])
        
        if operation_type == 'cron':
            logs.append({
                'severity': Severity.INFO,
                'service': 'CRON',
                'pid': self.pids['cron'],
                'message': f"(root) CMD (   cd / && run-parts --report /etc/cron.hourly)",
                'is_anomaly': False
            })
            
        elif operation_type == 'systemd':
            service = random.choice(['ssh.service', 'cron.service', 'rsyslog.service'])
            logs.append({
                'severity': Severity.INFO,
                'service': 'systemd',
                'pid': 1,
                'message': f"Started {service}",
                'is_anomaly': False
            })
            
        elif operation_type == 'network':
            interface = random.choice(['eth0', 'lo', 'docker0'])
            logs.append({
                'severity': Severity.INFO,
                'service': 'NetworkManager',
                'pid': self.pids['NetworkManager'],
                'message': f"<info> [{interface}]: state change: activated -> activated",
                'is_anomaly': False
            })
            
        elif operation_type == 'time':
            logs.append({
                'severity': Severity.INFO,
                'service': 'systemd-timesyncd',
                'pid': self.pids['systemd-timesyncd'],
                'message': f"Synchronized to time server 91.189.89.198:123 (ntp.ubuntu.com)",
                'is_anomaly': False
            })
            
        else:  # audit
            logs.append({
                'severity': Severity.NOTICE,
                'service': 'auditd',
                'pid': self.pids['auditd'],
                'message': f"Audit daemon rotating log files",
                'is_anomaly': False
            })
        
        return logs

    def generate_cpu_thermal_anomaly(self) -> List[Dict]:
        """Generate CPU thermal throttling anomaly"""
        logs = []
        
        temps = [70, 75, 80, 85, 90, 95]
        for temp in temps:
            severity = Severity.WARN if temp < 80 else Severity.ERROR if temp < 90 else Severity.CRITICAL
            logs.append({
                'severity': severity,
                'service': 'kernel',
                'pid': 0,
                'message': f"CPU0: Core temperature above threshold, cpu clock throttled (temperature: {temp}C)",
                'is_anomaly': True
            })
        
        logs.append({
            'severity': Severity.CRITICAL,
            'service': 'kernel',
            'pid': 0,
            'message': "mce: [Hardware Error]: CPU 0: Machine Check: 0 Bank 5: be00000000800400",
            'is_anomaly': True
        })
        
        return logs
    
    def format_log_line(self, log_entry: Dict) -> str:
        timestamp = self.get_timestamp()
        hostname = "linux-server"
        service = log_entry["service"]
        pid = log_entry["pid"]
        severity = log_entry["severity"].value
        message = log_entry["message"]

        # Syslog format
        if pid and pid > 0:
            line = f"{timestamp} {hostname} {service}[{pid}]: {message} {severity}"
        else:
            line = f"{timestamp} {hostname} {service}: {message} {severity}"

        # Add metadata
        metadata = f' # ANOMALY = {log_entry["is_anomaly"]}'

        return line # + metadata
    
    def write_log(self, log_entry: Dict):
        line = self.format_log_line(log_entry)

        with open(self.output_file, "a") as f:
            f.write(line + "\n")

    def generate_next_logs(self) -> List[Dict]:
        logs = []
        
        # Let anomaly sequence unroll
        if self.anomaly_countdown > 0:
            self.anomaly_countdown -= 1

            return []
        
        # Shall we generate an anomaly?
        if random.random() < self.anomaly_rate and not self.current_anomaly:
            anomaly_type = random.choice([
                "privilege_escalation",
                "memory_pressure",
                "disk_io_error",
                "network_intrusion",
                "cpu_thermal",
                "kernel_panic"
            ])

            if anomaly_type == "privilege_escalation":
                logs = self.generate_privilege_escalation_attempt()
            elif anomaly_type == "memory_pressure":
                logs = self.generate_memory_pressure_anomaly()
            elif anomaly_type == "disk_io_error":
                logs = self.generate_disk_io_anomaly()
            elif anomaly_type == "network_intrusion":
                logs = self.generate_network_intrusion_attempt()
            elif anomaly_type == "cpu_thermal":
                logs = self.generate_cpu_thermal_anomaly()
            elif anomaly_type == "kernel_panic":
                logs = self.generate_kernel_panic_sequence()

            self.current_anomaly = anomaly_type
            self.anomaly_countdown = len(logs)

        else:
            log_type = random.choices(
                ["auth", "system_ops", "boot"],
                weights = [40, 55, 5]
            )[0]

            if log_type == "auth":
                logs = self.generate_normal_auth_logs()
            elif log_type == "system_ops":
                logs = self.generate_normal_system_operations()
            elif log_type == "boot":
                if random.random() < 0.1:
                    logs = self.generatoe_kernel_boot_sequence()
                else:
                    logs = self.generate_normal_system_operations() 

            self.current_anomaly = None

        return logs
    
    def get_delay(self) -> float:
        hour = datetime.now().hour

        # Simulate different activity levels
        if 9 <= hour <= 17:  # Business hours
            base_delay = 0.5
        elif 6 <= hour <= 9 or 17 <= hour <= 22:  # Morning/Evening
            base_delay = 1.0
        else:  # Night
            base_delay = 2.0

        return base_delay * random.uniform(0.3, 3.0)
    
    def run(self):
        '''Generation loop'''
        log_queue = []

        try:
            while self.running:
                if not log_queue:
                    log_queue = self.generate_next_logs()

                if log_queue:
                    log_entry = log_queue.pop(0)
                    self.write_log(log_entry)

                time.sleep(self.get_delay())

        except KeyboardInterrupt:
            print("\n\n Exit process...")

def main():
    parser = argparse.ArgumentParser(description = "Generate synthetic Linux logs with anomaly labels")
    parser.add_argument("-o", "--output", default = "synthetic_linux_logs.log",
                        help = "Output file name (default: synthetic_linux_logs.log)")
    parser.add_argument("-r", "--anomaly-rate", type = float, default = 0.05,
                        help = "Anomaly rate 0.0-1.0 (default: 0.05)")
    parser.add_argument("--clear", action =  "store_true",
                        help = "Clear output file before starting")
    
    args = parser.parse_args()

    # Clear file
    if args.clear:
        open(args.output, "w").close()

    # Run generator
    generator = LogGenerator(
        output_file = args.output,
        anomaly_rate = args.anomaly_rate 
    )

    generator.run()

if __name__ == "__main__":
    main()