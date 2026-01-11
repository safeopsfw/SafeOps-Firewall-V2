#!/usr/bin/env python3
"""
SafeOps Traffic Logger - Unified Orchestrator
==============================================

Coordinates all logging components for comprehensive network monitoring:
- realtime_capture.py: Packet capture with TLS decryption
- ids_writer.py: IDS/IPS alert generation
- firewall_writer.py: Firewall log generation
- netflow_writer.py: NetFlow east-west/north-south splitting

Features:
- ✅ Parallel process management with health monitoring
- ✅ Beautiful real-time dashboard
- ✅ Automatic restart on failures
- ✅ Resource monitoring (CPU, memory, disk)
- ✅ Graceful shutdown with cleanup
- ✅ Performance metrics and statistics
- ✅ Color-coded status indicators
"""

import os
import sys
import time
import signal
import psutil
import subprocess
import threading
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from collections import deque
from dataclasses import dataclass, field

# ==================== Color Support ====================
try:
    import colorama
    from colorama import Fore, Back, Style

    colorama.init(autoreset=True)
    COLORS_ENABLED = True
except ImportError:
    COLORS_ENABLED = False


    class Fore:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ""


    class Back:
        BLACK = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ""


    class Style:
        BRIGHT = DIM = RESET_ALL = ""

# ==================== PATHS ====================
BASE_DIR = Path(__file__).resolve().parents[3]  # safeops/
LOGS_DIR = BASE_DIR / 'logs'
BACKEND_DIR = BASE_DIR / 'backend'
MODULES_DIR = BACKEND_DIR / 'modules'
LOGGING_ENGINE_DIR = MODULES_DIR / 'logging_engine'

# Component scripts
CAPTURE_SCRIPT = LOGGING_ENGINE_DIR / 'capture' / 'realtime_capture.py'
IDS_SCRIPT = LOGGING_ENGINE_DIR / 'storage' / 'ids_writer.py'
FIREWALL_SCRIPT = LOGGING_ENGINE_DIR / 'storage' / 'firewall_writer.py'
NETFLOW_SCRIPT = LOGGING_ENGINE_DIR / 'storage' / 'netflow_writer.py'

# Log files to monitor
LOG_FILES = {
    'packets': LOGS_DIR / 'network_packets.log',
    'ids': LOGS_DIR / 'ids' / 'ids.log',
    'firewall': LOGS_DIR / 'firewall' / 'firewall.log',
    'netflow_ew': LOGS_DIR / 'netflow' / 'east_west.log',
    'netflow_ns': LOGS_DIR / 'netflow' / 'north_south.log',
}

# ==================== CONFIGURATION ====================
DASHBOARD_REFRESH_INTERVAL = 30  # seconds
HEALTH_CHECK_INTERVAL = 15.0  # seconds
RESTART_DELAY = 3.0  # seconds before restarting failed process
MAX_RESTART_ATTEMPTS = 5
RESTART_WINDOW = 300  # 5 minutes

# Process startup order and dependencies
PROCESS_ORDER = [
    'capture',  # Must start first (generates logs)
    'ids',  # Can start once capture is running
    'firewall',  # Can start once capture is running
    'netflow',  # Can start once capture is running
]


# ==================== DATA STRUCTURES ====================
@dataclass
class ProcessStats:
    """Statistics for a managed process"""
    name: str
    pid: Optional[int] = None
    start_time: Optional[float] = None
    restart_count: int = 0
    restart_times: deque = field(default_factory=lambda: deque(maxlen=10))
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    status: str = 'stopped'  # stopped, starting, running, failed, restarting
    last_error: Optional[str] = None

    def elapsed_time(self) -> float:
        """Get elapsed time in seconds"""
        if self.start_time:
            return time.time() - self.start_time
        return 0.0

    def restart_rate(self) -> float:
        """Calculate restart rate (restarts per minute)"""
        if len(self.restart_times) < 2:
            return 0.0

        time_span = self.restart_times[-1] - self.restart_times[0]
        if time_span > 0:
            return (len(self.restart_times) / time_span) * 60
        return 0.0


@dataclass
class LogStats:
    """Statistics for a log file"""
    path: Path
    size_mb: float = 0.0
    line_count: int = 0
    last_modified: Optional[float] = None
    write_rate: float = 0.0  # lines per second
    last_line_count: int = 0
    last_check_time: float = field(default_factory=time.time)

    def update(self):
        """Update statistics"""
        try:
            if self.path.exists():
                stat = self.path.stat()
                self.size_mb = stat.st_size / 1024 / 1024
                self.last_modified = stat.st_mtime

                # Count lines (sample for large files)
                if stat.st_size < 10 * 1024 * 1024:  # < 10MB
                    with open(self.path, 'r', encoding='utf-8', errors='ignore') as f:
                        self.line_count = sum(1 for _ in f)
                else:
                    # Estimate for large files
                    with open(self.path, 'rb') as f:
                        sample = f.read(1024 * 1024)  # 1MB sample
                        lines_in_sample = sample.count(b'\n')
                        self.line_count = int((stat.st_size / len(sample)) * lines_in_sample)

                # Calculate write rate
                now = time.time()
                elapsed = now - self.last_check_time
                if elapsed > 0:
                    self.write_rate = (self.line_count - self.last_line_count) / elapsed

                self.last_line_count = self.line_count
                self.last_check_time = now
        except Exception:
            pass


# ==================== PROCESS MANAGER ====================
class ProcessManager:
    """Manages logging component processes"""

    def __init__(self):
        self.processes: Dict[str, subprocess.Popen] = {}
        self.stats: Dict[str, ProcessStats] = {
            'capture': ProcessStats('Packet Capture'),
            'ids': ProcessStats('IDS Writer'),
            'firewall': ProcessStats('Firewall Writer'),
            'netflow': ProcessStats('NetFlow Splitter'),
        }
        self.log_stats: Dict[str, LogStats] = {
            name: LogStats(path) for name, path in LOG_FILES.items()
        }
        self.stop_event = threading.Event()
        self.lock = threading.Lock()

    def start_process(self, name: str) -> bool:
        """Start a logging component process"""
        try:
            script_map = {
                'capture': CAPTURE_SCRIPT,
                'ids': IDS_SCRIPT,
                'firewall': FIREWALL_SCRIPT,
                'netflow': NETFLOW_SCRIPT,
            }

            script = script_map.get(name)
            if not script or not script.exists():
                self.stats[name].status = 'failed'
                self.stats[name].last_error = f"Script not found: {script}"
                return False

            # Start process
            self.stats[name].status = 'starting'

            process = subprocess.Popen(
                [sys.executable, str(script)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(BASE_DIR),
                env=os.environ.copy(),
            )

            with self.lock:
                self.processes[name] = process
                self.stats[name].pid = process.pid
                self.stats[name].start_time = time.time()
                self.stats[name].status = 'running'

            return True

        except Exception as e:
            self.stats[name].status = 'failed'
            self.stats[name].last_error = str(e)
            return False

    def stop_process(self, name: str, timeout: float = 10.0):
        """Stop a process gracefully with proper cleanup"""
        with self.lock:
            process = self.processes.get(name)

            if process and process.poll() is None:
                try:
                    # Try graceful shutdown (SIGTERM)
                    process.terminate()

                    # Wait for process to exit
                    try:
                        process.wait(timeout=timeout)
                        self.stats[name].status = 'stopped'
                    except subprocess.TimeoutExpired:
                        # Force kill if still running (SIGKILL)
                        print(
                            f"{Fore.YELLOW}⚠️  {self.stats[name].name} not responding, forcing shutdown...{Style.RESET_ALL}")
                        process.kill()
                        process.wait()
                        self.stats[name].status = 'killed'

                    self.stats[name].pid = None

                    # Clean up any zombie processes
                    try:
                        process.communicate(timeout=1)
                    except:
                        pass

                except Exception as e:
                    self.stats[name].last_error = f"Stop error: {e}"
                    # Force kill as last resort
                    try:
                        process.kill()
                        process.wait()
                    except:
                        pass

            if name in self.processes:
                del self.processes[name]

    def restart_process(self, name: str):
        """Restart a failed process"""
        stats = self.stats[name]

        # Check restart rate
        now = time.time()
        stats.restart_times.append(now)

        # Too many restarts in short time?
        if len(stats.restart_times) >= MAX_RESTART_ATTEMPTS:
            time_span = stats.restart_times[-1] - stats.restart_times[0]
            if time_span < RESTART_WINDOW:
                stats.status = 'failed'
                stats.last_error = f"Too many restarts ({MAX_RESTART_ATTEMPTS} in {time_span:.0f}s)"
                return False

        stats.status = 'restarting'
        stats.restart_count += 1

        # Stop old process
        self.stop_process(name, timeout=5.0)

        # Wait before restart
        time.sleep(RESTART_DELAY)

        # Start new process
        return self.start_process(name)

    def check_health(self):
        """Check health of all processes"""
        with self.lock:
            for name, process in list(self.processes.items()):
                stats = self.stats[name]

                # Check if process is still running
                if process.poll() is not None:
                    # Process died
                    stats.status = 'failed'
                    stats.last_error = f"Process exited with code {process.returncode}"
                    stats.pid = None

                    # Attempt restart
                    threading.Thread(
                        target=self.restart_process,
                        args=(name,),
                        daemon=True
                    ).start()
                    continue

                # Update resource usage
                try:
                    proc = psutil.Process(process.pid)
                    stats.cpu_percent = proc.cpu_percent(interval=0.1)
                    stats.memory_mb = proc.memory_info().rss / 1024 / 1024
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

    def update_log_stats(self):
        """Update statistics for all log files"""
        for log_stats in self.log_stats.values():
            log_stats.update()

    def start_all(self):
        """Start all processes in correct order"""
        for name in PROCESS_ORDER:
            if self.start_process(name):
                print(f"{Fore.GREEN}✓{Fore.RESET} Started {self.stats[name].name}")
                # Wait a bit between starts
                time.sleep(1.0)
            else:
                print(f"{Fore.RED}✗{Fore.RESET} Failed to start {self.stats[name].name}")

    def stop_all(self):
        """Stop all processes"""
        self.stop_event.set()

        # Stop in reverse order
        for name in reversed(PROCESS_ORDER):
            if name in self.processes:
                print(f"{Fore.YELLOW}⏸{Fore.RESET}  Stopping {self.stats[name].name}...")
                self.stop_process(name)

    def get_system_stats(self) -> Dict[str, float]:
        """Get system resource statistics"""
        try:
            return {
                'cpu_percent': psutil.cpu_percent(interval=0.1),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_percent': psutil.disk_usage(str(LOGS_DIR)).percent,
            }
        except Exception:
            return {
                'cpu_percent': 0.0,
                'memory_percent': 0.0,
                'disk_percent': 0.0,
            }


# ==================== DASHBOARD ====================
class Dashboard:
    """Real-time monitoring dashboard"""

    def __init__(self, manager: ProcessManager):
        self.manager = manager
        self.start_time = time.time()

    def clear_screen(self):
        """Clear terminal screen"""
        # Use ANSI escape codes for smooth in-place update (no flicker)
        if os.name == 'nt':
            os.system('cls')
        else:
            # Move cursor to home position and clear from there
            print('\033[H\033[J', end='', flush=True)

    def format_duration(self, seconds: float) -> str:
        """Format duration in human-readable format"""
        if seconds < 60:
            return f"{int(seconds)}s"
        elif seconds < 3600:
            return f"{int(seconds / 60)}m {int(seconds % 60)}s"
        else:
            hours = int(seconds / 3600)
            minutes = int((seconds % 3600) / 60)
            return f"{hours}h {minutes}m"

    def format_size(self, mb: float) -> str:
        """Format size in human-readable format"""
        if mb < 1:
            return f"{mb * 1024:.1f}KB"
        elif mb < 1024:
            return f"{mb:.1f}MB"
        else:
            return f"{mb / 1024:.2f}GB"

    def get_status_color(self, status: str) -> str:
        """Get color for status"""
        colors = {
            'running': Fore.GREEN,
            'starting': Fore.CYAN,
            'stopped': Fore.YELLOW,
            'failed': Fore.RED,
            'restarting': Fore.MAGENTA,
        }
        return colors.get(status, Fore.WHITE)

    def render(self):
        """Render dashboard"""
        self.clear_screen()

        uptime = time.time() - self.start_time
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Header
        print(f"{Fore.CYAN}{Style.BRIGHT}{'=' * 80}")
        print(f"{' ' * 20}SAFEOPS TRAFFIC LOGGER - MONITORING DASHBOARD")
        print(f"{'=' * 80}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Status: {Fore.GREEN}RUNNING{Fore.WHITE} | "
              f"Uptime: {Fore.CYAN}{self.format_duration(uptime)}{Fore.WHITE} | "
              f"Time: {Fore.YELLOW}{now}{Style.RESET_ALL}")
        print()

        # System Resources
        sys_stats = self.manager.get_system_stats()
        print(f"{Fore.YELLOW}{'─' * 80}")
        print(f"{Style.BRIGHT}SYSTEM RESOURCES{Style.RESET_ALL}")
        print(f"{'─' * 80}{Style.RESET_ALL}")

        cpu_color = Fore.GREEN if sys_stats['cpu_percent'] < 70 else (
            Fore.YELLOW if sys_stats['cpu_percent'] < 90 else Fore.RED
        )
        mem_color = Fore.GREEN if sys_stats['memory_percent'] < 70 else (
            Fore.YELLOW if sys_stats['memory_percent'] < 90 else Fore.RED
        )
        disk_color = Fore.GREEN if sys_stats['disk_percent'] < 70 else (
            Fore.YELLOW if sys_stats['disk_percent'] < 90 else Fore.RED
        )

        print(f"CPU:  {cpu_color}{sys_stats['cpu_percent']:>5.1f}%{Fore.RESET}  "
              f"Memory: {mem_color}{sys_stats['memory_percent']:>5.1f}%{Fore.RESET}  "
              f"Disk: {disk_color}{sys_stats['disk_percent']:>5.1f}%{Fore.RESET}")
        print()

        # Process Status
        print(f"{Fore.CYAN}{'─' * 80}")
        print(f"{Style.BRIGHT}PROCESS STATUS{Style.RESET_ALL}")
        print(f"{'─' * 80}{Style.RESET_ALL}")
        print(f"{'COMPONENT':<20} {'STATUS':<12} {'PID':<8} {'UPTIME':<10} "
              f"{'CPU%':<7} {'MEM(MB)':<10} {'RESTARTS':<10}")
        print(f"{Fore.WHITE}{'─' * 80}{Style.RESET_ALL}")

        for name in PROCESS_ORDER:
            stats = self.manager.stats[name]
            status_color = self.get_status_color(stats.status)

            pid_str = str(stats.pid) if stats.pid else '-'
            uptime_str = self.format_duration(stats.elapsed_time()) if stats.start_time else '-'
            cpu_str = f"{stats.cpu_percent:.1f}%" if stats.cpu_percent > 0 else '-'
            mem_str = f"{stats.memory_mb:.1f}" if stats.memory_mb > 0 else '-'
            restart_str = f"{stats.restart_count}" if stats.restart_count > 0 else '-'

            print(f"{Fore.WHITE}{stats.name:<20} "
                  f"{status_color}{stats.status.upper():<12}{Fore.RESET} "
                  f"{Fore.CYAN}{pid_str:<8}{Fore.RESET} "
                  f"{Fore.GREEN}{uptime_str:<10}{Fore.RESET} "
                  f"{Fore.YELLOW}{cpu_str:<7}{Fore.RESET} "
                  f"{Fore.MAGENTA}{mem_str:<10}{Fore.RESET} "
                  f"{Fore.RED if stats.restart_count > 0 else Fore.GREEN}{restart_str:<10}{Fore.RESET}")

            if stats.last_error:
                print(f"  {Fore.RED}└─ Error: {stats.last_error[:60]}{Fore.RESET}")

        print()

        # Log Files
        print(f"{Fore.GREEN}{'─' * 80}")
        print(f"{Style.BRIGHT}LOG FILES{Style.RESET_ALL}")
        print(f"{'─' * 80}{Style.RESET_ALL}")
        print(f"{'FILE':<25} {'SIZE':<12} {'LINES':<15} {'WRITE RATE':<15} {'MODIFIED':<13}")
        print(f"{Fore.WHITE}{'─' * 80}{Style.RESET_ALL}")

        for name, log_stats in self.manager.log_stats.items():
            if log_stats.path.exists():
                size_str = self.format_size(log_stats.size_mb)
                lines_str = f"{log_stats.line_count:,}"
                rate_str = f"{log_stats.write_rate:.1f}/s" if log_stats.write_rate > 0 else '-'

                if log_stats.last_modified:
                    mod_time = datetime.fromtimestamp(log_stats.last_modified)
                    mod_str = mod_time.strftime('%H:%M:%S')
                else:
                    mod_str = '-'

                print(f"{Fore.WHITE}{name:<25} "
                      f"{Fore.CYAN}{size_str:<12} "
                      f"{Fore.GREEN}{lines_str:<15} "
                      f"{Fore.YELLOW}{rate_str:<15} "
                      f"{Fore.MAGENTA}{mod_str:<13}{Fore.RESET}")
            else:
                print(f"{Fore.WHITE}{name:<25} {Fore.RED}NOT FOUND{Fore.RESET}")

        print()

        # Footer
        print(f"{Fore.CYAN}{'─' * 80}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Press Ctrl+C to stop all processes and exit{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}")


# ==================== MONITORING THREADS ====================
def health_monitor_thread(manager: ProcessManager):
    """Health monitoring thread"""
    while not manager.stop_event.is_set():
        manager.check_health()
        time.sleep(HEALTH_CHECK_INTERVAL)


def log_stats_thread(manager: ProcessManager):
    """Log statistics update thread"""
    while not manager.stop_event.is_set():
        manager.update_log_stats()
        time.sleep(DASHBOARD_REFRESH_INTERVAL)


def dashboard_thread(manager: ProcessManager, dashboard: Dashboard):
    """Dashboard rendering thread"""
    while not manager.stop_event.is_set():
        dashboard.render()
        time.sleep(DASHBOARD_REFRESH_INTERVAL)


# ==================== SIGNAL HANDLERS ====================
manager_instance = None


def signal_handler(signum, frame):
    """Handle shutdown signals with proper cleanup"""
    global manager_instance

    signal_names = {
        signal.SIGINT: 'SIGINT (Ctrl+C)',
        signal.SIGTERM: 'SIGTERM'
    }
    signal_name = signal_names.get(signum, f'Signal {signum}')

    print(f"\n\n{Fore.YELLOW}{'!' * 80}")
    print(f"⚠️  Received {signal_name} - Initiating emergency shutdown...")
    print(f"{'!' * 80}{Style.RESET_ALL}\n")

    if manager_instance:
        try:
            manager_instance.stop_all()
        except Exception as e:
            print(f"{Fore.RED}Error during shutdown: {e}{Style.RESET_ALL}")
            # Force exit if cleanup fails
            print(f"{Fore.RED}Forcing exit...{Style.RESET_ALL}")
            os._exit(1)

    print(f"{Fore.GREEN}Exiting safely...{Style.RESET_ALL}\n")
    sys.exit(0)


def cleanup_on_exit():
    """Cleanup function called on normal exit"""
    global manager_instance

    if manager_instance and not manager_instance.stop_event.is_set():
        print(f"\n{Fore.YELLOW}Performing final cleanup...{Style.RESET_ALL}")
        manager_instance.stop_all()


# ==================== MAIN ====================
def main():
    """Main entry point"""
    global manager_instance

    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Register cleanup function for normal exit
    import atexit
    atexit.register(cleanup_on_exit)

    print(f"{Fore.CYAN}{Style.BRIGHT}")
    print("=" * 80)
    print(" " * 20 + "SAFEOPS TRAFFIC LOGGER")
    print(" " * 15 + "Unified Network Monitoring System")
    print("=" * 80)
    print(f"{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Initializing components...{Style.RESET_ALL}\n")

    # Verify scripts exist
    missing_scripts = []
    for name, script in [
        ('Packet Capture', CAPTURE_SCRIPT),
        ('IDS Writer', IDS_SCRIPT),
        ('Firewall Writer', FIREWALL_SCRIPT),
        ('NetFlow Splitter', NETFLOW_SCRIPT),
    ]:
        if not script.exists():
            missing_scripts.append((name, script))
            print(f"{Fore.RED}✗{Fore.RESET} {name}: {script} not found")
        else:
            print(f"{Fore.GREEN}✓{Fore.RESET} {name}: {script}")

    if missing_scripts:
        print(f"\n{Fore.RED}Error: Missing required scripts. Please check installation.{Style.RESET_ALL}")
        return 1

    print()

    # Ensure log directories exist
    for log_path in LOG_FILES.values():
        log_path.parent.mkdir(parents=True, exist_ok=True)

    # Create manager
    manager_instance = ProcessManager()
    dashboard = Dashboard(manager_instance)

    # Start all processes
    print(f"{Fore.CYAN}Starting logging components...{Style.RESET_ALL}\n")
    manager_instance.start_all()

    print(f"\n{Fore.GREEN}All components started successfully!{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Launching monitoring dashboard in 3 seconds...{Style.RESET_ALL}\n")
    time.sleep(3)

    # Start monitoring threads
    health_thread = threading.Thread(
        target=health_monitor_thread,
        args=(manager_instance,),
        daemon=True,
        name='HealthMonitor'
    )
    health_thread.start()

    stats_thread = threading.Thread(
        target=log_stats_thread,
        args=(manager_instance,),
        daemon=True,
        name='LogStatsMonitor'
    )
    stats_thread.start()

    dash_thread = threading.Thread(
        target=dashboard_thread,
        args=(manager_instance, dashboard),
        daemon=True,
        name='DashboardRenderer'
    )
    dash_thread.start()

    # Keep main thread alive
    try:
        while not manager_instance.stop_event.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Keyboard interrupt detected...{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}Unexpected error: {e}{Style.RESET_ALL}")
    finally:
        # Ensure cleanup happens
        if manager_instance and not manager_instance.stop_event.is_set():
            manager_instance.stop_all()

    print(f"{Fore.GREEN}✓ All components stopped successfully{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Goodbye!{Style.RESET_ALL}\n")

    return 0


if __name__ == '__main__':
    sys.exit(main())