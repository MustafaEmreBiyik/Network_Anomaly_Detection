#!/usr/bin/env python3
"""
Network Anomaly Detection System - Automated Launcher
Orchestrates Docker, Kafka Consumer, Producer, and Dashboard in separate terminals.
"""

import os
import sys
import time
import socket
import platform
import subprocess
import json
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# ANSI COLORS
# ---------------------------------------------------------------------------
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
MAGENTA = '\033[95m'
BOLD = '\033[1m'
RESET = '\033[0m'

# ---------------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------------
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
PYTHON_EXE = sys.executable
PROJECT_VENV_PYTHON = os.path.join(PROJECT_ROOT, "venv", "Scripts", "python.exe")
SERVICE_ENV = {
    "PYTHONIOENCODING": "utf-8",
    "PYTHONUTF8": "1",
}


def resolve_service_python():
    """Prefer the project virtualenv for all launched services."""
    if os.path.exists(PROJECT_VENV_PYTHON):
        return PROJECT_VENV_PYTHON

    print(f"{YELLOW}⚠️  Project venv Python not found, falling back to launcher interpreter{RESET}")
    print(f"{YELLOW}   Expected: {PROJECT_VENV_PYTHON}{RESET}")
    return PYTHON_EXE


SERVICE_PYTHON_EXE = resolve_service_python()


def print_banner():
    """Print startup banner."""
    print(f"\n{BOLD}{CYAN}╔{'═'*68}╗{RESET}")
    print(f"{BOLD}{CYAN}║{' '*10}  NETWORK ANOMALY DETECTION SYSTEM LAUNCHER{' '*10}║{RESET}")
    print(f"{BOLD}{CYAN}║{' '*20}Automated Multi-Service Startup{' '*20}║{RESET}")
    print(f"{BOLD}{CYAN}╚{'═'*68}╝{RESET}\n")


def print_runtime_context():
    """Show which interpreter the launcher and child services will use."""
    print(f"{CYAN}🧭 Launcher Python: {PYTHON_EXE}{RESET}")
    print(f"{CYAN}🚀 Service Python:  {SERVICE_PYTHON_EXE}{RESET}")
    conda_env = os.getenv("CONDA_DEFAULT_ENV")
    if conda_env:
        print(f"{CYAN}🐍 Conda env:       {conda_env}{RESET}")
    if SERVICE_PYTHON_EXE != PYTHON_EXE:
        print(f"{YELLOW}⚠️  Services will be forced onto the project venv to avoid mixed environments{RESET}")
    print()


def check_os():
    """Verify running on Windows."""
    current_os = platform.system()
    print(f"{CYAN}🖥️  Operating System: {current_os}{RESET}")
    
    if current_os != "Windows":
        print(f"{RED}❌ ERROR: This script is designed for Windows only.{RESET}")
        print(f"{YELLOW}   Current OS: {current_os}{RESET}")
        print(f"{YELLOW}   Please use manual startup or adapt the script.{RESET}")
        sys.exit(1)
    
    print(f"{GREEN}✅ Windows detected - proceeding with automation{RESET}\n")


def check_docker_available():
    """Check if Docker is installed and available."""
    try:
        result = subprocess.run(
            ["docker", "--version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def start_docker_infrastructure():
    """Start Docker Compose services (Zookeeper & Kafka)."""
    print(f"{BOLD}{MAGENTA}{'─'*70}{RESET}")
    print(f"{BOLD}{MAGENTA}STEP 1: Starting Docker Infrastructure{RESET}")
    print(f"{BOLD}{MAGENTA}{'─'*70}{RESET}\n")
    
    # Check if Docker is available
    if not check_docker_available():
        print(f"{YELLOW}⚠️  Docker is not installed or not in PATH{RESET}")
        print(f"{CYAN}╭{'─'*68}╮{RESET}")
        print(f"{CYAN}│{BOLD} DOCKER KURULUM TALİMATLARI:{RESET}{' '*39}{CYAN}│{RESET}")
        print(f"{CYAN}│{' '*68}│{RESET}")
        print(f"{CYAN}│  1. Docker Desktop for Windows'u indirin:{' '*26}│{RESET}")
        print(f"{CYAN}│     https://www.docker.com/products/docker-desktop{' '*17}│{RESET}")
        print(f"{CYAN}│{' '*68}│{RESET}")
        print(f"{CYAN}│  2. Kurun ve bilgisayarı yeniden başlatın{' '*26}│{RESET}")
        print(f"{CYAN}│{' '*68}│{RESET}")
        print(f"{CYAN}│  3. Docker Desktop'ı çalıştırın{' '*36}│{RESET}")
        print(f"{CYAN}│{' '*68}│{RESET}")
        print(f"{CYAN}│  4. Bu scripti tekrar çalıştırın: python run_system.py{' '*13}│{RESET}")
        print(f"{CYAN}╰{'─'*68}╯{RESET}\n")
        
        print(f"{RED}❌ Docker olmadan sistem çalışmaz. Lütfen Docker'ı kurun.{RESET}")
        print(f"{YELLOW}Program sonlandırılıyor...{RESET}\n")
        sys.exit(1)
    
    # Check if docker-compose.yml exists
    docker_compose_path = os.path.join(PROJECT_ROOT, "docker-compose.yml")
    if not os.path.exists(docker_compose_path):
        print(f"{RED}❌ ERROR: docker-compose.yml not found!{RESET}")
        print(f"   Expected: {docker_compose_path}")
        sys.exit(1)
    
    print(f"{CYAN}📦 Launching Docker Compose...{RESET}")
    
    try:
        # Run docker-compose up -d
        result = subprocess.run(
            ["docker-compose", "up", "-d"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if result.returncode == 0:
            print(f"{GREEN}✅ Docker containers started successfully{RESET}")
            if result.stdout:
                # Print first line of output
                output_line = result.stdout.strip().split('\n')[0]
                print(f"{CYAN}   {output_line}{RESET}")
        else:
            print(f"{YELLOW}⚠️  Docker command completed with warnings{RESET}")
            if result.stderr:
                print(f"{YELLOW}   Error: {result.stderr.strip()[:200]}{RESET}")
        
        # Wait for Kafka to warm up
        print(f"\n{YELLOW}⏳ Waiting 10 seconds for Kafka to warm up...{RESET}")
        for i in range(10, 0, -1):
            print(f"   {i} seconds remaining...", end="\r")
            time.sleep(1)
        print(f"{GREEN}✅ Kafka warmup complete{RESET}" + " " * 30 + "\n")
        
    except subprocess.TimeoutExpired:
        print(f"{RED}❌ ERROR: Docker command timed out{RESET}")
        sys.exit(1)
    except FileNotFoundError:
        print(f"{RED}❌ ERROR: docker-compose command not found{RESET}")
        print(f"{YELLOW}   Try: docker compose up -d (newer Docker versions){RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"{RED}❌ ERROR: Failed to start Docker{RESET}")
        print(f"   {e}")
        sys.exit(1)


def find_running_stack_processes():
    """Return existing Python processes for this stack to avoid duplicate launches."""
    current_pid = os.getpid()
    powershell_script = rf"""
$matches = Get-CimInstance Win32_Process |
  Where-Object {{
    $_.Name -match 'python' -and
    $_.ProcessId -ne {current_pid} -and
    $_.CommandLine -and (
      $_.CommandLine -match 'src\\kafka_consumer\.py' -or
      $_.CommandLine -match 'src\\live_bridge\.py' -or
      $_.CommandLine -match 'streamlit run src\\dashboard\\app\.py'
    )
  }} |
  Select-Object ProcessId, CommandLine

if ($matches) {{
  $matches | ConvertTo-Json -Compress
}}
"""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", powershell_script],
            capture_output=True,
            text=True,
            timeout=15,
            cwd=PROJECT_ROOT,
        )
    except Exception as exc:
        print(f"{YELLOW}⚠️  Could not inspect existing stack processes: {exc}{RESET}")
        return []

    payload = result.stdout.strip()
    if result.returncode != 0 or not payload:
        return []

    try:
        parsed = json.loads(payload)
    except json.JSONDecodeError:
        return []

    if isinstance(parsed, dict):
        parsed = [parsed]
    elif not isinstance(parsed, list):
        return []

    return [
        proc for proc in parsed
        if int(proc.get("ProcessId", -1)) != current_pid
    ]


def ensure_single_stack():
    """Fail fast if another launcher or service stack is already running."""
    running = find_running_stack_processes()
    if not running:
        return

    print(f"{RED}❌ Existing pipeline processes detected. Refusing to launch a duplicate stack.{RESET}")
    for proc in running:
        pid = proc.get("ProcessId")
        cmd = (proc.get("CommandLine") or "").strip()
        print(f"{YELLOW}   PID {pid}: {cmd}{RESET}")

    pid_list = ",".join(str(proc.get("ProcessId")) for proc in running if proc.get("ProcessId"))
    if pid_list:
        print(f"\n{CYAN}Stop them first with:{RESET}")
        print(f"{CYAN}   Stop-Process -Id {pid_list}{RESET}")
    print()
    sys.exit(1)


def launch_in_new_terminal(command, title, working_dir=None, extra_env=None):
    """
    Launch a command in a new Windows terminal window.
    
    Args:
        command: Command to execute (string)
        title: Window title
        working_dir: Working directory (defaults to PROJECT_ROOT)
    
    Returns:
        subprocess.Popen object
    """
    if working_dir is None:
        working_dir = PROJECT_ROOT

    env_vars = dict(SERVICE_ENV)
    if extra_env:
        env_vars.update(extra_env)
    env_prefix = " && ".join([f'set "{key}={value}"' for key, value in env_vars.items()])

    # Windows command pattern: start cmd /k "command"
    # /k keeps the window open after command execution
    full_command = f'start "{title}" cmd /k "cd /d {working_dir} && {env_prefix} && {command}"'
    
    try:
        process = subprocess.Popen(
            full_command,
            shell=True,
            cwd=working_dir
        )
        return process
    except Exception as e:
        print(f"{RED}⚠️  Failed to launch {title}: {e}{RESET}")
        return None


def launch_services():
    """Launch Consumer, Dashboard, and Producer in separate terminals."""
    print(f"{BOLD}{MAGENTA}{'─'*70}{RESET}")
    print(f"{BOLD}{MAGENTA}STEP 2: Launching Background Services{RESET}")
    print(f"{BOLD}{MAGENTA}{'─'*70}{RESET}\n")
    
    services = []
    
    # 1. KAFKA CONSUMER
    print(f"{CYAN}🔄 Launching Kafka Consumer...{RESET}")
    consumer_process = launch_in_new_terminal(
        f'"{SERVICE_PYTHON_EXE}" src\\kafka_consumer.py',
        "NIDS - Kafka Consumer",
        PROJECT_ROOT
    )
    if consumer_process:
        services.append(("Consumer", consumer_process))
        print(f"{GREEN}✅ Consumer launched in new terminal{RESET}")
        time.sleep(2)  # Brief pause to avoid terminal spam
    
    # 2. STREAMLIT DASHBOARD
    print(f"{CYAN}📊 Launching Streamlit Dashboard...{RESET}")
    dashboard_process = launch_in_new_terminal(
        f'"{SERVICE_PYTHON_EXE}" -m streamlit run src\\dashboard\\app.py',
        "NIDS - Dashboard",
        PROJECT_ROOT
    )
    if dashboard_process:
        services.append(("Dashboard", dashboard_process))
        print(f"{GREEN}✅ Dashboard launched in new terminal{RESET}")
        print(f"{CYAN}   URL: http://localhost:8501{RESET}")
        time.sleep(2)
    
    print(f"\n{BOLD}{MAGENTA}{'─'*70}{RESET}")
    print(f"{BOLD}{MAGENTA}STEP 3: Launching Traffic Producer{RESET}")
    print(f"{BOLD}{MAGENTA}{'─'*70}{RESET}\n")
    
    # 3. LIVE BRIDGE (PRODUCER)
    print(f"{CYAN}📡 Launching Live Bridge Producer...{RESET}")
    producer_process = launch_in_new_terminal(
        f'"{SERVICE_PYTHON_EXE}" src\\live_bridge.py',
        "NIDS - Producer (Live Bridge)",
        PROJECT_ROOT
    )
    if producer_process:
        services.append(("Producer", producer_process))
        print(f"{GREEN}✅ Producer launched in new terminal{RESET}")
    
    return services


def print_system_status(services):
    """Print final system status and instructions."""
    print(f"\n{BOLD}{GREEN}{'═'*70}{RESET}")
    print(f"{BOLD}{GREEN}🚀 SYSTEM STARTUP COMPLETE{RESET}")
    print(f"{BOLD}{GREEN}{'═'*70}{RESET}\n")
    
    print(f"{CYAN}Active Services:{RESET}")
    print(f"   {GREEN}✓{RESET} Docker (Zookeeper + Kafka)")
    for service_name, _ in services:
        print(f"   {GREEN}✓{RESET} {service_name}")
    
    print(f"\n{CYAN}Service Windows:{RESET}")
    print(f"   📊 Dashboard:  http://localhost:8501")
    print(f"   🔄 Consumer:   Check 'NIDS - Kafka Consumer' terminal")
    print(f"   📡 Producer:   Check 'NIDS - Producer' terminal")
    print(f"   🐳 Docker:     docker ps")
    
    print(f"\n{YELLOW}{'─'*70}{RESET}")
    print(f"{YELLOW}⚠️  ÖNEMLİ NOTLAR:{RESET}")
    print(f"   • Her servis kendi terminal penceresinde çalışıyor")
    print(f"   • Durdurmak için: Her terminalde CTRL+C yapın")
    print(f"   • Docker'ı durdurmak için: docker-compose down")
    print(f"   • Logları ilgili terminal pencerelerinden izleyin")
    print(f"{YELLOW}{'─'*70}{RESET}\n")
    
    print(f"{BOLD}{CYAN}Sistem şimdi gerçek zamanlı ağ trafiğini işliyor!{RESET}")
    print(f"{CYAN}Bu pencereyi kapatabilirsiniz (servisler çalışmaya devam eder){RESET}\n")


@dataclass
class _CheckResult:
    ok: bool
    message: str
    fix_hint: str = ""


def _check_docker_installed() -> _CheckResult:
    try:
        r = subprocess.run(["docker", "--version"], capture_output=True, timeout=5)
        if r.returncode == 0:
            return _CheckResult(True, "Docker installed")
        return _CheckResult(False, "Docker returned non-zero", "Install Docker Desktop from https://docker.com")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return _CheckResult(False, "Docker not found in PATH", "Install Docker Desktop and restart this terminal")


def _check_kafka_port() -> _CheckResult:
    try:
        with socket.create_connection(("127.0.0.1", 9092), timeout=3):
            return _CheckResult(True, "Kafka port 9092 reachable")
    except OSError:
        return _CheckResult(
            False,
            "Cannot connect to 127.0.0.1:9092",
            "Start Kafka first: docker-compose up -d",
        )


def _check_model_files() -> _CheckResult:
    try:
        sys.path.insert(0, os.path.join(PROJECT_ROOT, "src"))
        from model_registry import MODEL_REGISTRY
        missing = [
            f"{key}: {entry['artifact_path']}"
            for key, entry in MODEL_REGISTRY.items()
            if entry["live_supported"] and not os.path.exists(entry["artifact_path"])
        ]
        if missing:
            return _CheckResult(
                False,
                f"Missing model files: {missing}",
                "Train or download models into the models/ directory",
            )
        return _CheckResult(True, "All live-supported model files present")
    except ImportError as exc:
        return _CheckResult(False, f"model_registry import failed: {exc}", "Check src/model_registry.py")


def _check_active_model() -> _CheckResult:
    active_path = os.path.join(PROJECT_ROOT, "data", "active_model.txt")
    if not os.path.exists(active_path):
        return _CheckResult(True, "active_model.txt absent — will default to Random Forest")
    try:
        sys.path.insert(0, os.path.join(PROJECT_ROOT, "src"))
        from model_registry import MODEL_REGISTRY
        with open(active_path) as f:
            key = f.read().strip()
        if key not in MODEL_REGISTRY:
            return _CheckResult(
                False,
                f"active_model.txt contains unknown key: '{key}'",
                f"Valid keys: {list(MODEL_REGISTRY.keys())}",
            )
        return _CheckResult(True, f"Active model: {key}")
    except Exception as exc:
        return _CheckResult(False, f"active_model.txt check failed: {exc}", "")


def _check_python_imports() -> _CheckResult:
    missing = []
    for pkg, import_name in [
        ("confluent-kafka", "confluent_kafka"),
        ("scikit-learn", "sklearn"),
        ("streamlit", "streamlit"),
        ("scapy", "scapy"),
    ]:
        try:
            __import__(import_name)
        except ImportError:
            missing.append(pkg)
    if missing:
        return _CheckResult(
            False,
            f"Missing Python packages: {missing}",
            f"pip install {' '.join(missing)}",
        )
    return _CheckResult(True, "Required Python packages importable")


def preflight_checks():
    """Run all startup checks and exit with a clear message on the first failure."""
    print(f"\n{CYAN}{'─'*60}{RESET}")
    print(f"{BOLD}🔍 Running preflight checks...{RESET}")

    checks = [
        ("Docker installed", _check_docker_installed),
        ("Kafka port 9092", _check_kafka_port),
        ("Model files", _check_model_files),
        ("Active model valid", _check_active_model),
        ("Python imports", _check_python_imports),
    ]

    all_ok = True
    for label, fn in checks:
        result = fn()
        status = f"{GREEN}✅{RESET}" if result.ok else f"{RED}❌{RESET}"
        print(f"  {status} {label}: {result.message}")
        if not result.ok:
            if result.fix_hint:
                print(f"     {YELLOW}Fix: {result.fix_hint}{RESET}")
            all_ok = False

    if not all_ok:
        print(f"\n{RED}[PREFLIGHT FAIL] One or more checks failed. Correct the issues above and retry.{RESET}\n")
        sys.exit(1)

    print(f"{GREEN}✅ All preflight checks passed.{RESET}\n")


def main():
    """Main orchestration function."""
    try:
        print_banner()
        check_os()
        print_runtime_context()
        preflight_checks()
        ensure_single_stack()
        start_docker_infrastructure()
        services = launch_services()
        print_system_status(services)
        
        # Keep launcher alive to show status
        print(f"{CYAN}Launcher aktif... (servisler bağımsız çalışıyor){RESET}")
        print(f"{YELLOW}Bu pencereyi kapatabilirsiniz - servisler çalışmaya devam eder.{RESET}\n")
        
        # Optional: Keep script running
        try:
            print(f"{CYAN}Çıkmak için CTRL+C yapın...{RESET}")
            while True:
                time.sleep(60)
        except KeyboardInterrupt:
            print(f"\n{GREEN}✅ Launcher kapatılıyor (servisler hala çalışıyor){RESET}")
            print(f"{CYAN}Servisler kendi terminal pencerelerinde aktif{RESET}\n")
    
    except KeyboardInterrupt:
        print(f"\n{YELLOW}⚠️  Launcher interrupted{RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{RED}❌ FATAL ERROR: {e}{RESET}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
