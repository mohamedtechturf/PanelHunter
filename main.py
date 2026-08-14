import requests
import threading
from urllib.parse import urljoin
from queue import Queue
import time
import sys
import os

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[35m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'
    WHITE = '\033[97m'
    DARK_GRAY = '\033[90m'
    
    if os.name == 'nt':
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except:
            pass

class AdminPanelFinder:
    def __init__(self, target_url, use_proxy=False, proxy_url=None, max_threads=20):
        if not target_url.startswith(('http://', 'https://')):
            self.target_url = 'https://' + target_url
        else:
            self.target_url = target_url
            
        self.use_proxy = use_proxy
        self.proxy_url = proxy_url
        self.max_threads = max_threads
        self.found_paths = []
        self.queue = Queue()
        self.lock = threading.Lock()
        self.timeout = 8
        self.max_retries = 3
        
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
    
    def create_session(self):
        """Create a new requests session (each thread gets its own)"""
        session = requests.Session()
        session.headers.update(self.headers)
        if self.use_proxy and self.proxy_url:
            session.proxies = {
                'http': self.proxy_url,
                'https': self.proxy_url
            }
        return session
    
    def load_paths(self, filename="list.txt"):
        """Load paths from file, remove duplicates"""
        try:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                paths = [line.strip() for line in f if line.strip()]
            seen = set()
            unique = []
            for p in paths:
                if p not in seen:
                    seen.add(p)
                    unique.append(p)
            return unique
        except FileNotFoundError:
            print(f"{Colors.RED}Error: {filename} not found. Please locate list.txt file.{Colors.RESET}")
            return []
    
    def test_path_with_retry(self, session, path):
        """Test a single path with retry logic. Returns (url, status, size) or None"""
        base_url = self.target_url.rstrip('/') + '/'
        url = urljoin(base_url, path)
        
        for attempt in range(1, self.max_retries + 1):
            try:
                resp = session.get(url, allow_redirects=True, timeout=self.timeout)
                size = len(resp.content)
                if resp.status_code == 200:
                    return (url, resp.status_code, size)
                else:
                    print(f"{Colors.DARK_GRAY}[{resp.status_code}] {url} ({size} bytes){Colors.RESET}")
                    return None
            except requests.exceptions.SSLError:
                if self.target_url.startswith('https://'):
                    http_url = self.target_url.replace('https://', 'http://')
                    http_full = urljoin(http_url.rstrip('/') + '/', path)
                    try:
                        resp = session.get(http_full, allow_redirects=True, timeout=self.timeout)
                        size = len(resp.content)
                        if resp.status_code == 200:
                            return (http_full, resp.status_code, size)
                        else:
                            print(f"{Colors.DARK_GRAY}[{resp.status_code}] {http_full} ({size} bytes){Colors.RESET}")
                            return None
                    except Exception:
                        pass
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
                if attempt < self.max_retries:
                    print(f"{Colors.YELLOW}[RETRY {attempt}/{self.max_retries}] {url} - {str(e)}{Colors.RESET}")
                    time.sleep(0.5)
                    continue
                else:
                    print(f"{Colors.RED}[FAILED] {url} - {str(e)}{Colors.RESET}")
                    return None
            except Exception as e:
                print(f"{Colors.RED}[ERROR] {url} - {str(e)}{Colors.RESET}")
                return None
        return None
    
    def worker(self):
        """Worker thread: creates its own session and processes queue items"""
        session = self.create_session()
        while True:
            try:
                path = self.queue.get(timeout=1)
            except:
                break
            
            result = self.test_path_with_retry(session, path)
            if result:
                url, status, size = result
                with self.lock:
                    self.found_paths.append({'url': url, 'status': status, 'size': size})
                print(f"{Colors.GREEN}[FOUND] {url} (Status: {status}, Size: {size} bytes){Colors.RESET}")
            
            self.queue.task_done()
    
    def find(self):
        """Main entry point: load paths, start threads, wait, show results"""
        paths = self.load_paths()
        if not paths:
            return False
        
        print(f"{Colors.CYAN}Loaded {len(paths)} unique paths to test{Colors.RESET}")
        print(f"{Colors.YELLOW}Testing against: {self.target_url}{Colors.RESET}")
        print(f"{Colors.BLUE}{'=' * 60}{Colors.RESET}")

        for p in paths:
            self.queue.put(p)

        threads = []
        for _ in range(self.max_threads):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            threads.append(t)

        try:
            self.queue.join()
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Scan interrupted by user. Stopping...{Colors.RESET}")
            return False

        print(f"\n{Colors.MAGENTA}{'=' * 60}{Colors.RESET}")
        if self.found_paths:
            print(f"\n{Colors.GREEN}{Colors.BOLD}Found admin panels:{Colors.RESET}")
            for res in self.found_paths:
                print(f"{Colors.GREEN}{res['url']} (Status: {res['status']}, Size: {res['size']} bytes){Colors.RESET}")

            try:
                domain = self.target_url.split('//')[-1].split('/')[0]
                filename = f"results_{domain}.txt"
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(f"PanelHunter Results for {self.target_url}\n")
                    f.write(f"Scan performed on: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("=" * 50 + "\n\n")
                    for res in self.found_paths:
                        f.write(f"{res['url']} (Status: {res['status']}, Size: {res['size']})\n")
                print(f"\n{Colors.GREEN}Results saved to: {filename}{Colors.RESET}")
            except Exception as e:
                print(f"{Colors.RED}Could not save results: {e}{Colors.RESET}")
        else:
            print(f"\n{Colors.YELLOW}No admin panels found.{Colors.RESET}")
        
        return True

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def show_whats_new():
    clear_screen()
    print(f"{Colors.BOLD}{Colors.CYAN}What's New in PanelHunter V2.0{Colors.RESET}")
    print(f"{Colors.BLUE}{'=' * 50}{Colors.RESET}")
    print(f"{Colors.GREEN}✓{Colors.RESET} {Colors.WHITE}Per thread persistent sessions, no connection overhead{Colors.RESET}")
    print(f"{Colors.GREEN}✓{Colors.RESET} {Colors.WHITE}Automatic retries (up to 3 times) on timeouts{Colors.RESET}")
    print(f"{Colors.GREEN}✓{Colors.RESET} {Colors.WHITE}Full colorized output (green = found, red = errors, gray = non-200){Colors.RESET}")
    print(f"{Colors.GREEN}✓{Colors.RESET} {Colors.WHITE}Fixed the integrated proxy{Colors.RESET}")
    print(f"{Colors.GREEN}✓{Colors.RESET} {Colors.WHITE}Thread safe result storage with Lock{Colors.RESET}")
    print(f"{Colors.GREEN}✓{Colors.RESET} {Colors.WHITE}Duplicate paths removed automatically{Colors.RESET}")
    print(f"{Colors.GREEN}✓{Colors.RESET} {Colors.WHITE}Ultra fast queue processing{Colors.RESET}")
    print(f"{Colors.GREEN}✓{Colors.RESET} {Colors.WHITE}2000+ wordlist for deep hunt{Colors.RESET}")
    
    print(f"\n{Colors.YELLOW}Press Enter to return to the main menu...{Colors.RESET}")
    input()

def show_menu():
    clear_screen()
    print(f"{Colors.BOLD}{Colors.CYAN}PanelHunter{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.RED}Made with love by MohamedTechTurf{Colors.RESET}")
    print(f"{Colors.RED}{'=' * 50}{Colors.RESET}")
    print(f"{Colors.GREEN}1.{Colors.RESET} {Colors.WHITE}Scan a website for admin panels{Colors.RESET}")
    print(f"{Colors.GREEN}2.{Colors.RESET} {Colors.WHITE}What's New{Colors.RESET}")
    print(f"{Colors.GREEN}3.{Colors.RESET} {Colors.WHITE}Exit{Colors.RESET}")
    print(f"{Colors.RED}{'=' * 50}{Colors.RESET}")
    choice = input(f"{Colors.YELLOW}Enter your choice (1-3): {Colors.RESET}").strip()
    return choice

def scan_website():
    clear_screen()
    print(f"{Colors.BOLD}{Colors.CYAN}Website Scanning{Colors.RESET}")
    print(f"{Colors.BLUE}{'=' * 50}{Colors.RESET}")
    
    target = input(f"{Colors.YELLOW}Enter target website (e.g., google.com): {Colors.RESET}").strip()
    if not target:
        print(f"{Colors.RED}No URL provided. Returning to main menu.{Colors.RESET}")
        time.sleep(2)
        return
    
    thread_input = input(f"{Colors.YELLOW}Enter number of threads (default 20): {Colors.RESET}").strip()
    threads = int(thread_input) if thread_input.isdigit() else 20
    
    proxy_input = input(f"{Colors.YELLOW}Use proxy? [Y/N]: {Colors.RESET}").strip().lower()
    use_proxy = proxy_input in ['y', 'yes']
    proxy_url = None
    
    if use_proxy:
        proxy_choice = input(f"{Colors.YELLOW}Use custom proxy or integrated proxy? [C/I]: {Colors.RESET}").strip().lower()
        if proxy_choice in ['c', 'custom']:
            proxy_url = input(f"{Colors.YELLOW}Enter proxy URL (e.g., http://proxy:port): {Colors.RESET}").strip()
        elif proxy_choice in ['i', 'integrated']:
            proxy_url = "http://80.48.119.28:8080"
            print(f"{Colors.GREEN}Using integrated proxy: {proxy_url}{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}Invalid choice. Using integrated proxy by default.{Colors.RESET}")
            proxy_url = "http://80.48.119.28:8080"
            print(f"{Colors.GREEN}Using integrated proxy: {proxy_url}{Colors.RESET}")
    
    finder = AdminPanelFinder(target, use_proxy, proxy_url, threads)
    print(f"\n{Colors.GREEN}Starting scan...{Colors.RESET}")
    start = time.time()
    finder.find()
    elapsed = time.time() - start
    print(f"\n{Colors.CYAN}Scan completed in {elapsed:.2f} seconds{Colors.RESET}")

    print(f"\n{Colors.MAGENTA}{'=' * 50}{Colors.RESET}")
    print(f"{Colors.CYAN}What would you like to do next?{Colors.RESET}")
    print(f"{Colors.GREEN}1.{Colors.RESET} {Colors.WHITE}Perform another scan{Colors.RESET}")
    print(f"{Colors.GREEN}2.{Colors.RESET} {Colors.WHITE}Return to main menu{Colors.RESET}")
    print(f"{Colors.GREEN}3.{Colors.RESET} {Colors.WHITE}Exit{Colors.RESET}")
    choice = input(f"{Colors.YELLOW}Enter your choice (1-3): {Colors.RESET}").strip()
    if choice == "1":
        scan_website()
    elif choice == "3":
        print(f"{Colors.GREEN}Goodbye!{Colors.RESET}")
        sys.exit(0)

def main():
    while True:
        choice = show_menu()
        if choice == "1":
            scan_website()
        elif choice == "2":
            show_whats_new()
        elif choice == "3":
            clear_screen()
            print(f"{Colors.GREEN}Thank you for using PanelHunter!{Colors.RESET}")
            print(f"{Colors.CYAN}Exiting...{Colors.RESET}")
            print(f"{Colors.MAGENTA}Made With Love By MTT ❤️{Colors.RESET}")
            break
        else:
            print(f"{Colors.RED}Invalid choice. Please try again.{Colors.RESET}")
            time.sleep(2)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.RED}Program interrupted by user. Goodbye!{Colors.RESET}")
        sys.exit(0)
