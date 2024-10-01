import argparse
from scanner_engine.vulnerability_scanner import VulnerabilityScanner
import cmd
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

class ScannerShell(cmd.Cmd):
    intro = (
        f"{Fore.BLUE}________                        _________                      {Style.RESET_ALL}\n"
        f"{Fore.BLUE}\\______ \\ ___.__. ____ _____   /   _____/ ____ _____    ____   {Style.RESET_ALL}\n"
        f"{Fore.BLUE} |    |  <   |  |/    \\ \\__ \\   \\_____  \\/  ___\\\\__  \\  /    \\  {Style.RESET_ALL}\n"
        f"{Fore.BLUE} |    `   \\___  |   |  \\/ __ \\_/        \\___ \\ / __ \\|   |  \\ {Style.RESET_ALL}\n"
        f"{Fore.BLUE}/_______  / ____|___|  (____  /_______  /____  >____  /___|  / {Style.RESET_ALL}\n"
        f"{Fore.BLUE}        \\/\\/         \\/     \\/        \\/     \\/     \\/     \\/  {Style.RESET_ALL}\n"
        f"{Fore.GREEN}Welcome to the DynaScan DAST CLI. Type help or ? to list commands.{Style.RESET_ALL}\n"
    )
    prompt = f"{Fore.YELLOW}(DynaScan_DAST) {Style.RESET_ALL}"

    def __init__(self, scanner):
        super().__init__()
        self.scanner = scanner

    def do_run(self, arg):
        "Run the vulnerability scans"
        print(f"{Fore.CYAN}Running vulnerability scans...{Style.RESET_ALL}")
        self.scanner.run_scans()
        print(f"{Fore.GREEN}Scans completed.{Style.RESET_ALL}")

    def do_report(self, arg):
        "Generate the vulnerability report"
        print(f"{Fore.CYAN}Generating report...{Style.RESET_ALL}")
        self.scanner.generate_report()
        print(f"{Fore.GREEN}Report generated.{Style.RESET_ALL}")

    def do_exit(self, arg):
        "Exit the CLI"
        print(f"{Fore.RED}Exiting...{Style.RESET_ALL}")
        return True

    def do_list_endpoints(self, arg):
        "List all endpoints being scanned"
        print(f"{Fore.CYAN}Listing all endpoints:{Style.RESET_ALL}")
        for endpoint in self.scanner.endpoints:
            print(f"{Fore.YELLOW}- {endpoint}{Style.RESET_ALL}")

    def do_set_base_url(self, arg):
        "Set the base URL for the scanner. Usage: set_base_url <url>"
        self.scanner.base_url = arg
        print(f"{Fore.GREEN}Base URL set to {arg}{Style.RESET_ALL}")

    def do_set_target_ip(self, arg):
        "Set the target IP for the scanner. Usage: set_target_ip <ip>"
        self.scanner.target_ip = arg
        print(f"{Fore.GREEN}Target IP set to {arg}{Style.RESET_ALL}")

    def do_show_config(self, arg):
        "Show the current configuration"
        print(f"{Fore.CYAN}Current configuration:{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Base URL: {self.scanner.base_url}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Target IP: {self.scanner.target_ip}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Endpoints:{Style.RESET_ALL}")
        for endpoint in self.scanner.endpoints:
            print(f"  {Fore.YELLOW}- {endpoint}{Style.RESET_ALL}")

    def help_run(self):
        print(f"{Fore.CYAN}Run the vulnerability scans on the specified endpoints.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Usage: run{Style.RESET_ALL}")

    def help_report(self):
        print(f"{Fore.CYAN}Generate a report of the vulnerability scan results.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Usage: report{Style.RESET_ALL}")

    def help_exit(self):
        print(f"{Fore.CYAN}Exit the CLI.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Usage: exit{Style.RESET_ALL}")

    def help_list_endpoints(self):
        print(f"{Fore.CYAN}List all endpoints that will be scanned.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Usage: list_endpoints{Style.RESET_ALL}")

    def help_set_base_url(self):
        print(f"{Fore.CYAN}Set the base URL for the scanner.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Usage: set_base_url <url>{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Example: set_base_url http://example.com{Style.RESET_ALL}")

    def help_set_target_ip(self):
        print(f"{Fore.CYAN}Set the target IP for the scanner.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Usage: set_target_ip <ip>{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Example: set_target_ip 192.168.1.1{Style.RESET_ALL}")

    def help_show_config(self):
        print(f"{Fore.CYAN}Show the current configuration of the scanner.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Usage: show_config{Style.RESET_ALL}")

    def do_help(self, arg):
        if arg:
            try:
                func = getattr(self, 'help_' + arg)
                func()
            except AttributeError:
                print(f"{Fore.RED}No help available for {arg}{Style.RESET_ALL}")
        else:
            print(f"{Fore.CYAN}Documented commands (type help <topic>):{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}========================================{Style.RESET_ALL}")
            print(f"{Fore.GREEN}exit           {Fore.CYAN}Exit the CLI{Style.RESET_ALL}")
            print(f"{Fore.GREEN}help           {Fore.CYAN}Show this help message{Style.RESET_ALL}")
            print(f"{Fore.GREEN}list_endpoints {Fore.CYAN}List all endpoints being scanned{Style.RESET_ALL}")
            print(f"{Fore.GREEN}run            {Fore.CYAN}Run the vulnerability scans{Style.RESET_ALL}")
            print(f"{Fore.GREEN}report         {Fore.CYAN}Generate the vulnerability report{Style.RESET_ALL}")
            print(f"{Fore.GREEN}set_base_url   {Fore.CYAN}Set the base URL for the scanner{Style.RESET_ALL}")
            print(f"{Fore.GREEN}set_target_ip  {Fore.CYAN}Set the target IP for the scanner{Style.RESET_ALL}")
            print(f"{Fore.GREEN}show_config    {Fore.CYAN}Show the current configuration{Style.RESET_ALL}")

    def default(self, line):
        commands = ['run', 'report', 'exit', 'list_endpoints', 'set_base_url', 'set_target_ip', 'show_config', 'help']
        matches = [cmd for cmd in commands if line in cmd]
        if matches:
            print(f"{Fore.YELLOW}Did you mean:{Style.RESET_ALL}")
            for match in matches:
                print(f"{Fore.GREEN}  {match}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Unknown command: {line}{Style.RESET_ALL}")
            print(f"Type {Fore.GREEN}help{Style.RESET_ALL} to see the list of available commands.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Vulnerability Scanner CLI")
    parser.add_argument("--interactive", action="store_true", help="Run in interactive mode")
    args = parser.parse_args()

    endpoints = {
        "WebGoat/SqlInjection/attack": {"last_name": ""},
        "WebGoat/SqlInjectionAdvanced/lesson1": {"last_name": ""},
        "WebGoat/SqlInjectionAdvanced/lesson2": {"last_name": ""},
        "WebGoat/SqlInjectionAdvanced/lesson3": {"last_name": ""},
        "WebGoat/SqlInjectionAdvanced/challenge": {"username_reg": "Tom"},
        "WebGoat/XSS/attack": {"q": "test"},
        "WebGoat/Auth/login": {"username": "test", "password": "test"},
        "WebGoat/SensitiveData": {},
        "WebGoat/AccessControl/attack": {},
        "WebGoat/login": {},
        "WebGoat/CSRF": {},
        "WebGoat/SSRF": {},
        "WebGoat/InsecureDeserialization/attack": {"serialized_data": ""},
        "WebGoat/SerializationBasics/attack": {"input": ""}
    }

    base_url = "http://127.0.0.1:8080/"
    target_ip = "127.0.0.1"
    host_info_url = "http://127.0.0.1:8080/WebGoat/login"

    scanner = VulnerabilityScanner(base_url, endpoints, target_ip, host_info_url)

    if args.interactive:
        ScannerShell(scanner).cmdloop()
    else:
        scanner.run_scans()
        scanner.generate_report()
