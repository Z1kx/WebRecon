import subprocess
import argparse
import requests
import re
from bs4 import BeautifulSoup

# Fonction pour interroger crt.sh
def fetch_crtsh_domains(target):
    print(f"[INFO] Fetching certificate information from crt.sh for {target}...")
    url = f"https://crt.sh/?q={target}&output=json"
    response = requests.get(url)
    
    if response.status_code == 200:
        json_data = response.json()
        domains = set()
        for cert in json_data:
            if 'name_value' in cert:
                domains.update(cert['name_value'].split("\n"))
        return domains
    else:
        print("[ERROR] Failed to fetch crt.sh data.")
        return []

# Fonction pour récupérer des informations depuis web.archive.org
def fetch_web_archive_domains(target):
    print(f"[INFO] Fetching historical domains from web.archive.org for {target}...")
    url = f"https://web.archive.org/cdx/search/cdx?url={target}/*&output=json&collapse=urlkey"
    response = requests.get(url)
    
    if response.status_code == 200:
        data = response.json()
        domains = set()
        for entry in data[1:]:
            domain = re.findall(r'https?://([^/]+)/', entry[2])
            if domain:
                domains.add(domain[0])
        return domains
    else:
        print("[ERROR] Failed to fetch data from web.archive.org.")
        return []

# Fonction pour exécuter un scan Nmap sur chaque domaine
def run_nmap_http_scan(domains):
    for domain in domains:
        print(f"[INFO] Running Nmap HTTP scan on {domain}...")
        nmap_cmd = f"nmap --script http-enum {domain}"
        subprocess.run(nmap_cmd, shell=True)

# Fonction pour exécuter Nuclei sur chaque domaine
def run_nuclei_scan(domains, user_agent):
    for domain in domains:
        print(f"[INFO] Running Nuclei scan on {domain}...")
        nuclei_cmd = f"nuclei -u {domain} -H 'User-Agent: {user_agent}'"
        subprocess.run(nuclei_cmd, shell=True)

# Fonction principale
def main():
    parser = argparse.ArgumentParser(description="Automated Web Reconnaissance Tool")
    parser.add_argument("targets", nargs='+', help="Target domains or IPs")
    parser.add_argument("--user-agent", help="Custom User-Agent", default="Mozilla/5.0")
    args = parser.parse_args()

    all_domains = set()

    # Fetch domains and subdomains from crt.sh and web.archive.org
    for target in args.targets:
        crtsh_domains = fetch_crtsh_domains(target)
        archive_domains = fetch_web_archive_domains(target)
        all_domains.update(crtsh_domains)
        all_domains.update(archive_domains)

    if all_domains:
        print(f"[INFO] Found {len(all_domains)} unique domains and subdomains.")
        for domain in all_domains:
            print(f"- {domain}")
    else:
        print("[INFO] No domains found.")

    # Run Nmap scan on found domains
    run_nmap_http_scan(all_domains)

    # Run Nuclei scan on found domains
    run_nuclei_scan(all_domains, args.user_agent)

if __name__ == "__main__":
    main()
