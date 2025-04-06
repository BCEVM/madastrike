#!/usr/bin/env python3

import os
import re
import argparse
import aiohttp
import asyncio
import subprocess
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from datetime import datetime

class MadaStrike:
    def __init__(self, target):
        self.target = target if target.startswith("http") else f"http://{target}"
        self.visited = set()
        self.crawled_urls = []
        self.sensitive_urls = []
        self.session = None
        self.max_urls = 100
        self.setup_dirs()
        self.sensitive_patterns = self.load_sensitive_patterns()

    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self.session:
            await self.session.close()

    def setup_dirs(self):
        os.makedirs("results/scans", exist_ok=True)
        os.makedirs("results/exploits", exist_ok=True)
        os.makedirs("results/loot", exist_ok=True)
        os.makedirs("results/downloads", exist_ok=True)
        os.makedirs("payloads", exist_ok=True)
        os.makedirs("results", exist_ok=True)

    def load_sensitive_patterns(self):
        return [
            r".env$", r"wp-config.php$", r"config\.(php|json|yml|xml)$", r".htaccess$",
            r".htpasswd$", r"settings.py$", r"application.properties$", r".bak$",
            r".old$", r".backup$", r".swp$", r".swo$", r".tmp$", r".temp$",
            r"access.log$", r"error.log$", r"debug.log$", r"auth.log$", r".log$",
            r".sql$", r".db$", r".sqlite$", r".mdb$", r"dump.sql$", r"backup.sql$",
            r"id_rsa$", r"id_dsa$", r".pem$", r".key$", r"credentials.json$",
            r"passwords.txt$", r"oauth.json$", r".git/?", r".svn/?", r".hg/?",
            r"admin\\.php$", r"adminpanel\\.", r"phpinfo\\.php$", r"debug\\.php$",
            r"test\\.php$", r"package-lock\\.json$", r"yarn\\.lock$", r"composer\.(json|lock)$",
            r"Dockerfile$", r"docker-compose\\.yml$", r".idea/?", r".vscode/?",
            r".project$", r".classpath$", r".DS_Store$", r"thumbs\\.db$", r".inc$",
            r".ini$", r"robots\\.txt$"
        ]

    def run_command(self, cmd):
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return result.stdout
        except Exception as e:
            print(f"[-] Error running command: {e}")
            return None

    async def fetch(self, url):
        try:
            async with self.session.get(url, timeout=10) as resp:
                if resp.status == 200:
                    return await resp.text()
        except Exception as e:
            print(f"[-] Error fetching {url}: {e}")
            return None

    def is_sensitive(self, url):
        return any(re.search(pattern, url, re.IGNORECASE) for pattern in self.sensitive_patterns)

    async def download_file(self, url):
        filename = os.path.join("results/downloads", url.split("/")[-1])
        try:
            async with self.session.get(url) as resp:
                if resp.status == 200:
                    with open(filename, "wb") as f:
                        f.write(await resp.read())
                    print(f"[+] Downloaded: {filename}")
        except Exception as e:
            print(f"[-] Failed to download {url}: {e}")

    async def crawl(self, url, depth=2):
        if url in self.visited or depth == 0 or len(self.crawled_urls) >= self.max_urls:
            return
        self.visited.add(url)

        html = await self.fetch(url)
        if not html:
            return

        if self.is_sensitive(url):
            print(f"[!] Sensitive File Found: {url}")
            self.sensitive_urls.append(url)
            await self.download_file(url)

        self.crawled_urls.append(url)
        soup = BeautifulSoup(html, "html.parser")
        tasks = []
        for tag in soup.find_all(["a", "form"]):
            href = tag.get("href") or tag.get("action")
            if href:
                joined = urljoin(url, href)
                if urlparse(self.target).netloc in urlparse(joined).netloc:
                    tasks.append(self.crawl(joined, depth - 1))
        await asyncio.gather(*tasks)

    def scan(self):
        print(f"\n[+] Running Nmap Scan on {self.target}")
        nmap_cmd = f"nmap -sV -T4 -p- -oN results/scans/nmap.txt {self.target.replace('http://', '').replace('https://', '')}"
        self.run_command(nmap_cmd)

        if not self.crawled_urls:
            print("[!] No URLs to scan with Nuclei")
            return

        print("[+] Running Nuclei Scan on crawled URLs")
        with open("results/scans/nuclei_targets.txt", "w") as f:
            for url in self.crawled_urls:
                f.write(url + "\n")

        nuclei_cmd = f"nuclei -l results/scans/nuclei_targets.txt -t nuclei-templates/ -o results/scans/nuclei.txt"
        self.run_command(nuclei_cmd)

        print("[+] Running SQLMap Scan on target")
        sqlmap_cmd = f"sqlmap -u {self.target} --batch --random-agent --output-dir=results/exploits"
        self.run_command(sqlmap_cmd)

        print("[+] Running XSS Fuzzer (custom payloads)")
        payloads_path = "payloads/xss.txt"
        if not os.path.exists(payloads_path):
            with open(payloads_path, "w") as f:
                f.write("<script>alert(1)</script>\n\" onmouseover=alert(1)")

        with open(payloads_path) as f:
            xss_payloads = [line.strip() for line in f if line.strip()]

        for payload in xss_payloads:
            test_url = f"{self.target}?x={payload}"
            with open("results/exploits/xss.txt", "a") as f:
                f.write(f"Payload: {payload}\nTested URL: {test_url}\n")

    def generate_report(self):
        print("\n[+] Generating Report...")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open("results/report.txt", "w") as f:
            f.write(f"Pentest Report for {self.target}\n")
            f.write(f"Timestamp: {timestamp}\n")
            f.write("=" * 50 + "\n")
            f.write(f"\nTotal URLs Crawled: {len(self.crawled_urls)}\n")
            f.write(f"Sensitive Files Found: {len(self.sensitive_urls)}\n")
            f.write("\nSensitive Files:\n")
            for url in self.sensitive_urls:
                f.write(url + "\n")
            f.write("\nCrawled URLs:\n")
            for url in self.crawled_urls:
                f.write(url + "\n")
            f.write("\n\nNmap Result:\n")
            try:
                f.write(open("results/scans/nmap.txt").read())
            except FileNotFoundError:
                f.write("[!] Nmap scan not available\n")
            f.write("\n\nNuclei Result:\n")
            try:
                f.write(open("results/scans/nuclei.txt").read())
            except FileNotFoundError:
                f.write("[!] Nuclei scan not available\n")
            f.write("\n\nSQLMap Output (check results/exploits/)\n")
            f.write("\nXSS Test URLs (check results/exploits/xss.txt)\n")
        print("[+] Report saved to results/report.txt")
        self.generate_html_report()

    def generate_html_report(self):
        html_path = "results/report.html"
        with open(html_path, "w") as f:
            f.write("<html><head><title>MadaStrike Report</title></head><body>")
            f.write(f"<h1>Pentest Report for {self.target}</h1>")
            f.write(f"<p><b>Timestamp:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>")
            f.write(f"<h2>Total URLs Crawled: {len(self.crawled_urls)}</h2>")
            f.write(f"<h2>Sensitive Files Found: {len(self.sensitive_urls)}</h2><ul>")
            for url in self.sensitive_urls:
                f.write(f"<li>{url}</li>")
            f.write("</ul><h2>Crawled URLs:</h2><ul>")
            for url in self.crawled_urls:
                f.write(f"<li>{url}</li>")
            f.write("</ul><h2>Nmap Result:</h2><pre>")
            try:
                f.write(open("results/scans/nmap.txt").read())
            except FileNotFoundError:
                f.write("Nmap scan not available")
            f.write("</pre><h2>Nuclei Result:</h2><pre>")
            try:
                f.write(open("results/scans/nuclei.txt").read())
            except FileNotFoundError:
                f.write("Nuclei scan not available")
            f.write("</pre><h2>SQLMap Output:</h2><p>See directory: results/exploits/</p>")
            f.write("<h2>XSS Test URLs:</h2><pre>")
            try:
                f.write(open("results/exploits/xss.txt").read())
            except FileNotFoundError:
                f.write("No XSS data available")
            f.write("</pre></body></html>")
        print(f"[+] HTML Report saved to {html_path}")

async def main():
    parser = argparse.ArgumentParser(description="MadaStrike CLI")
    parser.add_argument("-t", "--target", help="Target domain/IP")
    args = parser.parse_args()

    targets = []

    if args.target:
        targets.append(args.target)
    else:
        if not os.path.exists("target.txt"):
            print("[-] Tidak ada target.txt dan tidak ada target yang diberikan, sayang.")
            return
        with open("target.txt") as f:
            targets = [line.strip() for line in f if line.strip()]

    for target in targets:
        print(f"\n[+] Menjalankan MadaStrike untuk target: {target}, sayang")
        async with MadaStrike(target) as tool:
            await tool.crawl(tool.target)
            tool.scan()
            tool.generate_report()
            print(f"[!] Pentest selesai untuk {target}. Cek direktori 'results/' untuk hasil, sayang.\n")

if __name__ == "__main__":
    asyncio.run(main())
