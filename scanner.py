
import ssl
import socket
import json
import urllib.request
import urllib.error
from urllib.parse import urlparse
from datetime import datetime, timezone

# ==========================================
# WHITE HAT WEB SECURITY SCANNER
# Version: 1.0
# ==========================================

TIMEOUT = 10

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "name": "HSTS",
        "description": "強制使用 HTTPS",
        "severity": "HIGH"
    },
    "Content-Security-Policy": {
        "name": "CSP",
        "description": "防止部分跨站腳本攻擊",
        "severity": "HIGH"
    },
    "X-Frame-Options": {
        "name": "X-Frame-Options",
        "description": "降低 Clickjacking 風險",
        "severity": "MEDIUM"
    },
    "X-Content-Type-Options": {
        "name": "MIME Sniffing Protection",
        "description": "防止瀏覽器猜測內容類型",
        "severity": "MEDIUM"
    },
    "Referrer-Policy": {
        "name": "Referrer Policy",
        "description": "控制 Referrer 資訊傳送",
        "severity": "LOW"
    },
    "Permissions-Policy": {
        "name": "Permissions Policy",
        "description": "限制瀏覽器功能權限",
        "severity": "LOW"
    }
}


class WebSecurityScanner:

    def __init__(self, target):
        self.target = target.strip()
        self.results = []
        self.headers = {}
        self.status_code = None
        self.final_url = None

    # --------------------------------------
    # 1. URL 驗證
    # --------------------------------------

    def validate_url(self):

        if not self.target.startswith(("http://", "https://")):
            self.target = "https://" + self.target

        parsed = urlparse(self.target)

        if (
            parsed.scheme not in ("http", "https")
            or not parsed.hostname
            or parsed.username
            or parsed.password
        ):
            raise ValueError("無效的網站網址")

        try:
            port = parsed.port
        except ValueError:
            raise ValueError("無效的連接埠")

        if port and not (1 <= port <= 65535):
            raise ValueError("連接埠超出範圍")

        return parsed

    # --------------------------------------
    # 2. 網站連線檢查
    # --------------------------------------

    def fetch_website(self):

        print("\n[+] 正在連線至網站...")

        request = urllib.request.Request(
            self.target,
            headers={
                "User-Agent": "WhiteHatScanner/1.0",
                "Accept": "text/html"
            },
            method="GET"
        )

        try:
            with urllib.request.urlopen(
                request,
                timeout=TIMEOUT
            ) as response:

                self.status_code = response.status
                self.final_url = response.geturl()

                self.headers = dict(response.headers.items())

                print("[+] HTTP Status:", self.status_code)
                print("[+] Final URL:", self.final_url)

                return True

        except urllib.error.HTTPError as error:

            self.status_code = error.code
            self.headers = dict(error.headers.items())

            print("[!] HTTP Error:", error.code)

            return True

        except Exception as error:

            print("[-] Connection failed:", error)
            return False

    # --------------------------------------
    # 3. HTTPS 檢查
    # --------------------------------------

    def check_https(self):

        print("\n[+] HTTPS Security Check")

        parsed = urlparse(self.target)

        if parsed.scheme == "https":

            self.add_result(
                "HTTPS",
                "PASS",
                "網站使用 HTTPS",
                "INFO"
            )

        else:

            self.add_result(
                "HTTPS",
                "FAIL",
                "網站未使用 HTTPS",
                "HIGH"
            )

    # --------------------------------------
    # 4. SSL 憑證檢查
    # --------------------------------------

    def check_ssl(self):

        print("\n[+] SSL/TLS Certificate Check")

        parsed = urlparse(self.target)

        if parsed.scheme != "https":
            return

        hostname = parsed.hostname
        port = parsed.port or 443

        try:

            context = ssl.create_default_context()

            with socket.create_connection(
                (hostname, port),
                timeout=TIMEOUT
            ) as connection:

                with context.wrap_socket(
                    connection,
                    server_hostname=hostname
                ) as secure_socket:

                    certificate = secure_socket.getpeercert()

            expiry = certificate.get("notAfter")

            if not expiry:
                raise ValueError("無法取得憑證期限")

            expiry_date = datetime.strptime(
                expiry,
                "%b %d %H:%M:%S %Y %Z"
            ).replace(tzinfo=timezone.utc)

            now = datetime.now(timezone.utc)

            days_left = (expiry_date - now).days

            if days_left < 0:

                self.add_result(
                    "SSL Certificate",
                    "FAIL",
                    "憑證已過期",
                    "HIGH"
                )

            elif days_left <= 30:

                self.add_result(
                    "SSL Certificate",
                    "WARNING",
                    f"憑證即將到期，剩餘 {days_left} 天",
                    "MEDIUM"
                )

            else:

                self.add_result(
                    "SSL Certificate",
                    "PASS",
                    f"憑證有效，剩餘 {days_left} 天",
                    "INFO"
                )

        except Exception as error:

            self.add_result(
                "SSL Certificate",
                "WARNING",
                f"無法完成憑證檢查：{error}",
                "HIGH"
            )

    # --------------------------------------
    # 5. HTTP Security Headers
    # --------------------------------------

    def check_headers(self):

        print("\n[+] Security Headers Check")

        for header, config in SECURITY_HEADERS.items():

            value = self.headers.get(header)

            if value:

                self.add_result(
                    config["name"],
                    "PASS",
                    f"{config['description']}：已設定",
                    "INFO"
                )

            else:

                self.add_result(
                    config["name"],
                    "WARNING",
                    f"缺少 {header} 安全標頭",
                    config["severity"]
                )

    # --------------------------------------
    # 6. Cookie Security
    # --------------------------------------

    def check_cookies(self):

        print("\n[+] Cookie Security Check")

        cookies = self.headers.get("Set-Cookie")

        if not cookies:

            self.add_result(
                "Cookie",
                "INFO",
                "首頁回應沒有 Set-Cookie 標頭，無法檢查 Cookie",
                "INFO"
            )

            return

        # urllib 的 headers 可能包含多個 Set-Cookie
        response_headers = self.headers

        # 重新讀取所有 Cookie 標頭
        # 若只取得單一標頭，仍可檢查該標頭
        cookie_list = [cookies]

        for cookie in cookie_list:

            lower = cookie.lower()

            if "secure" not in lower:

                self.add_result(
                    "Cookie Secure",
                    "WARNING",
                    "Cookie 可能缺少 Secure 屬性",
                    "MEDIUM"
                )

            if "httponly" not in lower:

                self.add_result(
                    "Cookie HttpOnly",
                    "WARNING",
                    "Cookie 可能缺少 HttpOnly 屬性",
                    "MEDIUM"
                )

            if "samesite" not in lower:

                self.add_result(
                    "Cookie SameSite",
                    "WARNING",
                    "Cookie 未設定 SameSite",
                    "LOW"
                )

    # --------------------------------------
    # 7. Server Information
    # --------------------------------------

    def check_server_info(self):

        print("\n[+] Server Information Check")

        server = self.headers.get("Server")

        if server:

            self.add_result(
                "Server Information",
                "WARNING",
                f"伺服器資訊可能暴露：{server}",
                "LOW"
            )

        else:

            self.add_result(
                "Server Information",
                "PASS",
                "沒有發現 Server 標頭",
                "INFO"
            )

        powered = self.headers.get("X-Powered-By")

        if powered:

            self.add_result(
                "Technology Disclosure",
                "WARNING",
                f"可能暴露技術資訊：{powered}",
                "LOW"
            )

    # --------------------------------------
    # 8. 結果儲存
    # --------------------------------------

    def add_result(self, name, status, description, severity):

        self.results.append({
            "name": name,
            "status": status,
            "description": description,
            "severity": severity
        })

    # --------------------------------------
    # 9. 安全報告
    # --------------------------------------

    def generate_report(self):

        passed = sum(
            1 for r in self.results
            if r["status"] == "PASS"
        )

        warnings = sum(
            1 for r in self.results
            if r["status"] == "WARNING"
        )

        failed = sum(
            1 for r in self.results
            if r["status"] == "FAIL"
        )

        report = {
            "scanner": "White Hat Web Security Scanner",
            "version": "1.0",
            "target": self.target,
            "final_url": self.final_url,
            "http_status": self.status_code,
            "scan_time": datetime.now().astimezone().isoformat(),
            "summary": {
                "passed": passed,
                "warnings": warnings,
                "failed": failed,
                "total": len(self.results)
            },
            "results": self.results
        }

        filename = "security_report.json"

        with open(
            filename,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                report,
                file,
                ensure_ascii=False,
                indent=4
            )

        print("\n[+] Report saved:", filename)

    # --------------------------------------
    # 10. 顯示結果
    # --------------------------------------

    def display_results(self):

        print("\n")
        print("=" * 55)
        print("       WHITE HAT SECURITY SCAN REPORT")
        print("=" * 55)

        for result in self.results:

            status = result["status"]

            if status == "PASS":
                symbol = "[PASS]"
            elif status == "FAIL":
                symbol = "[FAIL]"
            elif status == "WARNING":
                symbol = "[WARN]"
            else:
                symbol = "[INFO]"

            print(
                f"\n{symbol} {result['name']}"
            )

            print(
                f"      {result['description']}"
            )

            print(
                f"      Severity: {result['severity']}"
            )

        print("\n" + "=" * 55)

        print(
            "Total Checks:",
            len(self.results)
        )

        print(
            "Passed:",
            sum(r["status"] == "PASS" for r in self.results)
        )

        print(
            "Warnings:",
            sum(r["status"] == "WARNING" for r in self.results)
        )

        print(
            "Failed:",
            sum(r["status"] == "FAIL" for r in self.results)
        )

        print("=" * 55)

    # --------------------------------------
    # 11. 啟動掃描
    # --------------------------------------

    def run(self):

        print("\n")
        print("=" * 55)
        print("       WHITE HAT WEB SECURITY SCANNER")
        print("                 Version 1.0")
        print("=" * 55)

        self.validate_url()

        if not self.fetch_website():

            print("\n[-] Scan stopped.")
            return

        self.check_https()
        self.check_ssl()
        self.check_headers()
        self.check_cookies()
        self.check_server_info()

        self.display_results()
        self.generate_report()


# ==========================================
# MAIN
# ==========================================

if __name__ == "__main__":

    print("WHITE HAT WEB SECURITY SCANNER")

    target = input(
        "\nEnter authorized website URL: "
    )

    try:

        scanner = WebSecurityScanner(target)
        scanner.run()

    except KeyboardInterrupt:

        print("\n[!] Scan cancelled.")

    except Exception as error:

        print("\n[-] Error:", error)
