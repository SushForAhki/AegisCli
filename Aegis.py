# AegisCLI - Gelişmiş Güvenlik Araç Seti
# Geliştirici: SushForAhki
# Bu araç, web güvenliği, port taraması, log analizi ve ağ araçları gibi çeşitli güvenlik testleri için kapsamlı bir komut satırı arayüzü sağlar.
# etik kullanım: Bu araç yalnızca yasal ve izinli güvenlik testleri için kullanılmalıdır. İzin alınmadan yapılan taramalar ve analizler yasa dışıdır ve ciddi sonuçlara yol açabilir.
# geliştirici hiçbir şekilde sorumluluk kabul etmez. Kullanıcılar, bu aracı kullanmadan önce geçerli yasaları ve düzenlemeleri anlamalı ve uymalıdır.
# Not: Bu araç, güvenlik testleri için temel bir başlangıç noktası sağlar ancak kapsamlı bir güvenlik değerlendirmesi için daha gelişmiş araçlar ve teknikler gereklidir. Her zaman etik kurallara uyun ve izin alınmadan hiçbir hedefe saldırmayın.




import json
import os
import re
import socket
import ssl
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import hashlib
import ipaddress
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import requests
from colorama import Fore, Style, init

init(autoreset=True)


class BannerSystem:
    @staticmethod
    def clear_screen() -> None:
        try:
            os.system("cls" if os.name == "nt" else "clear")
        except Exception:
            pass

    @staticmethod
    def show() -> None:
        banner = rf"""
 {Fore.CYAN}    ___              _     _____ _      _____ _      _____ 
 {Fore.CYAN}   /   |  ___  ____ (_)___/ ___/| | /| / / _ \ |    /  _  |
 {Fore.CYAN}  / /| | / _ \/ __ `/ / __ \__ \ | |/ |/ /  __/ |    | | | |
 {Fore.CYAN} / ___ |/  __/ /_/ / / /_/ /__/ / |__/|__/\___/ |___ | |_| |
 {Fore.CYAN}/_/  |_|\___/\__, /_/\____/____/                  |_____|\___/
 {Fore.CYAN}            /____/
 {Fore.YELLOW}                 AegisCLI {Fore.WHITE}| SushForAhki | 2025 Gelişmiş Güvenlik Araç Seti
"""
        print(banner)

    @staticmethod
    def section(title: str) -> None:
        print(f"{Fore.MAGENTA}{'=' * 68}")
        print(f"{Fore.MAGENTA}{title}")
        print(f"{Fore.MAGENTA}{'=' * 68}")


class JsonLogger:
    def __init__(self) -> None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.file_path = os.path.join(os.getcwd(), f"report_{timestamp}.json")
        self.data: Dict[str, Any] = {
            "arac": "AegisCLI",
            "olusturma_zamani": datetime.now().isoformat(),
            "kayitlar": [],
        }
        self._persist()

    def log(self, modul: str, islem: str, hedef: str, sonuc: Dict[str, Any]) -> None:
        try:
            entry = {
                "zaman": datetime.now().isoformat(),
                "modul": modul,
                "islem": islem,
                "hedef": hedef,
                "sonuc": sonuc,
            }
            self.data["kayitlar"].append(entry)
            self._persist()
        except Exception as exc:
            print(f"{Fore.RED}[!] Log kaydi olusturulamadi: {Helpers.safe_text(exc)}")

    def _persist(self) -> None:
        try:
            with open(self.file_path, "w", encoding="utf-8") as file:
                json.dump(self.data, file, indent=2, ensure_ascii=False)
        except Exception as exc:
            print(f"{Fore.RED}[!] Rapor dosyasi yazilamadi: {Helpers.safe_text(exc)}")

    def show_report_location(self) -> None:
        print(f"{Fore.GREEN}[*] JSON rapor dosyasi: {self.file_path}")


class Helpers:
    @staticmethod
    def safe_input(prompt: str) -> str:
        try:
            return input(prompt).strip()
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Giris islemi kullanici tarafindan iptal edildi.")
            return ""
        except EOFError:
            print(f"\n{Fore.YELLOW}[!] Giris akisi sonlandi.")
            return ""
        except Exception:
            return ""

    @staticmethod
    def pause() -> None:
        try:
            input(f"\n{Fore.CYAN}Devam etmek icin Enter tusuna basin...")
        except Exception:
            pass

    @staticmethod
    def normalize_url(url: str) -> Optional[str]:
        try:
            url = (url or "").strip()
            if not url:
                return None
            if not re.match(r"^https?://", url, re.IGNORECASE):
                url = f"http://{url}"
            parsed = urlparse(url)
            if not parsed.netloc:
                return None
            return urlunparse(parsed)
        except Exception:
            return None

    @staticmethod
    def is_valid_host(host: str) -> bool:
        try:
            host = (host or "").strip()
            if not host:
                return False
            socket.gethostbyname(host)
            return True
        except Exception:
            return False

    @staticmethod
    def parse_port_range(raw: str) -> Optional[Tuple[int, int]]:
        try:
            cleaned = raw.replace(" ", "")
            if "-" in cleaned:
                start_str, end_str = cleaned.split("-", 1)
            else:
                start_str = end_str = cleaned
            start = int(start_str)
            end = int(end_str)
            if start < 1 or end > 65535 or start > end:
                return None
            return start, end
        except Exception:
            return None

    @staticmethod
    def safe_text(value: Any, limit: int = 200) -> str:
        try:
            text = str(value)
            text = re.sub(r"[\x00-\x1f\x7f]", "", text)
            return text[:limit]
        except Exception:
            return ""

    @staticmethod
    def build_url_with_param(url: str, key: str, value: str) -> str:
        try:
            parsed = urlparse(url)
            query = dict(parse_qsl(parsed.query, keep_blank_values=True))
            query[key] = value
            new_query = urlencode(query, doseq=True)
            return urlunparse(
                (
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    new_query,
                    parsed.fragment,
                )
            )
        except Exception:
            return url

    @staticmethod
    def safe_int(value: str, default: int, minimum: int, maximum: int) -> int:
        try:
            parsed = int(value)
            return max(minimum, min(parsed, maximum))
        except Exception:
            return default

    @staticmethod
    def file_size(path: str) -> int:
        try:
            return os.path.getsize(path)
        except Exception:
            return 0

    @staticmethod
    def format_bytes(size: int) -> str:
        try:
            units = ["B", "KB", "MB", "GB"]
            value = float(size)
            for unit in units:
                if value < 1024 or unit == units[-1]:
                    return f"{value:.2f} {unit}"
                value /= 1024
            return f"{size} B"
        except Exception:
            return "0 B"

    @staticmethod
    def print_status(label: str, value: str, color: str = Fore.WHITE) -> None:
        print(f"{color}[*] {label:<24}: {value}")

    @staticmethod
    def print_table_line(left: str, right: str, color: str = Fore.WHITE) -> None:
        print(f"{color}- {left:<28} {right}")

    @staticmethod
    def normalize_host(value: str) -> str:
        try:
            value = (value or "").strip()
            if not value:
                return ""
            parsed = urlparse(value if "://" in value else f"//{value}")
            return (parsed.netloc or parsed.path).split("/")[0].strip()
        except Exception:
            return ""


class WebScanner:
    COMMON_ENDPOINTS = ["/admin", "/login", "/panel", "/dashboard"]
    SECURITY_HEADERS = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
    ]

    def __init__(self, logger: JsonLogger) -> None:
        self.logger = logger
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "AegisCLI/2.0",
                "Accept": "*/*",
                "Connection": "close",
            }
        )

    def menu(self) -> None:
        while True:
            BannerSystem.clear_screen()
            BannerSystem.show()
            BannerSystem.section("Web Guvenlik Tarayicisi")
            print(f"{Fore.WHITE}[1] Guvenlik Header Taramasi")
            print(f"{Fore.WHITE}[2] Endpoint Kesfi")
            print(f"{Fore.WHITE}[3] Temel Zafiyet Analizi")
            print(f"{Fore.WHITE}[0] Geri Don")

            choice = Helpers.safe_input(f"\n{Fore.CYAN}Seciminiz: ")
            if choice == "1":
                self.run_header_scan()
            elif choice == "2":
                self.run_endpoint_discovery()
            elif choice == "3":
                self.run_basic_vulnerability_checks()
            elif choice == "0":
                break
            else:
                print(f"{Fore.RED}[!] Gecersiz menu secimi.")
                Helpers.pause()

    def _get_url(self) -> Optional[str]:
        raw_url = Helpers.safe_input(f"{Fore.CYAN}Hedef URL: ")
        normalized = Helpers.normalize_url(raw_url)
        if not normalized:
            print(f"{Fore.RED}[!] URL formati gecersiz.")
            return None
        return normalized

    def _request(
        self, method: str, url: str, timeout: int = 8
    ) -> Tuple[Optional[requests.Response], Optional[str]]:
        try:
            response = self.session.request(
                method=method,
                url=url,
                timeout=timeout,
                allow_redirects=True,
                verify=False,
            )
            return response, None
        except requests.RequestException as exc:
            return None, Helpers.safe_text(exc, 300)
        except Exception as exc:
            return None, Helpers.safe_text(exc, 300)

    def run_header_scan(self) -> None:
        BannerSystem.clear_screen()
        BannerSystem.show()
        BannerSystem.section("Guvenlik Header Taramasi")

        url = self._get_url()
        if not url:
            Helpers.pause()
            return

        result: Dict[str, Any] = {
            "url": url,
            "durum_kodu": None,
            "sunucu": None,
            "guvenlik_headerlari": {},
            "eksik_headerlar": [],
            "risk_puani": 0,
            "hata": None,
        }

        response, error = self._request("GET", url)
        if error or response is None:
            result["hata"] = error or "Bilinmeyen istek hatasi"
            print(f"{Fore.RED}[!] Istek basarisiz: {result['hata']}")
            self.logger.log("web_scanner", "header_taramasi", url, result)
            Helpers.pause()
            return

        result["durum_kodu"] = response.status_code
        result["sunucu"] = Helpers.safe_text(response.headers.get("Server", "Bilinmiyor"), 80)
        Helpers.print_status("Hedef", url, Fore.CYAN)
        Helpers.print_status("HTTP Durum Kodu", str(response.status_code), Fore.GREEN)
        Helpers.print_status("Server Header", result["sunucu"], Fore.WHITE)
        print()

        for header in self.SECURITY_HEADERS:
            value = response.headers.get(header)
            if value:
                safe_value = Helpers.safe_text(value, 120)
                result["guvenlik_headerlari"][header] = safe_value
                Helpers.print_table_line(header, safe_value, Fore.GREEN)
            else:
                result["guvenlik_headerlari"][header] = None
                result["eksik_headerlar"].append(header)
                Helpers.print_table_line(header, "Bulunamadi", Fore.YELLOW)

        result["risk_puani"] = len(result["eksik_headerlar"])
        print()
        if result["risk_puani"] == 0:
            print(f"{Fore.GREEN}[+] Temel guvenlik header kontrolleri basarili gorunuyor.")
        else:
            print(
                f"{Fore.YELLOW}[!] Eksik header sayisi: {result['risk_puani']} "
                f"| Bu durum ek inceleme gerektirebilir."
            )

        self.logger.log("web_scanner", "header_taramasi", url, result)
        Helpers.pause()

    def run_endpoint_discovery(self) -> None:
        BannerSystem.clear_screen()
        BannerSystem.show()
        BannerSystem.section("Endpoint Kesfi")

        url = self._get_url()
        if not url:
            Helpers.pause()
            return

        base = url.rstrip("/")
        findings: List[Dict[str, Any]] = []

        print(f"{Fore.CYAN}[*] Yaygin endpoint'ler taraniyor...\n")
        for endpoint in self.COMMON_ENDPOINTS:
            full_url = urljoin(base + "/", endpoint.lstrip("/"))
            item = {
                "endpoint": endpoint,
                "url": full_url,
                "durum_kodu": None,
                "icerik_uzunlugu": None,
                "erisilebilir": False,
                "yonlendirme": False,
                "hata": None,
            }

            response, error = self._request("GET", full_url)
            if error or response is None:
                item["hata"] = error or "Bilinmeyen istek hatasi"
                Helpers.print_table_line(endpoint, "Hata", Fore.RED)
            else:
                item["durum_kodu"] = response.status_code
                item["icerik_uzunlugu"] = len(response.text)
                item["erisilebilir"] = response.status_code < 400
                item["yonlendirme"] = bool(response.history)
                status_text = (
                    f"HTTP {response.status_code} | Uzunluk={item['icerik_uzunlugu']}"
                )
                if item["yonlendirme"]:
                    status_text += " | Redirect"
                color = Fore.GREEN if item["erisilebilir"] else Fore.YELLOW
                Helpers.print_table_line(endpoint, status_text, color)
            findings.append(item)

        erisilebilirler = [item for item in findings if item["erisilebilir"]]
        print()
        print(f"{Fore.CYAN}[*] Ozet")
        Helpers.print_table_line("Toplam endpoint", str(len(findings)), Fore.WHITE)
        Helpers.print_table_line("Erisilebilir endpoint", str(len(erisilebilirler)), Fore.GREEN)
        Helpers.print_table_line(
            "Yonlendirme yapan endpoint",
            str(sum(1 for item in findings if item["yonlendirme"])),
            Fore.YELLOW,
        )

        result = {"url": url, "bulgular": findings}
        self.logger.log("web_scanner", "endpoint_kesfi", url, result)
        Helpers.pause()

    def run_basic_vulnerability_checks(self) -> None:
        BannerSystem.clear_screen()
        BannerSystem.show()
        BannerSystem.section("Temel Zafiyet Analizi")

        url = self._get_url()
        if not url:
            Helpers.pause()
            return

        test_value = "AegisYansimaKontrol123"
        test_param = "aegis_test"
        baseline_resp, baseline_err = self._request("GET", url)
        test_url = Helpers.build_url_with_param(url, test_param, test_value)
        test_resp, test_err = self._request("GET", test_url)

        result: Dict[str, Any] = {
            "url": url,
            "test_url": test_url,
            "baseline_durum": None,
            "test_durum": None,
            "baseline_uzunluk": None,
            "test_uzunluk": None,
            "uzunluk_farki": None,
            "yansima_tespit_edildi": False,
            "notlar": [],
            "hatalar": [],
        }

        if baseline_err or baseline_resp is None:
            result["hatalar"].append(
                f"Temel istek basarisiz: {baseline_err or 'Bilinmeyen hata'}"
            )
        else:
            result["baseline_durum"] = baseline_resp.status_code
            result["baseline_uzunluk"] = len(baseline_resp.text)

        if test_err or test_resp is None:
            result["hatalar"].append(
                f"Test istegi basarisiz: {test_err or 'Bilinmeyen hata'}"
            )
        else:
            result["test_durum"] = test_resp.status_code
            result["test_uzunluk"] = len(test_resp.text)
            result["yansima_tespit_edildi"] = test_value in test_resp.text

        if (
            result["baseline_uzunluk"] is not None
            and result["test_uzunluk"] is not None
        ):
            fark = result["test_uzunluk"] - result["baseline_uzunluk"]
            result["uzunluk_farki"] = fark
            if fark == 0:
                result["notlar"].append(
                    "Temel ve benign parametreli istek arasinda boyut farki gorulmedi."
                )
            else:
                result["notlar"].append(
                    "Response uzunlugu degisti; uygulama parametreyi farkli ele aliyor olabilir."
                )

        if result["yansima_tespit_edildi"]:
            result["notlar"].append(
                "Gonderilen benign deger response iceriginde yansidi."
            )
        else:
            result["notlar"].append(
                "Response iceriginde benign degerin yansimasi gorulmedi."
            )

        if result["hatalar"]:
            print(f"{Fore.RED}[!] Analiz sirasinda hata olustu:")
            for hata in result["hatalar"]:
                Helpers.print_table_line("Hata", Helpers.safe_text(hata, 120), Fore.RED)
        else:
            Helpers.print_status("Temel durum kodu", str(result["baseline_durum"]), Fore.GREEN)
            Helpers.print_status("Test durum kodu", str(result["test_durum"]), Fore.GREEN)
            Helpers.print_status(
                "Temel response boyutu", str(result["baseline_uzunluk"]), Fore.WHITE
            )
            Helpers.print_status(
                "Test response boyutu", str(result["test_uzunluk"]), Fore.WHITE
            )
            Helpers.print_status(
                "Uzunluk farki", str(result["uzunluk_farki"]), Fore.CYAN
            )
            print()

            if result["yansima_tespit_edildi"]:
                print(f"{Fore.YELLOW}[!] Benign girdinin response icinde yansimasi tespit edildi.")
            else:
                print(f"{Fore.GREEN}[+] Benign girdi yansimasi tespit edilmedi.")

            print(f"{Fore.CYAN}[*] Davranis Notlari")
            for note in result["notlar"]:
                Helpers.print_table_line("Analiz", note, Fore.WHITE)

        self.logger.log("web_scanner", "temel_zafiyet_analizi", url, result)
        Helpers.pause()


class PortScanner:
    def __init__(self, logger: JsonLogger) -> None:
        self.logger = logger
        self.default_timeout = 1.0
        self.default_workers = 100

    def menu(self) -> None:
        BannerSystem.clear_screen()
        BannerSystem.show()
        BannerSystem.section("Port Tarayici")
        self.run()

    def run(self) -> None:
        target = Helpers.safe_input(f"{Fore.CYAN}Hedef IP/Domain: ")
        if not Helpers.is_valid_host(target):
            print(f"{Fore.RED}[!] Hedef alan adi veya IP gecersiz.")
            Helpers.pause()
            return

        range_input = Helpers.safe_input(f"{Fore.CYAN}Port araligi (or. 1-1024): ")
        port_range = Helpers.parse_port_range(range_input)
        if not port_range:
            print(f"{Fore.RED}[!] Port araligi gecersiz.")
            Helpers.pause()
            return

        timeout_input = Helpers.safe_input(
            f"{Fore.CYAN}Timeout saniye (varsayilan 1, 1-5): "
        )
        worker_input = Helpers.safe_input(
            f"{Fore.CYAN}Thread sayisi (varsayilan 100, 10-300): "
        )

        timeout = float(Helpers.safe_int(timeout_input or "1", 1, 1, 5))
        workers = Helpers.safe_int(worker_input or "100", 100, 10, 300)

        try:
            resolved_ip = socket.gethostbyname(target)
        except Exception as exc:
            print(f"{Fore.RED}[!] DNS cozumleme hatasi: {Helpers.safe_text(exc)}")
            Helpers.pause()
            return

        start_port, end_port = port_range
        ports = list(range(start_port, end_port + 1))
        open_ports: List[Dict[str, Any]] = []

        print()
        Helpers.print_status("Hedef", target, Fore.CYAN)
        Helpers.print_status("Cozumlenen IP", resolved_ip, Fore.WHITE)
        Helpers.print_status("Port araligi", f"{start_port}-{end_port}", Fore.WHITE)
        Helpers.print_status("Thread sayisi", str(workers), Fore.WHITE)
        Helpers.print_status("Timeout", f"{timeout:.1f} saniye", Fore.WHITE)
        print()
        print(f"{Fore.CYAN}[*] Tarama baslatildi...\n")

        try:
            with ThreadPoolExecutor(max_workers=workers) as executor:
                future_map = {
                    executor.submit(self._scan_port, resolved_ip, port, timeout): port
                    for port in ports
                }
                for future in as_completed(future_map):
                    try:
                        result = future.result()
                        if result:
                            open_ports.append(result)
                            banner_text = result["banner"] or "Banner alinamadi"
                            print(
                                f"{Fore.GREEN}[+] {result['port']}/tcp acik | "
                                f"Servis: {result['service']} | "
                                f"Banner: {Helpers.safe_text(banner_text, 70)}"
                            )
                    except Exception as exc:
                        print(f"{Fore.RED}[!] Is parcacigi hatasi: {Helpers.safe_text(exc)}")
        except Exception as exc:
            print(f"{Fore.RED}[!] Port taramasi basarisiz: {Helpers.safe_text(exc)}")
            Helpers.pause()
            return

        open_ports.sort(key=lambda item: item["port"])
        print()
        print(f"{Fore.CYAN}[*] Port Tarama Ozeti")
        Helpers.print_table_line("Toplam taranan port", str(len(ports)), Fore.WHITE)
        Helpers.print_table_line("Acik port sayisi", str(len(open_ports)), Fore.GREEN)

        if not open_ports:
            print(f"{Fore.YELLOW}[!] Secilen aralikta acik port tespit edilmedi.")
        else:
            print(f"{Fore.CYAN}[*] Acik portlar")
            for item in open_ports:
                detail = f"{item['service']} | {Helpers.safe_text(item['banner'] or 'Yok', 60)}"
                Helpers.print_table_line(f"{item['port']}/tcp", detail, Fore.GREEN)

        result = {
            "hedef": target,
            "cozumlenen_ip": resolved_ip,
            "port_araligi": f"{start_port}-{end_port}",
            "thread_sayisi": workers,
            "timeout": timeout,
            "acik_portlar": open_ports,
            "acik_port_sayisi": len(open_ports),
        }
        self.logger.log("port_scanner", "port_taramasi", target, result)
        Helpers.pause()

    def _scan_port(
        self, host: str, port: int, timeout: float
    ) -> Optional[Dict[str, Any]]:
        sock: Optional[socket.socket] = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            status = sock.connect_ex((host, port))
            if status != 0:
                return None

            service = self._resolve_service_name(port)
            banner = self._grab_banner(sock)
            return {"port": port, "service": service, "banner": banner}
        except Exception:
            return None
        finally:
            try:
                if sock:
                    sock.close()
            except Exception:
                pass

    @staticmethod
    def _resolve_service_name(port: int) -> str:
        try:
            return socket.getservbyport(port, "tcp")
        except Exception:
            return "bilinmiyor"

    @staticmethod
    def _grab_banner(sock: socket.socket) -> str:
        try:
            sock.sendall(b"\r\n")
            data = sock.recv(1024)
            if not data:
                return ""
            return Helpers.safe_text(data.decode("utf-8", errors="ignore"), 120)
        except Exception:
            return ""


class LogAnalyzer:
    PATTERNS = {
        "failed": re.compile(r"\bfailed\b", re.IGNORECASE),
        "error": re.compile(r"\berror\b", re.IGNORECASE),
        "unauthorized": re.compile(r"\bunauthorized\b", re.IGNORECASE),
    }

    def __init__(self, logger: JsonLogger) -> None:
        self.logger = logger

    def menu(self) -> None:
        BannerSystem.clear_screen()
        BannerSystem.show()
        BannerSystem.section("Log Analizoru")
        self.run()

    def run(self) -> None:
        path = Helpers.safe_input(f"{Fore.CYAN}Log dosyasi yolu: ")
        if not path:
            print(f"{Fore.RED}[!] Dosya yolu bos birakilamaz.")
            Helpers.pause()
            return

        if not os.path.isfile(path):
            print(f"{Fore.RED}[!] Dosya bulunamadi.")
            Helpers.pause()
            return

        counts = {key: 0 for key in self.PATTERNS}
        total_lines = 0
        matched_lines = 0
        sample_hits: List[str] = []
        errors: List[str] = []
        file_size = Helpers.file_size(path)

        print()
        Helpers.print_status("Dosya", path, Fore.CYAN)
        Helpers.print_status("Boyut", Helpers.format_bytes(file_size), Fore.WHITE)
        print()
        print(f"{Fore.CYAN}[*] Log analizi baslatildi...\n")

        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as file:
                for line in file:
                    total_lines += 1
                    clean_line = Helpers.safe_text(line.strip(), 160)
                    line_has_match = False
                    for label, pattern in self.PATTERNS.items():
                        found = pattern.findall(line)
                        if found:
                            counts[label] += len(found)
                            line_has_match = True
                    if line_has_match:
                        matched_lines += 1
                        if len(sample_hits) < 5 and clean_line:
                            sample_hits.append(clean_line)
        except Exception as exc:
            errors.append(Helpers.safe_text(exc, 300))

        if errors:
            print(f"{Fore.RED}[!] Analiz basarisiz: {errors[0]}")
        else:
            print(f"{Fore.CYAN}[*] Analiz Ozeti")
            Helpers.print_table_line("Toplam satir", str(total_lines), Fore.WHITE)
            Helpers.print_table_line("Eslesen satir", str(matched_lines), Fore.GREEN)
            for key, value in counts.items():
                color = Fore.YELLOW if value > 0 else Fore.GREEN
                Helpers.print_table_line(key.upper(), str(value), color)

            print()
            if sample_hits:
                print(f"{Fore.CYAN}[*] Ornek Eslesmeler")
                for sample in sample_hits:
                    Helpers.print_table_line("Satir", sample, Fore.WHITE)
            else:
                print(f"{Fore.GREEN}[+] Anahtar kelimeler icin eslesme bulunamadi.")

        result = {
            "dosya_yolu": path,
            "dosya_boyutu": file_size,
            "toplam_satir": total_lines,
            "eslesen_satir": matched_lines,
            "sayaclar": counts,
            "ornekler": sample_hits,
            "hatalar": errors,
        }
        self.logger.log("log_analyzer", "log_analizi", path, result)
        Helpers.pause()


class NetworkToolkit:
    def __init__(self, logger: JsonLogger) -> None:
        self.logger = logger

    def menu(self) -> None:
        while True:
            BannerSystem.clear_screen()
            BannerSystem.show()
            BannerSystem.section("Ag ve Alan Adi Araclari")
            print(f"{Fore.WHITE}[1] DNS ve IP Bilgisi")
            print(f"{Fore.WHITE}[2] Reverse DNS Kontrolu")
            print(f"{Fore.WHITE}[0] Geri Don")

            choice = Helpers.safe_input(f"\n{Fore.CYAN}Seciminiz: ")
            if choice == "1":
                self.run_dns_lookup()
            elif choice == "2":
                self.run_reverse_dns()
            elif choice == "0":
                break
            else:
                print(f"{Fore.RED}[!] Gecersiz menu secimi.")
                Helpers.pause()

    def run_dns_lookup(self) -> None:
        BannerSystem.clear_screen()
        BannerSystem.show()
        BannerSystem.section("DNS ve IP Bilgisi")

        raw_host = Helpers.safe_input(f"{Fore.CYAN}Alan adi veya host: ")
        host = Helpers.normalize_host(raw_host)
        if not host:
            print(f"{Fore.RED}[!] Gecerli bir host girilmedi.")
            Helpers.pause()
            return

        result: Dict[str, Any] = {
            "host": host,
            "ip_adresleri": [],
            "adres_turu": "bilinmiyor",
            "reverse_dns": [],
            "hatalar": [],
        }

        try:
            infos = socket.getaddrinfo(host, None)
            ips: List[str] = []
            for info in infos:
                candidate = info[4][0]
                if candidate not in ips:
                    ips.append(candidate)
            result["ip_adresleri"] = ips
        except Exception as exc:
            result["hatalar"].append(f"DNS cozumleme hatasi: {Helpers.safe_text(exc)}")

        if result["ip_adresleri"]:
            for ip in result["ip_adresleri"]:
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    result["adres_turu"] = "ozel" if ip_obj.is_private else "genel"
                    reverse_name = socket.gethostbyaddr(ip)[0]
                    result["reverse_dns"].append({"ip": ip, "kayit": reverse_name})
                except Exception:
                    result["reverse_dns"].append({"ip": ip, "kayit": "Bulunamadi"})

        Helpers.print_status("Host", host, Fore.CYAN)
        Helpers.print_table_line("Toplam IP", str(len(result["ip_adresleri"])), Fore.WHITE)
        if result["ip_adresleri"]:
            for ip in result["ip_adresleri"]:
                Helpers.print_table_line("IP", ip, Fore.GREEN)
            Helpers.print_table_line("Adres sinifi", result["adres_turu"], Fore.YELLOW)
            for item in result["reverse_dns"]:
                Helpers.print_table_line(
                    f"PTR {item['ip']}", Helpers.safe_text(item["kayit"], 100), Fore.WHITE
                )
        if result["hatalar"]:
            for err in result["hatalar"]:
                Helpers.print_table_line("Hata", err, Fore.RED)

        self.logger.log("network_toolkit", "dns_ip_bilgisi", host, result)
        Helpers.pause()

    def run_reverse_dns(self) -> None:
        BannerSystem.clear_screen()
        BannerSystem.show()
        BannerSystem.section("Reverse DNS Kontrolu")

        ip = Helpers.safe_input(f"{Fore.CYAN}IP adresi: ")
        try:
            ipaddress.ip_address(ip)
        except Exception:
            print(f"{Fore.RED}[!] Gecerli bir IP adresi girilmedi.")
            Helpers.pause()
            return

        result: Dict[str, Any] = {"ip": ip, "kayit": None, "hata": None}
        try:
            result["kayit"] = socket.gethostbyaddr(ip)[0]
            Helpers.print_table_line("PTR Kaydi", str(result["kayit"]), Fore.GREEN)
        except Exception as exc:
            result["hata"] = Helpers.safe_text(exc)
            Helpers.print_table_line("Hata", result["hata"], Fore.RED)

        self.logger.log("network_toolkit", "reverse_dns", ip, result)
        Helpers.pause()


class TLSInspector:
    def __init__(self, logger: JsonLogger) -> None:
        self.logger = logger

    def menu(self) -> None:
        BannerSystem.clear_screen()
        BannerSystem.show()
        BannerSystem.section("TLS Sertifika Analizi")
        self.run()

    def run(self) -> None:
        raw_host = Helpers.safe_input(f"{Fore.CYAN}Host veya URL: ")
        host = Helpers.normalize_host(raw_host)
        if not host:
            print(f"{Fore.RED}[!] Gecerli bir host girilmedi.")
            Helpers.pause()
            return

        port = Helpers.safe_int(
            Helpers.safe_input(f"{Fore.CYAN}Port (varsayilan 443): ") or "443",
            443,
            1,
            65535,
        )

        result: Dict[str, Any] = {
            "host": host,
            "port": port,
            "sertifika_var": False,
            "subject": None,
            "issuer": None,
            "not_before": None,
            "not_after": None,
            "gun_kaldi": None,
            "hata": None,
        }

        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as secure_sock:
                    cert = secure_sock.getpeercert()

            result["sertifika_var"] = bool(cert)
            result["subject"] = self._flatten_cert_name(cert.get("subject", ()))
            result["issuer"] = self._flatten_cert_name(cert.get("issuer", ()))
            result["not_before"] = cert.get("notBefore")
            result["not_after"] = cert.get("notAfter")
            result["gun_kaldi"] = self._days_left(cert.get("notAfter"))

            Helpers.print_status("Host", host, Fore.CYAN)
            Helpers.print_table_line("Port", str(port), Fore.WHITE)
            Helpers.print_table_line("Subject", str(result["subject"]), Fore.GREEN)
            Helpers.print_table_line("Issuer", str(result["issuer"]), Fore.GREEN)
            Helpers.print_table_line("Baslangic", str(result["not_before"]), Fore.WHITE)
            Helpers.print_table_line("Bitis", str(result["not_after"]), Fore.WHITE)
            color = Fore.YELLOW if result["gun_kaldi"] is not None and result["gun_kaldi"] <= 30 else Fore.GREEN
            Helpers.print_table_line("Kalan gun", str(result["gun_kaldi"]), color)
        except Exception as exc:
            result["hata"] = Helpers.safe_text(exc, 300)
            Helpers.print_table_line("Hata", result["hata"], Fore.RED)

        self.logger.log("tls_inspector", "sertifika_analizi", host, result)
        Helpers.pause()

    @staticmethod
    def _flatten_cert_name(parts: Any) -> str:
        try:
            values: List[str] = []
            for group in parts:
                for key, value in group:
                    values.append(f"{key}={value}")
            return ", ".join(values) if values else "Bulunamadi"
        except Exception:
            return "Bulunamadi"

    @staticmethod
    def _days_left(not_after: Optional[str]) -> Optional[int]:
        try:
            if not not_after:
                return None
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            return (expiry - datetime.utcnow()).days
        except Exception:
            return None


class HashToolkit:
    ALGORITHMS = {
        "1": "md5",
        "2": "sha1",
        "3": "sha256",
    }

    def __init__(self, logger: JsonLogger) -> None:
        self.logger = logger

    def menu(self) -> None:
        while True:
            BannerSystem.clear_screen()
            BannerSystem.show()
            BannerSystem.section("Hash Araci")
            print(f"{Fore.WHITE}[1] Metin Hash Uret")
            print(f"{Fore.WHITE}[2] Dosya Hash Uret")
            print(f"{Fore.WHITE}[0] Geri Don")

            choice = Helpers.safe_input(f"\n{Fore.CYAN}Seciminiz: ")
            if choice == "1":
                self.run_text_hash()
            elif choice == "2":
                self.run_file_hash()
            elif choice == "0":
                break
            else:
                print(f"{Fore.RED}[!] Gecersiz menu secimi.")
                Helpers.pause()

    def run_text_hash(self) -> None:
        BannerSystem.clear_screen()
        BannerSystem.show()
        BannerSystem.section("Metin Hash Uret")

        text = Helpers.safe_input(f"{Fore.CYAN}Metin: ")
        if not text:
            print(f"{Fore.RED}[!] Metin bos olamaz.")
            Helpers.pause()
            return
        algorithm = self._choose_algorithm()
        if not algorithm:
            return

        digest = self._hash_bytes(text.encode("utf-8"), algorithm)
        Helpers.print_table_line("Algoritma", algorithm.upper(), Fore.WHITE)
        Helpers.print_table_line("Hash", digest, Fore.GREEN)
        self.logger.log(
            "hash_toolkit",
            "metin_hash",
            "inline_text",
            {"algoritma": algorithm, "hash": digest, "uzunluk": len(text)},
        )
        Helpers.pause()

    def run_file_hash(self) -> None:
        BannerSystem.clear_screen()
        BannerSystem.show()
        BannerSystem.section("Dosya Hash Uret")

        path = Helpers.safe_input(f"{Fore.CYAN}Dosya yolu: ")
        if not os.path.isfile(path):
            print(f"{Fore.RED}[!] Dosya bulunamadi.")
            Helpers.pause()
            return
        algorithm = self._choose_algorithm()
        if not algorithm:
            return

        try:
            hasher = hashlib.new(algorithm)
            with open(path, "rb") as file:
                while True:
                    chunk = file.read(8192)
                    if not chunk:
                        break
                    hasher.update(chunk)
            digest = hasher.hexdigest()
            Helpers.print_table_line("Algoritma", algorithm.upper(), Fore.WHITE)
            Helpers.print_table_line("Dosya", path, Fore.WHITE)
            Helpers.print_table_line("Hash", digest, Fore.GREEN)
            self.logger.log(
                "hash_toolkit",
                "dosya_hash",
                path,
                {
                    "algoritma": algorithm,
                    "hash": digest,
                    "boyut": Helpers.file_size(path),
                },
            )
        except Exception as exc:
            Helpers.print_table_line("Hata", Helpers.safe_text(exc), Fore.RED)
        Helpers.pause()

    def _choose_algorithm(self) -> Optional[str]:
        print(f"{Fore.WHITE}[1] MD5")
        print(f"{Fore.WHITE}[2] SHA1")
        print(f"{Fore.WHITE}[3] SHA256")
        choice = Helpers.safe_input(f"\n{Fore.CYAN}Algoritma secimi: ")
        algorithm = self.ALGORITHMS.get(choice)
        if not algorithm:
            print(f"{Fore.RED}[!] Gecersiz algoritma secimi.")
            Helpers.pause()
            return None
        return algorithm

    @staticmethod
    def _hash_bytes(data: bytes, algorithm: str) -> str:
        try:
            hasher = hashlib.new(algorithm)
            hasher.update(data)
            return hasher.hexdigest()
        except Exception:
            return ""


class PasswordStrengthToolkit:
    COMMON_PASSWORDS = {
        "123456",
        "123456789",
        "qwerty",
        "password",
        "admin",
        "admin123",
        "letmein",
        "welcome",
        "iloveyou",
        "000000",
    }

    def __init__(self, logger: JsonLogger) -> None:
        self.logger = logger

    def menu(self) -> None:
        while True:
            BannerSystem.clear_screen()
            BannerSystem.show()
            BannerSystem.section("Sifre Gucu Test Araci")
            print(f"{Fore.WHITE}[1] Sifre Analizi Yap")
            print(f"{Fore.WHITE}[2] Politika Onerilerini Goster")
            print(f"{Fore.WHITE}[0] Geri Don")

            choice = Helpers.safe_input(f"\n{Fore.CYAN}Seciminiz: ")
            if choice == "1":
                self.run_strength_test()
            elif choice == "2":
                self.show_policy_tips()
            elif choice == "0":
                break
            else:
                print(f"{Fore.RED}[!] Gecersiz menu secimi.")
                Helpers.pause()

    def run_strength_test(self) -> None:
        BannerSystem.clear_screen()
        BannerSystem.show()
        BannerSystem.section("Sifre Analizi")

        password = Helpers.safe_input(f"{Fore.CYAN}Test edilecek sifre: ")
        if not password:
            print(f"{Fore.RED}[!] Sifre bos olamaz.")
            Helpers.pause()
            return

        analysis = self._analyze_password(password)
        Helpers.print_table_line("Uzunluk", str(analysis["uzunluk"]), Fore.WHITE)
        Helpers.print_table_line("Skor", f"{analysis['skor']}/100", Fore.CYAN)
        Helpers.print_table_line("Seviye", str(analysis["seviye"]), self._score_color(analysis["skor"]))
        Helpers.print_table_line("Tahmini entropy", f"{analysis['entropy_bits']} bit", Fore.WHITE)
        print()
        print(f"{Fore.CYAN}[*] Kontroller")
        for item in analysis["kontroller"]:
            color = Fore.GREEN if item["durum"] else Fore.YELLOW
            Helpers.print_table_line(item["etiket"], "Var" if item["durum"] else "Yok", color)

        print()
        if analysis["uyarilar"]:
            print(f"{Fore.YELLOW}[*] Uyarilar")
            for warning in analysis["uyarilar"]:
                Helpers.print_table_line("Uyari", warning, Fore.YELLOW)
        if analysis["oneriler"]:
            print(f"{Fore.CYAN}[*] Oneriler")
            for suggestion in analysis["oneriler"]:
                Helpers.print_table_line("Oneri", suggestion, Fore.WHITE)

        self.logger.log(
            "password_toolkit",
            "sifre_gucu_analizi",
            "inline_password",
            analysis,
        )
        Helpers.pause()

    def show_policy_tips(self) -> None:
        BannerSystem.clear_screen()
        BannerSystem.show()
        BannerSystem.section("Sifre Politika Onerileri")
        tips = [
            "En az 12-14 karakter uzunluk hedefleyin.",
            "Buyuk harf, kucuk harf, rakam ve sembol kombinasyonu kullanin.",
            "Tekrar eden desenler ve klavye siralari kullanmayin.",
            "Her servis icin farkli sifre tercih edin.",
            "Mumkunse parola yoneticisi ve MFA kullanin.",
        ]
        for tip in tips:
            Helpers.print_table_line("Kural", tip, Fore.WHITE)
        self.logger.log(
            "password_toolkit",
            "sifre_politika_ozeti",
            "local",
            {"oneriler": tips},
        )
        Helpers.pause()

    def _analyze_password(self, password: str) -> Dict[str, Any]:
        lowered = password.lower()
        checks = [
            {"etiket": "Kucuk harf", "durum": bool(re.search(r"[a-z]", password))},
            {"etiket": "Buyuk harf", "durum": bool(re.search(r"[A-Z]", password))},
            {"etiket": "Rakam", "durum": bool(re.search(r"\d", password))},
            {"etiket": "Sembol", "durum": bool(re.search(r"[^A-Za-z0-9]", password))},
            {"etiket": "12+ karakter", "durum": len(password) >= 12},
        ]

        char_pool = 0
        if checks[0]["durum"]:
            char_pool += 26
        if checks[1]["durum"]:
            char_pool += 26
        if checks[2]["durum"]:
            char_pool += 10
        if checks[3]["durum"]:
            char_pool += 32
        entropy = round(len(password) * (char_pool.bit_length() if char_pool else 0), 2)

        score = min(len(password) * 4, 40)
        score += sum(10 for item in checks[:4] if item["durum"])
        score += 10 if len(password) >= 12 else 0
        score += 10 if len(set(password)) >= max(6, len(password) // 2) else 0

        warnings: List[str] = []
        suggestions: List[str] = []

        if lowered in self.COMMON_PASSWORDS:
            score = max(5, score - 50)
            warnings.append("Sifre yaygin ve tahmin edilmesi kolay gorunuyor.")
        if re.search(r"(.)\1{2,}", password):
            score = max(0, score - 10)
            warnings.append("Tekrar eden karakter desenleri bulundu.")
        if re.search(r"(1234|abcd|qwerty)", lowered):
            score = max(0, score - 15)
            warnings.append("Sirali veya klavye tabanli desen tespit edildi.")
        if len(password) < 12:
            suggestions.append("Sifre uzunlugunu en az 12 karaktere cikar.")
        if not checks[0]["durum"] or not checks[1]["durum"]:
            suggestions.append("Buyuk ve kucuk harf karisimi kullan.")
        if not checks[2]["durum"]:
            suggestions.append("En az bir rakam ekle.")
        if not checks[3]["durum"]:
            suggestions.append("En az bir sembol ekle.")
        if lowered in self.COMMON_PASSWORDS:
            suggestions.append("Yaygin sifreleri kullanma; tamamen ozgun bir sifre sec.")
        if len(set(password)) < max(4, len(password) // 3):
            suggestions.append("Tekrari azaltip daha cesitli karakterler kullan.")

        score = max(0, min(score, 100))
        if score >= 85:
            level = "Cok Guclu"
        elif score >= 70:
            level = "Guclu"
        elif score >= 50:
            level = "Orta"
        elif score >= 30:
            level = "Zayif"
        else:
            level = "Cok Zayif"

        return {
            "uzunluk": len(password),
            "skor": score,
            "seviye": level,
            "entropy_bits": entropy,
            "kontroller": checks,
            "uyarilar": warnings,
            "oneriler": suggestions,
        }

    @staticmethod
    def _score_color(score: int) -> str:
        if score >= 85:
            return Fore.GREEN
        if score >= 50:
            return Fore.YELLOW
        return Fore.RED


class OsintToolkit:
    META_PATTERNS = {
        "title": re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL),
        "generator": re.compile(
            r'<meta[^>]+name=["\']generator["\'][^>]+content=["\'](.*?)["\']',
            re.IGNORECASE,
        ),
        "emails": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    }

    def __init__(self, logger: JsonLogger) -> None:
        self.logger = logger
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "AegisCLI-OSINT/1.0",
                "Accept": "*/*",
                "Connection": "close",
            }
        )

    def menu(self) -> None:
        while True:
            BannerSystem.clear_screen()
            BannerSystem.show()
            BannerSystem.section("Pasif OSINT Araci")
            print(f"{Fore.WHITE}[1] Domain / URL Profili")
            print(f"{Fore.WHITE}[2] robots.txt ve security.txt Kontrolu")
            print(f"{Fore.WHITE}[3] Sayfa Meta Bilgisi")
            print(f"{Fore.WHITE}[0] Geri Don")

            choice = Helpers.safe_input(f"\n{Fore.CYAN}Seciminiz: ")
            if choice == "1":
                self.run_target_profile()
            elif choice == "2":
                self.run_public_files_check()
            elif choice == "3":
                self.run_meta_analysis()
            elif choice == "0":
                break
            else:
                print(f"{Fore.RED}[!] Gecersiz menu secimi.")
                Helpers.pause()

    def run_target_profile(self) -> None:
        BannerSystem.clear_screen()
        BannerSystem.show()
        BannerSystem.section("Domain / URL Profili")

        raw_target = Helpers.safe_input(f"{Fore.CYAN}URL veya host: ")
        host = Helpers.normalize_host(raw_target)
        url = Helpers.normalize_url(raw_target) if raw_target else None
        if not host:
            print(f"{Fore.RED}[!] Gecerli bir hedef girilmedi.")
            Helpers.pause()
            return

        result: Dict[str, Any] = {
            "host": host,
            "url": url,
            "ip_adresleri": [],
            "reverse_dns": [],
            "http_durum": None,
            "server": None,
            "content_type": None,
            "baslik": None,
            "hata": None,
        }

        try:
            infos = socket.getaddrinfo(host, None)
            seen: List[str] = []
            for info in infos:
                ip = info[4][0]
                if ip not in seen:
                    seen.append(ip)
            result["ip_adresleri"] = seen
            for ip in seen[:5]:
                try:
                    result["reverse_dns"].append({"ip": ip, "kayit": socket.gethostbyaddr(ip)[0]})
                except Exception:
                    result["reverse_dns"].append({"ip": ip, "kayit": "Bulunamadi"})
        except Exception as exc:
            result["hata"] = Helpers.safe_text(exc)

        if url:
            try:
                response = self.session.get(url, timeout=6, allow_redirects=True, verify=False)
                result["http_durum"] = response.status_code
                result["server"] = Helpers.safe_text(response.headers.get("Server", "Bilinmiyor"), 100)
                result["content_type"] = Helpers.safe_text(response.headers.get("Content-Type", "Bilinmiyor"), 100)
                result["baslik"] = self._extract_first(self.META_PATTERNS["title"], response.text)
            except Exception as exc:
                result["hata"] = Helpers.safe_text(exc)

        Helpers.print_table_line("Host", host, Fore.CYAN)
        if result["ip_adresleri"]:
            for ip in result["ip_adresleri"]:
                Helpers.print_table_line("IP", ip, Fore.GREEN)
        for item in result["reverse_dns"]:
            Helpers.print_table_line(f"PTR {item['ip']}", item["kayit"], Fore.WHITE)
        if result["http_durum"] is not None:
            Helpers.print_table_line("HTTP durum", str(result["http_durum"]), Fore.GREEN)
            Helpers.print_table_line("Server", str(result["server"]), Fore.WHITE)
            Helpers.print_table_line("Content-Type", str(result["content_type"]), Fore.WHITE)
            Helpers.print_table_line("Title", str(result["baslik"] or "Bulunamadi"), Fore.YELLOW)
        if result["hata"]:
            Helpers.print_table_line("Hata", result["hata"], Fore.RED)

        self.logger.log("osint_toolkit", "hedef_profili", host, result)
        Helpers.pause()

    def run_public_files_check(self) -> None:
        BannerSystem.clear_screen()
        BannerSystem.show()
        BannerSystem.section("robots.txt ve security.txt")

        raw_target = Helpers.safe_input(f"{Fore.CYAN}URL veya host: ")
        base_url = Helpers.normalize_url(raw_target)
        if not base_url:
            print(f"{Fore.RED}[!] Gecerli bir URL girilmedi.")
            Helpers.pause()
            return

        parsed = urlparse(base_url)
        root = f"{parsed.scheme}://{parsed.netloc}"
        targets = {
            "robots.txt": f"{root}/robots.txt",
            "security.txt": f"{root}/.well-known/security.txt",
        }
        results: List[Dict[str, Any]] = []

        for name, target_url in targets.items():
            item = {
                "dosya": name,
                "url": target_url,
                "durum": None,
                "bulundu": False,
                "icerik_onizleme": None,
                "hata": None,
            }
            try:
                response = self.session.get(target_url, timeout=6, allow_redirects=True, verify=False)
                item["durum"] = response.status_code
                item["bulundu"] = response.status_code == 200
                if item["bulundu"]:
                    item["icerik_onizleme"] = Helpers.safe_text(response.text, 120)
            except Exception as exc:
                item["hata"] = Helpers.safe_text(exc)
            results.append(item)

        for item in results:
            color = Fore.GREEN if item["bulundu"] else Fore.YELLOW
            status = f"HTTP {item['durum']}" if item["durum"] is not None else "Istek hatasi"
            Helpers.print_table_line(item["dosya"], status, color)
            if item["icerik_onizleme"]:
                Helpers.print_table_line("Onizleme", item["icerik_onizleme"], Fore.WHITE)
            if item["hata"]:
                Helpers.print_table_line("Hata", item["hata"], Fore.RED)

        self.logger.log(
            "osint_toolkit",
            "genel_dosya_kontrolu",
            root,
            {"hedef": root, "sonuclar": results},
        )
        Helpers.pause()

    def run_meta_analysis(self) -> None:
        BannerSystem.clear_screen()
        BannerSystem.show()
        BannerSystem.section("Sayfa Meta Bilgisi")

        raw_target = Helpers.safe_input(f"{Fore.CYAN}URL: ")
        url = Helpers.normalize_url(raw_target)
        if not url:
            print(f"{Fore.RED}[!] Gecerli bir URL girilmedi.")
            Helpers.pause()
            return

        result: Dict[str, Any] = {
            "url": url,
            "title": None,
            "generator": None,
            "emails": [],
            "hata": None,
        }

        try:
            response = self.session.get(url, timeout=6, allow_redirects=True, verify=False)
            body = response.text
            result["title"] = self._extract_first(self.META_PATTERNS["title"], body)
            result["generator"] = self._extract_first(self.META_PATTERNS["generator"], body)
            emails = list(dict.fromkeys(self.META_PATTERNS["emails"].findall(body)))
            result["emails"] = emails[:10]
        except Exception as exc:
            result["hata"] = Helpers.safe_text(exc)

        Helpers.print_table_line("URL", url, Fore.CYAN)
        Helpers.print_table_line("Title", str(result["title"] or "Bulunamadi"), Fore.GREEN)
        Helpers.print_table_line("Generator", str(result["generator"] or "Bulunamadi"), Fore.WHITE)
        Helpers.print_table_line("E-posta adedi", str(len(result["emails"])), Fore.YELLOW)
        for email in result["emails"]:
            Helpers.print_table_line("E-posta", email, Fore.WHITE)
        if result["hata"]:
            Helpers.print_table_line("Hata", result["hata"], Fore.RED)

        self.logger.log("osint_toolkit", "meta_analizi", url, result)
        Helpers.pause()

    @staticmethod
    def _extract_first(pattern: re.Pattern[str], text: str) -> Optional[str]:
        try:
            match = pattern.search(text)
            if not match:
                return None
            return Helpers.safe_text(match.group(1).strip(), 120)
        except Exception:
            return None


class AegisCLI:
    def __init__(self) -> None:
        requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
        self.logger = JsonLogger()
        self.web_scanner = WebScanner(self.logger)
        self.port_scanner = PortScanner(self.logger)
        self.log_analyzer = LogAnalyzer(self.logger)
        self.network_toolkit = NetworkToolkit(self.logger)
        self.tls_inspector = TLSInspector(self.logger)
        self.hash_toolkit = HashToolkit(self.logger)
        self.password_toolkit = PasswordStrengthToolkit(self.logger)
        self.osint_toolkit = OsintToolkit(self.logger)

    def run(self) -> None:
        while True:
            try:
                BannerSystem.clear_screen()
                BannerSystem.show()
                self.logger.show_report_location()
                print(f"{Fore.BLUE}{Style.BRIGHT}Egitim ve etik test amacli kullanim icindir.\n")
                print(f"{Fore.WHITE}[1] Web Guvenlik Tarayicisi")
                print(f"{Fore.WHITE}[2] Port Tarayici")
                print(f"{Fore.WHITE}[3] Log Analizoru")
                print(f"{Fore.WHITE}[4] Ag ve DNS Araclari")
                print(f"{Fore.WHITE}[5] TLS Sertifika Analizi")
                print(f"{Fore.WHITE}[6] Hash Araci")
                print(f"{Fore.WHITE}[7] Sifre Gucu Test Araci")
                print(f"{Fore.WHITE}[8] Pasif OSINT Araci")
                print(f"{Fore.WHITE}[9] Rapor Dosyasi Yolunu Goster")
                print(f"{Fore.WHITE}[0] Cikis")

                choice = Helpers.safe_input(f"\n{Fore.CYAN}Seciminiz: ")

                if choice == "1":
                    self.web_scanner.menu()
                elif choice == "2":
                    self.port_scanner.menu()
                elif choice == "3":
                    self.log_analyzer.menu()
                elif choice == "4":
                    self.network_toolkit.menu()
                elif choice == "5":
                    self.tls_inspector.menu()
                elif choice == "6":
                    self.hash_toolkit.menu()
                elif choice == "7":
                    self.password_toolkit.menu()
                elif choice == "8":
                    self.osint_toolkit.menu()
                elif choice == "9":
                    print(f"\n{Fore.GREEN}[*] Aktif rapor dosyasi: {self.logger.file_path}")
                    Helpers.pause()
                elif choice == "0":
                    print(f"{Fore.GREEN}\n[*] AegisCLI guvenli bicimde kapatiliyor.")
                    break
                else:
                    print(f"{Fore.RED}[!] Gecersiz menu secimi.")
                    Helpers.pause()
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}[!] Islem kullanici tarafindan durduruldu.")
                Helpers.pause()
            except Exception as exc:
                print(f"{Fore.RED}[!] Beklenmeyen hata: {Helpers.safe_text(exc, 300)}")
                Helpers.pause()


def main() -> None:
    try:
        app = AegisCLI()
        app.run()
    except Exception as exc:
        print(f"{Fore.RED}[!] Kritik hata: {Helpers.safe_text(exc, 300)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
