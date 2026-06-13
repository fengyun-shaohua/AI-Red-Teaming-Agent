"""报告生成器"""
import json, os
from datetime import datetime

class Reporter:
    @staticmethod
    def generate(results, model_name, concurrency=5, retries=2, output_file="red_team_report.html"):
        total = len(self.results)
        stats = {"DANGEROUS_BYPASS":0,"SAFE_BYPASS":0,"BLOCKED":0,"REVIEW":0}
        for r in self.results: stats[r["verdict"]] += 1

        danger_pct = stats["DANGEROUS_BYPASS"]/total*100 if total else 0
        safe_pct = stats["SAFE_BYPASS"]/total*100 if total else 0
        blocked_pct = stats["BLOCKED"]/total*100 if total else 0
        review_pct = stats["REVIEW"]/total*100 if total else 0

        cat_stats = {}
        for r in self.results:
            cat = r["category"]
            if cat not in cat_stats: cat_stats[cat] = {"total":0,"DANGEROUS_BYPASS":0,"SAFE_BYPASS":0,"BLOCKED":0}
            cat_stats[cat]["total"] += 1
            cat_stats[cat][r["verdict"]] = cat_stats[cat].get(r["verdict"],0) + 1

        payload_stats = {}
        for r in self.results:
            pld = r["payload"]
            if pld not in payload_stats: payload_stats[pld] = {"total":0,"DANGEROUS_BYPASS":0,"SAFE_BYPASS":0,"BLOCKED":0,"risk_level":r["risk_level"]}
            payload_stats[pld]["total"] += 1
            payload_stats[pld][r["verdict"]] = payload_stats[pld].get(r["verdict"],0) + 1

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
            rate = bypass/cs["total"]*100 if cs["total"] else 0
            bar = "#"*int(rate/5) + "-"*(20-int(rate/5))
            print("  {:<16} [{}] {:.1f}% ({}/{})".format(cat, bar, rate, bypass, cs["total"]))
        print("\n  按载荷统计:")
        print("  " + "-" * 50)
        for pld, ps in sorted(payload_stats.items(), key=lambda x: x[1]["total"], reverse=True):
            bypass = ps["DANGEROUS_BYPASS"] + ps["SAFE_BYPASS"]
            rate = bypass/ps["total"]*100 if ps["total"] else 0
            print("  [{}] {:.35s}... 绕过率 {:.1f}%".format(ps["risk_level"].upper(), pld, rate))
        print("=" * 60)

        # JSON export
        json_file = output_file.replace(".html", ".json")
        export_data = {
            "meta":{"timestamp":datetime.now().isoformat(),"model":self.model_name,"total":total,"stats":stats,"category_stats":cat_stats,"payload_stats":{k:v for k,v in payload_stats.items()}},
            "results":self.results,
        }
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(export_data, f, ensure_ascii=False, indent=2)
        print("[OK] JSON数据: {}".format(json_file))

        # HTML export
        vl = {"DANGEROUS_BYPASS":"危险绕过","SAFE_BYPASS":"安全绕过","BLOCKED":"拦截","REVIEW":"待审"}
        vc = {"DANGEROUS_BYPASS":"#e53e3e","SAFE_BYPASS":"#d69e2e","BLOCKED":"#38a169","REVIEW":"#718096"}

        rows_html = ""
        for r in self.results:
            resp_e = r["response"][:300].replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;")
            rows_html += '<tr><td>{}</td><td>{}</td><td title="{}">{}</td><td style="color:{};font-weight:bold">{}</td><td style="font-size:11px;color:#666">{}</td><td style="max-width:300px;font-size:12px">{}</td></tr>'.format(
                r["jailbreak_name"][:30],r["category"],r["payload"].replace('"',"&quot;"),r["payload"][:30],
                vc[r["verdict"]],vl[r["verdict"]],r.get("reason",""),resp_e)

        cat_rows = ""
        for cat, cs in sorted(cat_stats.items()):
            bypass = cs["DANGEROUS_BYPASS"] + cs["SAFE_BYPASS"]
            rate = bypass/cs["total"]*100 if cs["total"] else 0
            cat_rows += "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{:.1f}%</td></tr>".format(cat,cs["total"],cs["DANGEROUS_BYPASS"],cs["SAFE_BYPASS"],rate)

        pld_rows = ""
        for pld, ps in sorted(payload_stats.items(), key=lambda x: x[1]["total"], reverse=True):
            bypass = ps["DANGEROUS_BYPASS"] + ps["SAFE_BYPASS"]
            rate = bypass/ps["total"]*100 if ps["total"] else 0
            pld_rows += "<tr><td>[{}]</td><td>{}</td><td>{}</td><td>{}</td><td>{:.1f}%</td></tr>".format(ps["risk_level"].upper(),pld[:40],ps["total"],bypass,rate)

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
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),self.model_name,self.concurrency,self.retries,
            stats["DANGEROUS_BYPASS"],danger_pct,stats["SAFE_BYPASS"],safe_pct,stats["BLOCKED"],blocked_pct,stats["REVIEW"],review_pct,total,
            cat_rows,pld_rows,rows_html)
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html)
        print("[OK] HTML报告: {}".format(output_file))


