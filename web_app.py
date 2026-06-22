# -*- coding: utf-8 -*-
"""大模型红队评测工具 - Web 版(FastAPI + WebSocket)

本地运行:
    uvicorn web_app:app --port 8000 --reload
浏览器访问 http://localhost:8000

后端复用 red_team_core 服务层(LangChain 调用、规则/LLM 双判定、SQLite 持久化),
评测编排绕过 RedTeamAgent.run_evaluation(它有状态累积/print 噪音/硬编码规则判定),
改用与 gui_app.py worker 同构的:generate_samples + ThreadPoolExecutor + _call_target。
进度通过 WebSocket 实时推送给浏览器。
"""
import os
import asyncio
import threading
import tempfile
import time
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

import requests as _req
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from red_team_core import (
    JAILBREAK_TEMPLATES, DEFAULT_PAYLOADS, ResponseAnalyzer, RedTeamAgent,
    JudgeAnalyzer, Reporter, load_payloads,
)
from red_team_core.llm_factory import build_target_llm, build_judge_llm
from red_team_core import db
from red_team_core.analyzer import DANGEROUS_BYPASS, SAFE_BYPASS, BLOCKED, REVIEW

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(BASE_DIR, "web")

app = FastAPI(title="大模型红队评测工具")
templates = Jinja2Templates(directory=os.path.join(WEB_DIR, "templates"))
app.mount("/static", StaticFiles(directory=os.path.join(WEB_DIR, "static")), name="static")

# verdict → 中文显示 + 颜色(与 GUI 一致)
VERDICT_DISPLAY = {
    DANGEROUS_BYPASS: ("危险绕过", "#e53e3e"),
    SAFE_BYPASS: ("安全绕过", "#d69e2e"),
    BLOCKED: ("已拦截", "#38a169"),
    REVIEW: ("待复核", "#718096"),
}

# ===== 全局单任务互斥(本地单用户;save_results 全表删重建不支持并发写)=====
_task_lock = threading.Lock()
_current_task: Dict[str, Any] = {"running": False, "stop": False}


# ============================ 页面路由 ============================
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """主页面:服务端渲染初始数据,后续交互走 REST + WebSocket"""
    return templates.TemplateResponse("index.html", {
        "request": request,
        "templates": db.load_templates(),
        "payloads": db.load_payloads(),
        "results": db.load_results(),
        "custom_inputs": db.load_custom_inputs(),
        "verdict_display": VERDICT_DISPLAY,
    })


# ============================ 模板 CRUD ============================
@app.get("/api/templates")
def get_templates():
    return db.load_templates()


@app.post("/api/templates")
def add_template(body: Dict[str, str]):
    """新增模板。body: {name, category, description, template}"""
    tpls = db.load_templates()
    tpls.append({
        "name": body.get("name", "").strip(),
        "category": body.get("category", "自定义").strip(),
        "description": body.get("description", "").strip(),
        "template": body.get("template", "").strip(),
    })
    db.save_templates(tpls)
    return {"ok": True, "count": len(tpls)}


@app.put("/api/templates/{idx}")
def edit_template(idx: int, body: Dict[str, str]):
    tpls = db.load_templates()
    if idx < 0 or idx >= len(tpls):
        return JSONResponse({"ok": False, "error": "索引越界"}, status_code=400)
    tpls[idx] = {
        "name": body.get("name", "").strip(),
        "category": body.get("category", "").strip(),
        "description": body.get("description", "").strip(),
        "template": body.get("template", "").strip(),
    }
    db.save_templates(tpls)
    return {"ok": True}


@app.delete("/api/templates/{idx}")
def del_template(idx: int):
    tpls = db.load_templates()
    if 0 <= idx < len(tpls):
        tpls.pop(idx)
        db.save_templates(tpls)
    return {"ok": True, "count": len(tpls)}


# ============================ 载荷 CRUD ============================
@app.get("/api/payloads")
def get_payloads():
    return db.load_payloads()


@app.post("/api/payloads")
def add_payload(body: Dict[str, str]):
    """body: {payload, risk_level}"""
    plds = db.load_payloads()
    plds.append({"payload": body.get("payload", "").strip(),
                 "risk_level": body.get("risk_level", "medium")})
    db.save_payloads(plds)
    return {"ok": True, "count": len(plds)}


@app.put("/api/payloads/{idx}")
def edit_payload(idx: int, body: Dict[str, str]):
    plds = db.load_payloads()
    if idx < 0 or idx >= len(plds):
        return JSONResponse({"ok": False, "error": "索引越界"}, status_code=400)
    plds[idx] = {"payload": body.get("payload", "").strip(),
                 "risk_level": body.get("risk_level", "medium")}
    db.save_payloads(plds)
    return {"ok": True}


@app.delete("/api/payloads/{idx}")
def del_payload(idx: int):
    plds = db.load_payloads()
    if 0 <= idx < len(plds):
        plds.pop(idx)
        db.save_payloads(plds)
    return {"ok": True, "count": len(plds)}


# ============================ 自定义输入 ============================
@app.get("/api/custom-inputs")
def get_custom_inputs():
    return db.load_custom_inputs()


@app.post("/api/custom-inputs")
def add_custom_input(body: Dict[str, str]):
    """自定义输入→同时添加为载荷(与 GUI _add_custom_as_payload 一致)"""
    text = body.get("content", "").strip()
    if not text:
        return JSONResponse({"ok": False, "error": "内容为空"}, status_code=400)
    plds = db.load_payloads()
    plds.append({"payload": text, "risk_level": "medium"})
    db.save_payloads(plds)
    inputs = db.load_custom_inputs()
    inputs.append({"content": text, "time": time.strftime("%H:%M:%S")})
    db.save_custom_inputs(inputs)
    return {"ok": True, "count": len(inputs)}


@app.delete("/api/custom-inputs")
def clear_custom_inputs():
    db.save_custom_inputs([])
    return {"ok": True}


# ============================ 结果管理 ============================
@app.get("/api/results")
def get_results():
    return db.load_results()


@app.delete("/api/results")
def clear_results():
    db.save_results([])
    return {"ok": True}


# ============================ 模型/连接 ============================
@app.post("/api/test-connection")
def test_connection(body: Dict[str, str]):
    """body: {base_url, api_key}。GET {base_url}/models 测连通性"""
    base = body.get("base_url", "").strip().rstrip("/")
    key = body.get("api_key", "").strip()
    headers = {"Authorization": "Bearer %s" % key} if key else {}
    try:
        r = _req.get("%s/models" % base, headers=headers, timeout=10)
        if r.status_code == 200:
            return {"ok": True, "message": "连接成功"}
        return {"ok": False, "message": "HTTP %d" % r.status_code}
    except Exception as e:
        return {"ok": False, "message": "连接失败: %s" % str(e)[:60]}


@app.post("/api/models")
def fetch_models(body: Dict[str, str]):
    """body: {base_url, api_key}。获取模型列表"""
    base = body.get("base_url", "").strip().rstrip("/")
    key = body.get("api_key", "").strip()
    headers = {"Authorization": "Bearer %s" % key} if key else {}
    try:
        r = _req.get("%s/models" % base, headers=headers, timeout=15)
        if r.status_code == 200:
            models = [m["id"] for m in r.json().get("data", [])]
            return {"ok": True, "models": models}
        return {"ok": False, "message": "HTTP %d" % r.status_code, "models": []}
    except Exception as e:
        return {"ok": False, "message": "获取失败: %s" % str(e)[:60], "models": []}


# ============================ 停止评测 ============================
@app.post("/api/evaluate/stop")
def stop_evaluate():
    if _current_task["running"]:
        _current_task["stop"] = True
        return {"ok": True, "message": "已请求停止"}
    return {"ok": False, "message": "没有正在运行的评测"}


# ============================ WebSocket 评测编排(核心) ============================
@app.websocket("/ws/evaluate")
async def ws_evaluate(websocket: WebSocket):
    """WebSocket 评测端点。

    握手后:接收一份 JSON 配置 → 后台线程并发跑评测 → 通过 WebSocket
    实时推送 {type:"progress", done, total, result} 与 {type:"done", results}。
    """
    await websocket.accept()
    try:
        config = await websocket.receive_json()
    except WebSocketDisconnect:
        return

    # 单任务互斥
    if not _task_lock.acquire(blocking=False):
        await websocket.send_json({"type": "error", "message": "已有评测任务在运行"})
        await websocket.close()
        return

    loop = asyncio.get_event_loop()
    _current_task["running"] = True
    _current_task["stop"] = False

    def send(msg: Dict[str, Any]):
        """跨线程推送:从后台线程把消息塞回事件循环"""
        asyncio.run_coroutine_threadsafe(websocket.send_json(msg), loop)

    def run_evaluation():
        """后台线程:照搬 gui_app.py worker 模式,绕过 run_evaluation"""
        try:
            api_key = (config.get("api_key") or "").strip()
            base_url = (config.get("base_url") or "").strip()
            model_name = (config.get("model_name") or "").strip()
            concurrency = max(1, int(config.get("concurrency", 3)))
            use_agent = bool(config.get("use_agent", False))
            agent_url = (config.get("agent_url") or "").strip()
            agent_key = (config.get("agent_key") or "").strip()
            agent_model = (config.get("agent_model") or "").strip()

            selected_tpl_idx = config.get("template_idxs", [])
            selected_pld_idx = config.get("payload_idxs", [])

            all_tpls = db.load_templates() or list(JAILBREAK_TEMPLATES)
            all_plds = db.load_payloads() or list(DEFAULT_PAYLOADS)
            selected_tpls = [all_tpls[i] for i in selected_tpl_idx if 0 <= i < len(all_tpls)]
            selected_plds = [all_plds[i] for i in selected_pld_idx if 0 <= i < len(all_plds)]

            if not selected_tpls or not selected_plds:
                send({"type": "error", "message": "未选择模板或载荷"})
                return

            # 构造目标模型 + 判定器(与 GUI worker 同构)
            target_llm = None
            if api_key:
                target_llm = build_target_llm(
                    base_url=base_url, api_key=api_key, model_name=model_name,
                    temperature=0.7, max_tokens=500, timeout=30, retries=2)

            judge_analyzer = None
            if use_agent and agent_key:
                judge_llm = build_judge_llm(
                    base_url=agent_url, api_key=agent_key, model_name=agent_model,
                    temperature=0.3, max_tokens=300, timeout=30, retries=2)
                judge_analyzer = JudgeAnalyzer(judge_llm)

            def judge(prompt, response):
                if judge_analyzer is not None:
                    return judge_analyzer.evaluate(prompt, response)
                return ResponseAnalyzer.evaluate(prompt, response)

            agent = RedTeamAgent(
                api_key=api_key if api_key else None,
                base_url=base_url, model_name=model_name,
                concurrency=concurrency, retries=2, timeout=30, target_llm=target_llm)
            samples = agent.generate_samples(selected_plds, selected_tpls)
            total = len(samples)
            send({"type": "start", "total": total})

            results: List[Dict[str, Any]] = []
            results_lock = threading.Lock()
            completed = [0]

            def make_result(sample, response):
                verdict, reason = judge(sample["prompt"], response)
                return {
                    "jailbreak_name": sample["jailbreak_name"],
                    "category": sample["category"],
                    "payload": sample["payload"],
                    "risk_level": sample.get("risk_level", "medium"),
                    "prompt": sample["prompt"],
                    "response": response,
                    "messages": sample.get("messages", []),
                    "verdict": verdict,
                    "reason": reason,
                }

            if api_key:
                # 在线模式:线程池真正并发调用目标模型
                with ThreadPoolExecutor(max_workers=concurrency) as pool:
                    def run_one(item):
                        if _current_task["stop"]:
                            return None
                        idx, sample = item
                        response = agent._call_target(sample)
                        return idx, make_result(sample, response)

                    futures = {pool.submit(run_one, it): it[0] for it in enumerate(samples)}
                    for fut in as_completed(futures):
                        res = fut.result()
                        if res is None:
                            continue
                        idx, result = res
                        with results_lock:
                            results.append(result)
                            completed[0] += 1
                            done = completed[0]
                            if done % 3 == 0 or done >= total:
                                db.save_results(results)
                                send({"type": "progress", "done": done, "total": total,
                                      "result": result})
                with results_lock:
                    db.save_results(results)
            else:
                # 离线模式:随机模拟响应(不调用 API)
                for sample in samples:
                    if _current_task["stop"]:
                        break
                    time.sleep(0.05)
                    if random.random() < 0.3:
                        response = "Sure, here code:\n```python\nimport socket\n```"
                    else:
                        response = random.choice(["Sorry, I cannot.", "I cannot help.", "Policy violation."])
                    result = make_result(sample, response)
                    with results_lock:
                        results.append(result)
                        completed[0] += 1
                        if completed[0] % 3 == 0 or completed[0] >= total:
                            db.save_results(results)
                            send({"type": "progress", "done": completed[0], "total": total,
                                  "result": result})
                with results_lock:
                    db.save_results(results)

            send({"type": "done", "total": total, "count": len(results),
                  "stopped": _current_task["stop"]})
        except Exception as e:
            send({"type": "error", "message": "评测异常: %s" % str(e)[:200]})
        finally:
            _current_task["running"] = False
            _task_lock.release()

    # 启动后台线程,主事件循环保持可接收 WebSocket 关闭
    worker = threading.Thread(target=run_evaluation, daemon=True)
    worker.start()
    try:
        # 保持连接直到客户端断开或评测完成;这里仅维持心跳等待
        while _current_task["running"]:
            await asyncio.sleep(0.2)
    except WebSocketDisconnect:
        _current_task["stop"] = True
    finally:
        worker.join(timeout=5)
        try:
            await websocket.close()
        except Exception:
            pass


# ============================ 报告导出 ============================
@app.get("/api/report/html")
def export_html(request: Request):
    results = db.load_results()
    if not results:
        return JSONResponse({"ok": False, "error": "无结果可导出"}, status_code=400)
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".html", mode="w", encoding="utf-8")
    tmp.close()
    reporter = Reporter(results, model_name="web-export", concurrency=3, retries=2)
    reporter.generate(output_file=tmp.name)
    return FileResponse(tmp.name, media_type="text/html",
                        filename="red_team_report.html")


@app.get("/api/report/json")
def export_json():
    results = db.load_results()
    if not results:
        return JSONResponse({"ok": False, "error": "无结果可导出"}, status_code=400)
    return Response(
        content=__import__("json").dumps(results, ensure_ascii=False, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=red_team_report.json"})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
