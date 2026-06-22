# AI Red Teaming Agent — 大模型红队安全评测工具

基于 FastAPI + LangChain 的 Web 端红队测试工具,用于评估大语言模型的内容安全防线能力。

## 功能特点

- **多模板测试**:内置 7 种测试模板,涵盖角色扮演、Prompt Injection、编码绕过、多轮对话、网安研究等手法
- **LangChain 框架**:统一的大模型调用抽象,原生支持重试退避、流式传输
- **双轨判定**:规则匹配(ResponseAnalyzer)+ LLM 智能判定(JudgeAnalyzer),verdict 统一为 4 级
- **真正并发**:ThreadPoolExecutor 让并发参数生效,批量评测提速
- **流式传输**:可选开关,边接收边显示模型输出,避免长响应整体超时
- **WebSocket 实时进度**:评测进度实时推送到浏览器,无需轮询
- **数据库持久化**:SQLite 自动保存模板、载荷、测试结果,重启不丢失
- **专业报告导出**:HTML/JSON 红队评测报告,含统计卡片、绕过率/拦截率分析

## 快速开始

```bash
# 安装依赖
pip install -r requirements.txt

# 启动 Web 服务
uvicorn web_app:app --port 8000 --reload
```

浏览器访问 http://localhost:8000

## 使用说明

1. 在「API 配置」区填写目标模型的 Base URL 和 API Key(留空则离线模拟)
2. 点击「获取模型」拉取可用模型列表,点 ▼ 按钮选择模型
3. 按需调整并发数、超时(秒);长响应建议勾选「流式传输」
4. 在「测试模板」和「测试载荷」Tab 勾选要使用的项目
5. 可选:勾选「启用 Agent 自动判定」,填写判定模型的 API/Key/Model 进行 LLM 智能判定
6. 点击「开始测试」执行,结果实时显示在「测试结果」Tab
7. 测试完成后可导出 HTML/JSON 报告

## 项目结构

```
agent红队测试/
├── web_app.py                # FastAPI 主应用(路由 + WebSocket 评测编排)
├── web/                      # Web 前端资源
│   ├── templates/            # Jinja2 模板(base.html / index.html)
│   └── static/               # 静态资源(css / js)
├── red_team_core/            # 核心模块
│   ├── __init__.py
│   ├── agent.py              # 测试执行引擎(generate_samples / _call_target / _call_target_stream)
│   ├── analyzer.py           # 响应分析器(ResponseAnalyzer 规则 + JudgeAnalyzer LLM)
│   ├── llm_factory.py        # LangChain 模型工厂(build_target_llm / build_judge_llm)
│   ├── reporter.py           # 报告生成器
│   ├── templates.py          # 测试模板库
│   └── db.py                 # SQLite 持久化
├── requirements.txt
├── .gitignore
└── README.md
```

## 技术栈

- **后端**:FastAPI + WebSocket + LangChain + SQLite
- **前端**:Jinja2 服务端渲染 + Tailwind CSS + 原生 JS(无构建工具)
- **AI 框架**:LangChain(ChatOpenAI 统一目标模型与判定模型调用)

## 免责声明

本工具仅用于大语言模型的安全研究和防御体系建设。请勿将其用于非法用途。
