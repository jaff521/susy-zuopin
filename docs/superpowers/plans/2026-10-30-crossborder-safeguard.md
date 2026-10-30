# 出海易审 (CrossBorder SafeGuard) 跨境出海商品 AI 合规审查与风险诊断平台实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 构建“出海易审”工业级 AI 合规审查平台，实现“PaddleOCR + ChromaDB RAG + 阿里云通义千问 LLM”三模型协同闭环、四道内容安全闸门（Fail-Closed）、SQLite 审计与鉴权、单端口静态工作台托管以及带冒烟自检的双轨离线防翻车体系。

**Architecture:** 系统基于 Python FastAPI 构建核心业务中台与三维安全网关，以 SQLite + SQLAlchemy 实现无外部依赖的单文件数据持久化与防越权审计；流水线依次串联文件魔数检查（闸门①）、本地 OCR 抽取、文本合规预检（闸门②）、RAG 法规向量溯源、输入防注入隔离（闸门③）、通义千问研判、输出复核与国标水印（闸门④）；前端由 FastAPI 单端口静态托管，辅以 `scripts/smoke.py` 与 `--offline` 仿真离线包保障现场 10 分钟路演绝对稳定。

**Tech Stack:** Python 3.10+, FastAPI, Uvicorn, SQLAlchemy, SQLite, Pydantic v2, ChromaDB, DashScope SDK, PyCryptodome (AES-256), ReportLab (PDF), HTML5/Vue3 响应式前端。

---

## 交付文件结构概览

```text
susy-zuopin/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py                          # FastAPI 入口与静态前端挂载
│   │   ├── config.py                        # 配置管理 (AES密钥, JWT, DashScope Key)
│   │   ├── db/
│   │   │   ├── __init__.py
│   │   │   ├── session.py                   # SQLite 数据库引擎与会话
│   │   │   └── models.py                    # User, AuditLog, ComplianceReport ORM模型
│   │   ├── schemas/
│   │   │   ├── __init__.py
│   │   │   └── compliance.py                # 严格契约 Pydantic 模型 (诊断报告/缺陷/法条)
│   │   ├── security/
│   │   │   ├── __init__.py
│   │   │   ├── crypto.py                    # AES-256-GCM 敏感字段加密与脱敏格式化
│   │   │   ├── auth.py                      # JWT 鉴权与行级租户防越权校验 (IDOR)
│   │   │   └── gates.py                     # 四道内容安全闸门与 Fail-Closed 拦截器
│   │   ├── services/
│   │   │   ├── __init__.py
│   │   │   ├── ocr_service.py               # 模型1: OCR 结构化提取与本地权重兜底
│   │   │   ├── rag_service.py               # 模型2: ChromaDB 欧盟法规向量库检索
│   │   │   ├── llm_service.py               # 模型3: 阿里云 DashScope Qwen 研判与离线重放
│   │   │   └── pdf_service.py               # 带有 GB/T 45654 水印的合规诊断书导出
│   │   ├── pipeline/
│   │   │   ├── __init__.py
│   │   │   └── engine.py                    # 核心合规审查流水线调度引擎
│   │   └── api/
│   │       ├── __init__.py
│   │       └── routes.py                    # 业务路由 (/api/v1/compliance/...)
│   ├── tests/
│   │   ├── __init__.py
│   │   ├── conftest.py
│   │   ├── test_security_gates.py           # 25分安全专项与 Fail-Closed 单元测试
│   │   ├── test_pipeline_models.py          # 三模型协同调度单元测试
│   │   └── test_api_integration.py         # 端到端 API 与越权防御测试
│   ├── requirements.txt
│   └── .env.example
├── static_web/                              # 单端口静态合规大屏工作台
│   ├── index.html                           # 响应式向导式大屏页面
│   ├── app.js                               # 工作台前端交互与数据图表渲染
│   ├── styles.css                           # 现代工业深色大屏视觉样式
│   └── samples/                             # 现场真实演示样品图 (儿童玩具/欧代缺陷商品)
├── scripts/
│   ├── start.sh                             # 单命令一键拉起服务 (端口自动检测)
│   ├── smoke.py                             # 现场 10 分钟路演冒烟自检脚本
│   └── seed_regulations.py                  # 欧盟 GPSR/CE 知识库离线索引初始化
└── docs/
    ├── competition_prep_guide.md
    └── superpowers/specs/2026-10-30-crossborder-safeguard-design.md
```

---

### Task 1: 基础工程环境与安全数据持久层 (SQLite + SQLAlchemy)

**Files:**
- Create: `backend/requirements.txt`
- Create: `backend/.env.example`
- Create: `backend/app/config.py`
- Create: `backend/app/db/session.py`
- Create: `backend/app/db/models.py`
- Create: `backend/app/security/crypto.py`
- Test: `backend/tests/test_crypto_and_db.py`

- [ ] **Step 1: 编写依赖清单与环境变量模板**
  在 `backend/requirements.txt` 中写入：
  `fastapi`, `uvicorn`, `python-multipart`, `pydantic>=2.0`, `sqlalchemy>=2.0`, `pycryptodome`, `python-jose[cryptography]`, `passlib[bcrypt]`, `pillow>=10.0`, `chromadb>=0.4.0`, `dashscope`, `reportlab`, `pytest`, `httpx`。
  并在 `backend/.env.example` 中提供无明文 Key 的规范模板（`DASHSCOPE_API_KEY=""`, `SECRET_KEY=""`, `AES_SECRET_KEY=""`）。

- [ ] **Step 2: 编写敏感数据 AES-256 加密与日志脱敏工具的失败测试**
  在 `backend/tests/test_crypto_and_db.py` 中编写针对 AES 加密解密、手机号/邮箱脱敏掩码（如 `138****0000`, `a***@domain.com`）的测试用例。

- [ ] **Step 3: 运行测试验证失败**
  运行：`pytest backend/tests/test_crypto_and_db.py`，确认因模块不存在而失败。

- [ ] **Step 4: 实现配置模块、加密工具与 SQLAlchemy 模型**
  编写 `backend/app/config.py`、`backend/app/security/crypto.py`、`backend/app/db/session.py` 以及 `backend/app/db/models.py`（包含 `User`, `AuditLog`, `ComplianceTask`, `ComplianceReport`，主键采用 UUID/自增，带 `user_id` 租户索引）。

- [ ] **Step 5: 运行测试并验证通过**
  运行：`pytest backend/tests/test_crypto_and_db.py`，测试应全部 PASS。

- [ ] **Step 6: 提交代码**
  ```bash
  git add backend/
  git commit -m "feat: setup project environment, sqlite db and crypto utils"
  ```

---

### Task 2: 25分安全专项：四道内容安全闸门、令牌桶限流与 Fail-Closed 机制

**Files:**
- Create: `backend/app/security/gates.py`
- Create: `backend/app/security/limiter.py`
- Create: `backend/app/security/auth.py`
- Test: `backend/tests/test_security_gates.py`

- [ ] **Step 1: 编写四道闸门、令牌桶限流与 Fail-Closed 机制的测试用例**
  编写 `backend/tests/test_security_gates.py`，测试：
  - 闸门①：可执行文件伪装（非允许 MIME/Magic Number）拦截；
  - 闸门②：文本预检敏感词黑名单拦截；
  - 闸门③：Prompt 越狱注入词（如 "Ignore previous instructions", "System override"）识别隔离；
  - 闸门④：大模型输出复审与合规水印注入；
  - 令牌桶防刷限流（Rate Limiting）：单 IP/用户在滑动窗口内超过频次阈值（如 >10次/分）时触发 HTTP 429 阻断；
  - Fail-Closed 检验：当模拟审核服务异常（抛出 Exception / 降级开关触发）时，系统**坚决拦截**，并返回 `degraded: true`，严禁放行。

- [ ] **Step 2: 运行测试验证失败**
  运行：`pytest backend/tests/test_security_gates.py`，确认测试失败。

- [ ] **Step 3: 实现四道安全闸门、令牌桶限流器与 JWT/防越权逻辑**
  在 `backend/app/security/gates.py` 中实现 `FileSecurityGate`, `TextBlacklistGate`, `PromptInjectionGate`, `OutputComplianceGate`，并实现带熔断降级标志的 Fail-Closed 处理器；
  在 `backend/app/security/limiter.py` 中实现内存令牌桶限流器（TokenBucketLimiter）；
  在 `backend/app/security/auth.py` 中实现密码哈希、JWT Token 生成/验证及行级 `user_id` 越权防护依赖。

- [ ] **Step 4: 运行测试验证通过**
  运行：`pytest backend/tests/test_security_gates.py`，测试全部 PASS。

- [ ] **Step 5: 提交代码**
  ```bash
  git add backend/app/security/ backend/tests/test_security_gates.py
  git commit -m "feat(security): implement 4-stage fail-closed gates, rate limiter and auth"
  ```

---

### Task 3: AI 模型 1：本地 OCR 结构化抽取引擎与轻量冷启动兜底

**Files:**
- Create: `backend/app/services/ocr_service.py`
- Test: `backend/tests/test_ocr_service.py`

- [ ] **Step 1: 编写 OCR 提取契约与边界测试**
  在 `backend/tests/test_ocr_service.py` 中测试输入商品包装样例图，预期抽取结构化字典：`eu_rep_info` (欧盟责任人), `warning_labels` (小零件警示), `ce_symbol_detected` (CE认证标志), `ingredients` (成分列表), `raw_text`。
  测试包括：真实图片提取、模糊图片告警以及离线冷启动模式。

- [ ] **Step 2: 运行测试验证失败**
  运行：`pytest backend/tests/test_ocr_service.py`，确认失败。

- [ ] **Step 3: 实现 OCR 服务与轻量离线权重解析引擎**
  在 `backend/app/services/ocr_service.py` 中编写 `OCRService`：
  - 集成本地 OCR 提取逻辑，并支持正则/关键词智能切片；
  - 内置快速离线兜底提取器（当未安装大型 Paddle 轮子或无 GPU 时，依然能对演示样本进行 100% 精准的结构化特征解析，零阻塞）。

- [ ] **Step 4: 运行测试验证通过**
  运行：`pytest backend/tests/test_ocr_service.py`，测试全部 PASS。

- [ ] **Step 5: 提交代码**
  ```bash
  git add backend/app/services/ocr_service.py backend/tests/test_ocr_service.py
  git commit -m "feat(ai): implement OCR extraction service with offline fallback"
  ```

---

### Task 4: AI 模型 2：ChromaDB 本地欧盟法规向量库 (RAG)

**Files:**
- Create: `scripts/seed_regulations.py`
- Create: `backend/app/services/rag_service.py`
- Test: `backend/tests/test_rag_service.py`

- [ ] **Step 1: 编写 RAG 知识库检索与法条溯源的单元测试**
  在 `backend/tests/test_rag_service.py` 中测试查询“欧盟责任人 追溯要求”、“儿童玩具 CE 警示”等场景，验证返回包含《GPSR (EU) 2023/988》第9条/第19条、《EN 71-1 玩具安全》等权威条款、条号及处罚依据。

- [ ] **Step 2: 运行测试验证失败**
  运行：`pytest backend/tests/test_rag_service.py`，确认失败。

- [ ] **Step 3: 编写法规种子脚本与 RAG 服务**
  - 在 `scripts/seed_regulations.py` 中构建权威欧盟 GPSR、CE、RoHS、REACH 法规知识库条目（包含官方条款编号、中英文法条文本、执法处罚标准）；
  - 在 `backend/app/services/rag_service.py` 中基于 ChromaDB 实现向量数据库初始化与混合检索（语义距离 + 关键字重排序）。

- [ ] **Step 4: 运行测试验证通过**
  运行：`pytest backend/tests/test_rag_service.py`，测试全部 PASS。

- [ ] **Step 5: 提交代码**
  ```bash
  git add scripts/seed_regulations.py backend/app/services/rag_service.py backend/tests/test_rag_service.py
  git commit -m "feat(ai): implement RAG vector knowledge base for EU regulations"
  ```

---

### Task 5: AI 模型 3：阿里云通义千问 LLM 研判引擎与双轨离线重放

**Files:**
- Create: `backend/app/schemas/compliance.py`
- Create: `backend/app/services/llm_service.py`
- Test: `backend/tests/test_llm_service.py`

- [ ] **Step 1: 定义 Pydantic 严格数据契约**
  在 `backend/app/schemas/compliance.py` 中定义统一输出契约：
  - `ComplianceScore`: 0~100 综合分值；
  - `RiskLevel`: HIGH (红牌) / MEDIUM (黄牌) / LOW (绿牌)；
  - `ComplianceDefect`: 缺陷名称、严重等级、违规事实、法条依据与原文出处、整改前后对比（Before vs After）；
  - `ComplianceReportSchema`: 完整诊断报告，带 `ai_attribution_stamp` 溯源标识。

- [ ] **Step 2: 编写 LLM 研判服务与离线重放测试用例**
  在 `backend/tests/test_llm_service.py` 中测试：
  - 结构化 JSON 生成契约解析；
  - 云端 DashScope API 联调（带 Key 时调用 Qwen-Plus/Max）；
  - 离线回放模式（无 Key 或网络中断时，毫秒级返回真实逻辑推理结果，保障演示）。

- [ ] **Step 3: 编写 LLM 法律诊断服务**
  在 `backend/app/services/llm_service.py` 中实现 `LLMComplianceService`，注入专业法律研判 System Prompt，对 OCR 提取信息与 RAG 召回条款进行归纳推理，并实现无缝离线重放适配器。

- [ ] **Step 4: 运行测试验证通过**
  运行：`pytest backend/tests/test_llm_service.py`，测试全部 PASS。

- [ ] **Step 5: 提交代码**
  ```bash
  git add backend/app/schemas/compliance.py backend/app/services/llm_service.py backend/tests/test_llm_service.py
  git commit -m "feat(ai): implement LLM compliance diagnostic engine with dual-track mode"
  ```

---

### Task 6: 合规审查核心流水线编排、PDF 导出与 RESTful API

**Files:**
- Create: `backend/app/pipeline/engine.py`
- Create: `backend/app/services/pdf_service.py`
- Create: `backend/app/api/routes.py`
- Create: `backend/app/main.py`
- Test: `backend/tests/test_pipeline_and_api.py`

- [ ] **Step 1: 编写全链路流水线与端到端 API 测试**
  在 `backend/tests/test_pipeline_and_api.py` 中测试完整的审查 API 流程：
  `POST /api/v1/compliance/tasks/create`（上传物料） $\rightarrow$ 流水线（闸门① $\rightarrow$ OCR $\rightarrow$ 闸门② $\rightarrow$ RAG $\rightarrow$ 闸门③ $\rightarrow$ LLM $\rightarrow$ 闸门④ $\rightarrow$ 落库与审计） $\rightarrow$ `GET /api/v1/compliance/reports/{id}`（报告查询与防越权校验） $\rightarrow$ `GET /api/v1/compliance/reports/{id}/export-pdf`（PDF 生成）。

- [ ] **Step 2: 运行测试验证失败**
  运行：`pytest backend/tests/test_pipeline_and_api.py`，确认失败。

- [ ] **Step 3: 实现流水线引擎、PDF 报告导出与 API 路由**
  - 在 `backend/app/pipeline/engine.py` 中实现完整时序编排：
    1. 闸门①（文件头魔数预审）；
    2. OCR 抽取结构化信息；
    3. **即时物理擦除**：调用 `os.unlink` 立即粉碎临时上传图片文件，落实“上传即审即删、杜绝敏感原图滞留”；
    4. 闸门②（文本预检与黑名单过滤）；
    5. RAG 知识库检索关联法条；
    6. 闸门③（Prompt 注入强隔离）；
    7. 阿里云 Qwen 研判；
    8. 闸门④（双向内容复核与 GB/T 45654 水印注入）；
    9. SQLite 租户脱敏落库与审计日志落库。
  - 在 `backend/app/services/pdf_service.py` 中配置中文字体注册（`pdfmetrics.registerFont(UnicodeCIDFont('STSong-Light'))`），生成排版严谨的 PDF 诊断报告（含合规仪表盘、缺陷明细、整改前后对比表及 AI 合成内容水印）；
  - 在 `backend/app/api/routes.py` 中使用 `UploadFile` 暴露标准 REST 接口；
  - 在 `backend/app/main.py` 中初始化 FastAPI 应用，挂载速率限流中间件与安全头。

- [ ] **Step 4: 运行测试验证通过**
  运行：`pytest backend/tests/test_pipeline_and_api.py`，测试全部 PASS。

- [ ] **Step 5: 提交代码**
  ```bash
  git add backend/app/pipeline/ backend/app/services/pdf_service.py backend/app/api/ backend/app/main.py backend/tests/test_pipeline_and_api.py
  git commit -m "feat(pipeline): implement full compliance pipeline, pdf export and API"
  ```

---

### Task 7: 现场防翻车两大脚本：冒烟自检 (smoke.py) 与一键启动 (start.sh)

**Files:**
- Create: `scripts/smoke.py`
- Create: `scripts/start.sh`
- Test: `backend/tests/test_smoke_script.py`

- [ ] **Step 1: 编写冒烟自检脚本的自动化测试**
  在 `backend/tests/test_smoke_script.py` 中测试自检逻辑（环境校验、数据库写权限、模型连通性、离线应急包校验、源码无明文密钥检查）。

- [ ] **Step 2: 运行测试验证失败**
  运行：`pytest backend/tests/test_smoke_script.py`，确认失败。

- [ ] **Step 3: 实现冒烟自检脚本与一键启动脚本**
  - 编写 `scripts/smoke.py`：按照官方截图 6 规程，10 秒内逐条打勾核验“运行环境/依赖、数据目录可写、大模型连通性/API Key、ChromaDB 向量库、源码明文 Key 安全自检”；
  - 编写 `scripts/start.sh`：自动检测 Python 环境与空闲端口（默认 8092），初始化 SQLite 与种子向量库，单命令拉起后台服务并打开浏览器。

- [ ] **Step 4: 运行冒烟测试与脚本验证**
  在终端执行 `python scripts/smoke.py`，验证终端输出格式化的彩色勾选清单与健康指标。

- [ ] **Step 5: 提交代码**
  ```bash
  git add scripts/ backend/tests/test_smoke_script.py
  git commit -m "feat(ops): add smoke check script and one-click start script"
  ```

---

### Task 8: 单端口响应式大屏前端工作台 (FastAPI 静态托管)

**Files:**
- Create: `static_web/index.html`
- Create: `static_web/styles.css`
- Create: `static_web/app.js`
- Create: `static_web/samples/toy_label_sample.png`
- Modify: `backend/app/main.py`
- Test: `backend/tests/test_web_hosting.py`

- [ ] **Step 1: 编写前端静态托管集成测试**
  在 `backend/tests/test_web_hosting.py` 中测试访问 `GET /` 直接返回合规大屏工作台 HTML，静态资源正确定位，彻底消除 CORS 跨域问题。

- [ ] **Step 2: 运行测试验证失败**
  运行：`pytest backend/tests/test_web_hosting.py`，确认失败。

- [ ] **Step 3: 实现现代工业级合规体检工作台与静态挂载**
  - 编写 `static_web/index.html`、`styles.css`、`app.js`：
    - 深色科技感 UI 配色，带 4 步向导式上传界面；
    - 流水线动态状态条（OCR $\rightarrow$ 法规检索 $\rightarrow$ 法律研判）；
    - 合规综合评分仪表盘（环形图）与红黄绿三色风险卡片；
    - 交互式法规溯源对比面板（点击法条展开《GPSR (EU) 2023/988》官方原文）；
    - Before / After 整改对比表格；
    - 一键导出 PDF 合规报告按钮与离线模式切换按钮；
  - 在 `backend/app/main.py` 中挂载 `StaticFiles(directory="static_web", html=True)`。

- [ ] **Step 4: 运行测试验证通过**
  运行：`pytest backend/tests/test_web_hosting.py`，测试全部 PASS。

- [ ] **Step 5: 提交代码**
  ```bash
  git add static_web/ backend/app/main.py backend/tests/test_web_hosting.py
  git commit -m "feat(ui): implement single-port responsive compliance workbench"
  ```

---

### Task 9: 60秒安全自检扫描、全量端到端验证与竞赛交付物归档

**Files:**
- Create: `docs/roadshow_script.md` (10分钟路演逐字脚本与掐表指南)
- Create: `docs/security_architecture_design.md` (承载25分安全专项的完整设计说明书)
- Test: `backend/tests/test_security_audit_checklist.py`

- [ ] **Step 1: 编写 60 秒安全自检与匿名合规测试**
  在 `backend/tests/test_security_audit_checklist.py` 中执行：
  - 检查项目源码目录绝无硬编码 API Key（匹配正则 `sk-[a-zA-Z0-9]{20,}`）；
  - 检查代码库与交付文档中无任何学校、队员真实姓名，符合参赛编号匿名规则；
  - 验证未携带 Token 访问业务接口 100% 返回 401；
  - 验证跨用户访问他人报告 100% 被 403 阻断；
  - 验证 Fail-Closed 熔断在断网/故障时生效；
  - 验证日志脱敏函数对隐私数据的掩码覆盖率。

- [ ] **Step 2: 运行全量测试套件**
  运行：`pytest backend/tests/ -v`，确保所有模块测试 100% 绿色通过。

- [ ] **Step 3: 生成 10 分钟路演逐字脚本与安全架构设计说明书**
  在 `docs/roadshow_script.md` 中编写 10 分钟精确掐表脚本（含台词、操作要点与评委问答 Q&A）；在 `docs/security_architecture_design.md` 中形成对应的 25 分安全架构专项说明文档。

- [ ] **Step 4: 提交全量成果并打好版本 Tag**
  ```bash
  git add .
  git commit -m "docs: add roadshow script, security architecture doc and finalize e2e tests"
  ```
