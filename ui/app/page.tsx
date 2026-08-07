const pipelineSteps = [
  {
    step: "01",
    title: "Rate Limiter",
    description: "Giữ nhịp request ổn định, chặn burst traffic và giảm bề mặt tấn công.",
    badge: "Traffic control",
  },
  {
    step: "02",
    title: "Input Guardrails",
    description: "Chuẩn hóa Unicode, phát hiện jailbreak và phân biệt data với instruction.",
    badge: "Prompt safety",
  },
  {
    step: "03",
    title: "Model Layer",
    description: "Agent trả lời có kiểm soát, giữ phạm vi banking và tránh lộ system prompt.",
    badge: "Core logic",
  },
  {
    step: "04",
    title: "Output Guardrails",
    description: "Redact PII, secret, API key trước khi phản hồi hoặc egress ra ngoài.",
    badge: "Leak prevention",
  },
  {
    step: "05",
    title: "Audit + Monitoring",
    description: "Gắn request ID xuyên suốt để xem block-rate, judge-fail và replay sự cố.",
    badge: "Observability",
  },
];

const labParts = [
  {
    name: "Phần A1",
    title: "Input guardrails",
    hint: "Chặn direct injection, Unicode obfuscation và câu lệnh lẫn trong email/RAG.",
  },
  {
    name: "Phần A2",
    title: "Output guardrails",
    hint: "Che PII, secret, phone, email trước khi phản hồi hoặc chuyển sang sink.",
  },
  {
    name: "Phần A3",
    title: "Judge + NeMo",
    hint: "Thêm lớp đánh giá đa tiêu chí và một lớp fallback nếu muốn.",
  },
  {
    name: "Phần A4",
    title: "Defense pipeline",
    hint: "Kết hợp limiter, audit, monitor và egress allowlist trong một luồng.",
  },
  {
    name: "Phần B",
    title: "Red team",
    hint: "Viết prompt attack thật, chạy unsafe trước rồi mới đánh giá Guards Agent.",
  },
];

const commands = [
  {
    label: "Install",
    value: "cd ui && npm install",
  },
  {
    label: "Run",
    value: "npm run dev",
  },
  {
    label: "Build",
    value: "npm run build",
  },
];

const metrics = [
  { label: "Defense", value: "80 pts" },
  { label: "Red team", value: "20 pts" },
  { label: "Bonus", value: "+10 pts" },
  { label: "Mode", value: "Next.js" },
];

const focusCards = [
  {
    title: "Safe by default",
    text: "Thiết kế tách rõ user input, model output và decision points. Không để LLM tự quyết policy.",
  },
  {
    title: "Human in the loop",
    text: "Mọi action nhạy cảm cần reviewer, diff context và audit trail rõ ràng.",
  },
  {
    title: "Red-team ready",
    text: "UI đặt attack và defense cạnh nhau để demo luồng tấn công và phòng thủ dễ hơn.",
  },
];

export default function Home() {
  return (
    <main className="page-shell">
      <div className="ambient ambient-a" />
      <div className="ambient ambient-b" />
      <div className="ambient ambient-c" />

      <section className="hero-grid">
        <div className="hero-card glass">
          <div className="eyebrow">
            <span className="dot" />
            Guardrails HITL Responsible AI
          </div>
          <h1>
            Một dashboard Next.js sắc nét hơn cho lab an toàn agent.
          </h1>
          <p className="hero-copy">
            UI mới tập trung vào câu chuyện bảo vệ hệ thống: từ prompt injection,
            output exfiltration, cho tới HITL và audit. Mục tiêu là nhìn vào một
            màn hình đã hiểu ngay pipeline đang chặn ở đâu, leak ở đâu, và phần
            nào cần con người duyệt.
          </p>

          <div className="hero-actions">
            <a href="#pipeline" className="primary-action">
              Xem pipeline
            </a>
            <a href="#runbook" className="secondary-action">
              Mở runbook
            </a>
          </div>

          <div className="metric-strip">
            {metrics.map((metric) => (
              <article key={metric.label} className="metric-card">
                <span>{metric.label}</span>
                <strong>{metric.value}</strong>
              </article>
            ))}
          </div>
        </div>

        <aside className="status-card glass">
          <div className="status-top">
            <div>
              <p className="section-label">Mission control</p>
              <h2>UI thay thế webapp cũ</h2>
            </div>
            <span className="status-pill live">Live draft</span>
          </div>

          <div className="status-grid">
            <div className="status-item">
              <span>UI stack</span>
              <strong>Next.js 16.3.0</strong>
            </div>
            <div className="status-item">
              <span>Font</span>
              <strong>Space Grotesk</strong>
            </div>
            <div className="status-item">
              <span>Focus</span>
              <strong>Readable, bold, responsive</strong>
            </div>
            <div className="status-item">
              <span>Old UI</span>
              <strong>Removed</strong>
            </div>
          </div>

          <div className="code-block">
            <div className="code-head">
              <span>Quick start</span>
              <span className="status-pill">ui/</span>
            </div>
            <pre>
{`cd ui
npm install
npm run dev`}
            </pre>
          </div>
        </aside>
      </section>

      <section className="focus-grid">
        {focusCards.map((card) => (
          <article key={card.title} className="focus-card glass">
            <h3>{card.title}</h3>
            <p>{card.text}</p>
          </article>
        ))}
      </section>

      <section id="pipeline" className="section-card glass">
        <div className="section-heading">
          <div>
            <p className="section-label">Pipeline</p>
            <h2>Đường đi an toàn từ input tới response</h2>
          </div>
          <p className="section-copy">
            UI này mô tả rõ thứ tự kiểm soát để tránh “LLM tự quyết tất cả”.
            Mỗi stage là một lớp có trách nhiệm riêng.
          </p>
        </div>

        <div className="pipeline-track">
          {pipelineSteps.map((item, index) => (
            <article key={item.step} className="pipeline-step">
              <div className="pipeline-number">{item.step}</div>
              <div className="pipeline-body">
                <span className="status-pill">{item.badge}</span>
                <h3>{item.title}</h3>
                <p>{item.description}</p>
              </div>
              {index < pipelineSteps.length - 1 ? <div className="pipeline-link" /> : null}
            </article>
          ))}
        </div>
      </section>

      <section className="content-grid">
        <div className="section-card glass">
          <div className="section-heading">
            <div>
              <p className="section-label">Lab map</p>
              <h2>Những phần cần làm trong repo</h2>
            </div>
          </div>

          <div className="lab-list">
            {labParts.map((part) => (
              <article key={part.name} className="lab-item">
                <div className="lab-meta">{part.name}</div>
                <div>
                  <h3>{part.title}</h3>
                  <p>{part.hint}</p>
                </div>
              </article>
            ))}
          </div>
        </div>

        <div className="section-card glass" id="runbook">
          <div className="section-heading">
            <div>
              <p className="section-label">Runbook</p>
              <h2>Chạy giao diện mới</h2>
            </div>
          </div>

          <div className="command-stack">
            {commands.map((command) => (
              <div key={command.label} className="command-card">
                <span>{command.label}</span>
                <code>{command.value}</code>
              </div>
            ))}
          </div>

          <div className="note-card">
            <p>
              Mình đã xóa `webapp.py` và thay bằng app Next.js ở thư mục
              `ui/`. Nếu muốn nối thêm API thật sau này, mình có thể thêm route
              hoặc proxy riêng mà vẫn giữ nguyên design system này.
            </p>
          </div>
        </div>
      </section>

      <footer className="footer-bar">
        <span>Guardrails HITL Lab</span>
        <span>Next.js UI refresh</span>
      </footer>
    </main>
  );
}
