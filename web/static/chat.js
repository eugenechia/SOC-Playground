// Workbench chat. EventSource can't POST, so we POST the form and read the SSE
// body with fetch()+getReader(), splitting on \n\n frames.
//
// Phase 1 (no tools): status -> token* -> done.
// Phase 2 (tools): status -> (tool_call -> tool_result)* -> token(final) -> done.
// tool_call/tool_result render as their own step bubbles so the analyst sees
// exactly how the model uses tools.
(function () {
  const form = document.getElementById("chat-form");
  if (!form) return;
  const input = document.getElementById("chat-input");
  const sendBtn = document.getElementById("chat-send");
  const log = document.getElementById("chat-log");

  document.querySelectorAll(".starter-btn").forEach((b) => {
    b.addEventListener("click", () => { input.value = b.dataset.prompt; input.focus(); });
  });

  function scroll() { log.scrollTop = log.scrollHeight; }

  function bubble(role, roleLabel) {
    const el = document.createElement("div");
    el.className = "bubble bubble-" + role;
    el.innerHTML = '<div class="bubble-role"></div><div class="bubble-content"></div>';
    el.querySelector(".bubble-role").textContent = roleLabel || role;
    log.appendChild(el);
    scroll();
    return el.querySelector(".bubble-content");
  }

  form.addEventListener("submit", async function (e) {
    e.preventDefault();
    const message = input.value.trim();
    if (!message) return;
    sendBtn.disabled = true;

    bubble("user", "you").textContent = message;

    // Transient status line; assistant bubble is created lazily on first token.
    let statusEl = bubble("status", "…");
    let assistantEl = null;
    let assistant = "";

    const body = new FormData();
    body.append("task", form.dataset.task);
    body.append("model", form.dataset.model);
    body.append("message", message);
    input.value = "";

    function setStatus(text) {
      if (!statusEl) statusEl = bubble("status", "…");
      statusEl.textContent = text;
      scroll();
    }
    function clearStatus() {
      if (statusEl && statusEl.parentElement) statusEl.parentElement.remove();
      statusEl = null;
    }

    let resp;
    try {
      resp = await fetch("/workbench/chat", { method: "POST", body });
    } catch (err) {
      clearStatus();
      bubble("assistant", "assistant").textContent = "network error: " + err.message;
      sendBtn.disabled = false;
      return;
    }
    if (!resp.ok || !resp.body) {
      clearStatus();
      bubble("assistant", "assistant").textContent = "http " + resp.status;
      sendBtn.disabled = false;
      return;
    }

    const reader = resp.body.getReader();
    const dec = new TextDecoder();
    let buf = "";
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      let idx;
      while ((idx = buf.indexOf("\n\n")) !== -1) {
        const block = buf.slice(0, idx);
        buf = buf.slice(idx + 2);
        let event = "message", data = "";
        for (const line of block.split("\n")) {
          if (line.startsWith("event:")) event = line.slice(6).trim();
          else if (line.startsWith("data:")) data += line.slice(5).trim();
        }
        let d = {};
        try { d = data ? JSON.parse(data) : {}; } catch (_) {}

        if (event === "status") {
          setStatus(d.message || "…");
        } else if (event === "tool_call") {
          clearStatus();
          const el = bubble("tool-call", "tool call");
          el.textContent = d.tool + "(" + JSON.stringify(d.args || {}) + ")";
        } else if (event === "tool_result") {
          const el = bubble("tool-result", "tool result");
          let r = d.result;
          el.textContent = typeof r === "string" ? r : JSON.stringify(r, null, 0);
        } else if (event === "token") {
          clearStatus();
          if (!assistantEl) assistantEl = bubble("assistant", "assistant");
          assistant += d.text || "";
          assistantEl.textContent = assistant;
          scroll();
        } else if (event === "error") {
          clearStatus();
          if (!assistantEl) assistantEl = bubble("assistant", "assistant");
          assistantEl.textContent = "error: " + (d.message || "generation failed");
        } else if (event === "done") {
          clearStatus();
          if (!assistantEl) bubble("assistant", "assistant").textContent = "(no output)";
        }
      }
    }
    clearStatus();
    sendBtn.disabled = false;
    input.focus();
  });
})();
