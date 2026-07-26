// Workbench chat. EventSource can't POST, so we POST the form and read the SSE
// body with fetch()+getReader(), splitting on \n\n frames — the same reader
// pattern as Orbstack-Local's dashboard. Tokens append into a live assistant
// bubble; 'done' finalises it.
(function () {
  const form = document.getElementById("chat-form");
  if (!form) return;
  const input = document.getElementById("chat-input");
  const sendBtn = document.getElementById("chat-send");
  const log = document.getElementById("chat-log");

  document.querySelectorAll(".starter-btn").forEach((b) => {
    b.addEventListener("click", () => { input.value = b.dataset.prompt; input.focus(); });
  });

  function bubble(role, text) {
    const el = document.createElement("div");
    el.className = "bubble bubble-" + role;
    el.innerHTML = '<div class="bubble-role"></div><div class="bubble-content"></div>';
    el.querySelector(".bubble-role").textContent = role;
    el.querySelector(".bubble-content").textContent = text || "";
    log.appendChild(el);
    log.scrollTop = log.scrollHeight;
    return el.querySelector(".bubble-content");
  }

  form.addEventListener("submit", async function (e) {
    e.preventDefault();
    const message = input.value.trim();
    if (!message) return;
    sendBtn.disabled = true;

    bubble("user", message);
    const assistantEl = bubble("assistant", "");
    let assistant = "";

    const body = new FormData();
    body.append("task", form.dataset.task);
    body.append("model", form.dataset.model);
    body.append("message", message);
    input.value = "";

    let resp;
    try {
      resp = await fetch("/workbench/chat", { method: "POST", body });
    } catch (err) {
      assistantEl.textContent = "network error: " + err.message;
      sendBtn.disabled = false;
      return;
    }
    if (!resp.ok || !resp.body) {
      assistantEl.textContent = "http " + resp.status;
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
          if (!assistant) assistantEl.textContent = "… " + (d.message || "loading");
        } else if (event === "token") {
          assistant += d.text || "";
          assistantEl.textContent = assistant;
          log.scrollTop = log.scrollHeight;
        } else if (event === "error") {
          assistantEl.textContent = "error: " + (d.message || "generation failed");
        } else if (event === "done") {
          if (!assistant) assistantEl.textContent = "(no output)";
        }
      }
    }
    sendBtn.disabled = false;
    input.focus();
  });
})();
