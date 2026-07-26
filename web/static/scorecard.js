// Scorecard runner. POSTs the selected models and reads the SSE benchmark
// stream, upserting a results row per model as it completes and showing live
// per-case progress.
(function () {
  const form = document.getElementById("scorecard-form");
  if (!form) return;
  const runBtn = document.getElementById("run-btn");
  const status = document.getElementById("run-status");
  const body = document.getElementById("scorecard-body");
  const meta = document.getElementById("results-meta");

  function pct(x) { return Math.round((x || 0) * 100) + "%"; }

  function upsertRow(model, summary) {
    let row = body.querySelector('tr[data-model="' + CSS.escape(model) + '"]');
    if (!row) {
      row = document.createElement("tr");
      row.setAttribute("data-model", model);
      body.appendChild(row);
    }
    row.innerHTML =
      '<td class="mono"></td><td></td><td></td><td></td><td class="overall"></td>';
    const tds = row.querySelectorAll("td");
    tds[0].textContent = model;
    tds[1].textContent = pct(summary.tool);
    tds[2].textContent = pct(summary.params);
    tds[3].textContent = pct(summary.completed);
    tds[4].textContent = pct(summary.overall);
  }

  form.addEventListener("submit", async function (e) {
    e.preventDefault();
    const chosen = [...form.querySelectorAll('input[name="models"]:checked')].map((c) => c.value);
    if (!chosen.length) { status.textContent = "Select at least one model."; return; }

    runBtn.disabled = true;
    status.textContent = "Starting…";

    const body_data = new FormData();
    chosen.forEach((m) => body_data.append("models", m));

    let resp;
    try {
      resp = await fetch("/scorecard/run", { method: "POST", body: body_data });
    } catch (err) {
      status.textContent = "network error: " + err.message;
      runBtn.disabled = false;
      return;
    }
    if (!resp.ok || !resp.body) {
      status.textContent = "http " + resp.status;
      runBtn.disabled = false;
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

        if (event === "model_start") {
          status.textContent = "Benchmarking " + d.model + " (0/" + d.total + ")…";
        } else if (event === "case_done") {
          status.textContent = "Benchmarking " + d.model + " (" + d.index + "/" + d.total + "): "
            + d.result.case + " → " + (d.result.called_tool || "no tool");
        } else if (event === "model_done") {
          upsertRow(d.model, d.summary);
        } else if (event === "result") {
          meta.textContent = "Last run: " + (d.generated_at || "just now");
        } else if (event === "error") {
          status.textContent = "error: " + (d.message || "run failed");
        } else if (event === "done") {
          status.textContent = "Done.";
        }
      }
    }
    runBtn.disabled = false;
  });
})();
