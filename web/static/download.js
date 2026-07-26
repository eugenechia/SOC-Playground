// Model-download progress follower. The download runs on a server thread; we
// open an EventSource to /events/download/{job_id} and drive the progress bar
// from the JSON 'progress' frames. On 'done'/'error' we reload the page so the
// model list reflects the new state.
(function () {
  window.attachDownload = function (jobId) {
    const root = document.getElementById("dl-" + jobId);
    if (!root) return;
    const bar = root.querySelector(".progress-bar");
    const status = root.querySelector(".dl-status");
    const es = new EventSource("/events/download/" + encodeURIComponent(jobId));

    es.addEventListener("progress", function (e) {
      let d;
      try { d = JSON.parse(e.data); } catch (_) { return; }
      if (bar) bar.style.width = (d.pct || 0) + "%";
      if (status) {
        const gb = (n) => (n / 1024 / 1024 / 1024).toFixed(2);
        status.textContent = d.total
          ? `${d.pct}% — ${gb(d.done)} / ${gb(d.total)} GiB`
          : "downloading…";
      }
    });

    es.addEventListener("done", function () {
      if (status) status.textContent = "done — refreshing…";
      es.close();
      setTimeout(() => window.location.reload(), 600);
    });

    es.addEventListener("error", function (e) {
      let msg = "download failed";
      try { msg = JSON.parse(e.data).message || msg; } catch (_) {}
      if (status) { status.textContent = msg; status.classList.add("dl-failed"); }
      es.close();
    });
  };
})();
