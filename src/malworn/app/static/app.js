// Malworn page behaviour. Loaded from the app itself (no internet in the VM).
(function () {
  "use strict";

  // ---- upload page: show the chosen file name, allow drag and drop ----
  var drop = document.querySelector(".drop");
  var fileInput = document.getElementById("sample");
  var dropText = document.getElementById("drop-text");
  if (drop && fileInput) {
    fileInput.addEventListener("change", function () {
      if (fileInput.files.length) dropText.textContent = fileInput.files[0].name;
    });
    ["dragenter", "dragover"].forEach(function (e) {
      drop.addEventListener(e, function (ev) { ev.preventDefault(); drop.classList.add("over"); });
    });
    ["dragleave", "drop"].forEach(function (e) {
      drop.addEventListener(e, function (ev) { ev.preventDefault(); drop.classList.remove("over"); });
    });
    drop.addEventListener("drop", function (ev) {
      if (ev.dataTransfer.files.length) {
        fileInput.files = ev.dataTransfer.files;
        dropText.textContent = ev.dataTransfer.files[0].name;
      }
    });
    document.getElementById("upload-form").addEventListener("submit", function () {
      var b = document.getElementById("analyse-btn");
      b.disabled = true; b.textContent = "Uploading…";
    });
  }

  var page = document.getElementById("analysis");
  if (!page) return;
  var runId = page.dataset.run;
  var base = "/analysis/" + encodeURIComponent(runId);

  // ---- live progress while the agent works ----
  if (page.dataset.status === "queued" || page.dataset.status === "running") {
    var steps = document.getElementById("steps");
    var thinking = document.getElementById("thinking");
    var forming = document.getElementById("answer-forming");
    var note = document.getElementById("live-note");
    var pill = document.getElementById("status-pill");
    var seen = 0;

    function line(text, cls) {
      var li = document.createElement("li");
      li.textContent = text;
      if (cls) li.className = cls;
      steps.appendChild(li);
    }

    function poll() {
      fetch(base + "/status?since=" + seen, { cache: "no-store" })
        .then(function (r) { return r.json(); })
        .then(function (s) {
          s.events.forEach(function (e) {
            if (e.kind === "tool_call") line("→ " + e.tool);
            else if (e.kind === "tool_result")
              line("← " + e.tool + ": " + e.status + (e.ms != null ? " (" + e.ms + " ms)" : "") +
                   (e.error ? " · " + e.error : ""), e.status === "success" ? "ok" : "bad");
            else if (e.kind === "invalid_call") line("model asked for an unknown tool: " + e.tool, "note");
            else if (e.kind === "repeat_call") line("model asked for " + e.tool + " again (earlier result reused)", "note");
            else if (e.kind === "limit") line("tool-call limit reached; asking for the answer", "note");
            else if (e.kind === "cutoff") line("model's reasoning ran too long; asking it to answer directly", "note");
            else if (e.kind === "check")
              line(e.tool ? "answer check failed (" + e.tool.replace(/_/g, " ") + "); asking the model to fix it"
                          : "answer check passed", e.tool ? "note" : "ok");
          });
          seen = s.event_count;
          thinking.textContent = s.thinking;
          thinking.scrollTop = thinking.scrollHeight;
          forming.textContent = s.answer;
          pill.textContent = s.status;
          pill.className = "pill " + s.status;
          if (s.status === "running") note.textContent = s.answer ? "The model is writing its explanation." : "The model is choosing tools.";
          if (s.status === "done" || s.status === "error") { window.location.reload(); return; }
          setTimeout(poll, 1000);
        })
        .catch(function () { setTimeout(poll, 3000); });
    }
    poll();
    return;
  }

  // ---- follow-up questions ----
  var form = document.getElementById("chat-form");
  if (!form) return;
  var log = document.getElementById("chat-log");
  var input = document.getElementById("question");
  var button = document.getElementById("ask-btn");

  form.addEventListener("submit", function (ev) {
    ev.preventDefault();
    var question = input.value.trim();
    if (!question) return;
    var q = document.createElement("div");
    q.className = "q"; q.textContent = question;
    var a = document.createElement("div");
    a.className = "a md muted"; a.textContent = "Thinking…";
    log.appendChild(q); log.appendChild(a);
    input.value = ""; button.disabled = true;

    fetch(base + "/ask", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ question: question })
    })
      .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, body: j }; }); })
      .then(function (res) {
        a.classList.remove("muted");
        if (!res.ok) { a.textContent = res.body.error || "Something went wrong."; return; }
        a.innerHTML = res.body.answer_html;  // rendered and escaped on the server
        if (res.body.new_tools && res.body.new_tools.length) {
          var p = document.createElement("p");
          p.className = "muted small";
          p.textContent = "Ran: " + res.body.new_tools.join(", ");
          a.appendChild(p);
          var frame = document.getElementById("report-frame");
          if (frame) frame.src = frame.src;
        }
      })
      .catch(function () { a.textContent = "Couldn't reach the app."; })
      .then(function () { button.disabled = false; input.focus(); });
  });
})();
