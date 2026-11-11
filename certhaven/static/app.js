// Reload the form with new query parameters when an issuer/template select changes.
document.addEventListener("change", (event) => {
  const el = event.target.closest("[data-reload]");
  if (!el) return;
  const url = new URL(window.location.href);
  el.form.querySelectorAll("[data-reload]").forEach((field) => url.searchParams.set(field.name, field.value));
  window.location.href = url.toString();
});

// Times arrive in UTC as <time datetime="...Z">. When Settings → Show times in is set to local
// time, rewrite them in this browser's time zone and keep the UTC text as a tooltip.
(() => {
  document.querySelectorAll("[data-local-zone]").forEach((el) => {
    el.textContent = `(each person's browser; yours is ${Intl.DateTimeFormat().resolvedOptions().timeZone})`;
  });
  if (document.body.dataset.timeDisplay !== "local") return;
  const pad = (n) => String(n).padStart(2, "0");
  const zoneName = new Intl.DateTimeFormat(undefined, { timeZoneName: "short" });
  document.querySelectorAll("time[datetime]").forEach((el) => {
    const when = new Date(el.getAttribute("datetime"));
    if (Number.isNaN(when.getTime())) return;
    let text = `${when.getFullYear()}-${pad(when.getMonth() + 1)}-${pad(when.getDate())}`;
    if (el.dataset.kind === "datetime") {
      const zone = zoneName.formatToParts(when).find((part) => part.type === "timeZoneName");
      text += ` ${pad(when.getHours())}:${pad(when.getMinutes())}${zone ? ` ${zone.value}` : ""}`;
    }
    el.title = `${el.textContent.trim()}${el.dataset.kind === "date" ? " (UTC)" : ""}`;
    el.textContent = text;
  });
})();

// Ask before submitting destructive forms.
document.addEventListener("submit", (event) => {
  const message = event.target.dataset.confirm;
  if (message && !window.confirm(message)) event.preventDefault();
});

// A form that downloads a file leaves the page as it was. Forms marked data-reload-after reload it once the
// download has started, so the page shows what the server recorded (such as the next step).
document.addEventListener("submit", (event) => {
  const delay = Number(event.target.dataset.reloadAfter);
  if (!event.defaultPrevented && delay) setTimeout(() => window.location.reload(), delay);
});
