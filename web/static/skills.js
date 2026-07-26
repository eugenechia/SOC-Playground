// Client-side filter for the skill library list. The full index (~800 cards) is
// rendered server-side; this just shows/hides cards by search text so there's no
// round-trip per keystroke.
(function () {
  const search = document.getElementById("skill-search");
  const list = document.getElementById("skill-list");
  const count = document.getElementById("skill-count");
  const empty = document.getElementById("skill-empty");
  if (!list) return;

  const cards = Array.from(list.querySelectorAll(".skill-card"));

  function apply() {
    const q = (search.value || "").trim().toLowerCase();
    let shown = 0;
    for (const card of cards) {
      const visible =
        !q ||
        card.dataset.name.includes(q) ||
        card.dataset.desc.includes(q);
      card.hidden = !visible;
      if (visible) shown++;
    }
    count.textContent = shown + " of " + cards.length;
    empty.hidden = shown !== 0;
  }

  search.addEventListener("input", apply);
  apply();
})();
