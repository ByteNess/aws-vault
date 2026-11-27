// Appends the repository's star count to the GitHub icon link in the navbar.
// The repository comes from that link's href, so the menu entry in hugo.yaml
// stays the single place that names it.
(() => {
  // Unauthenticated GitHub API calls are limited to 60 per hour per IP.
  const CACHE_TTL_MS = 60 * 60 * 1000;
  const REPO_LINK = /^https:\/\/github\.com\/([\w.-]+)\/([\w.-]+)\/?$/;

  const format = (count) =>
    count < 1000 ? String(count) : `${(count / 1000).toFixed(1).replace(/\.0$/, "")}k`;

  const readCache = (key) => {
    try {
      const cached = JSON.parse(localStorage.getItem(key));
      return cached && typeof cached.count === "number" ? cached : null;
    } catch {
      return null;
    }
  };

  const writeCache = (key, count) => {
    try {
      localStorage.setItem(key, JSON.stringify({ count, at: Date.now() }));
    } catch {
      // Storage is unavailable in private windows; the count still renders.
    }
  };

  const fetchCount = async (repo) => {
    const response = await fetch(`https://api.github.com/repos/${repo}`, {
      headers: { Accept: "application/vnd.github+json" },
    });
    if (!response.ok) throw new Error(`GitHub API responded ${response.status}`);
    const { stargazers_count: count } = await response.json();
    if (typeof count !== "number") throw new Error("No stargazers_count in response");
    return count;
  };

  const render = (link, count) => {
    let badge = link.querySelector(".github-stars");
    if (!badge) {
      badge = document.createElement("span");
      badge.className = "github-stars";
      link.classList.add("github-stars-link");
      link.append(badge);
    }
    badge.textContent = `★ ${format(count)}`;
    badge.title = `${count.toLocaleString()} GitHub stars`;
  };

  document.addEventListener("DOMContentLoaded", async () => {
    const link = [...document.querySelectorAll(".hextra-nav-container nav a[href]")].find((a) =>
      REPO_LINK.test(a.href),
    );
    if (!link) return;

    const [, owner, name] = link.href.match(REPO_LINK);
    const repo = `${owner}/${name}`;
    const cacheKey = `github-stars:${repo.toLowerCase()}`;

    const cached = readCache(cacheKey);
    if (cached) render(link, cached.count);
    if (cached && Date.now() - cached.at < CACHE_TTL_MS) return;

    try {
      const count = await fetchCount(repo);
      writeCache(cacheKey, count);
      render(link, count);
    } catch {
      // Rate-limited or offline: keep the stale count, or the bare icon.
    }
  });
})();
