(() => {
  "use strict";
  const sidebar = document.getElementById("sidebar");
  const toggle = document.getElementById("menu-toggle");
  const scrim = document.getElementById("mobile-scrim");
  if (!sidebar || !toggle || !scrim) return;

  const setMenuOpen = (open) => {
    sidebar.classList.toggle("is-open", open);
    scrim.hidden = !open;
    toggle.setAttribute("aria-expanded", String(open));
    toggle.setAttribute("aria-label", open ? "Close navigation" : "Open navigation");
    document.body.classList.toggle("menu-open", open);
    if (open) {
      const firstLink = sidebar.querySelector("a");
      if (firstLink) firstLink.focus({ preventScroll: true });
    } else {
      toggle.focus({ preventScroll: true });
    }
  };

  toggle.addEventListener("click", () => {
    setMenuOpen(toggle.getAttribute("aria-expanded") !== "true");
  });
  scrim.addEventListener("click", () => setMenuOpen(false));
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && toggle.getAttribute("aria-expanded") === "true") {
      setMenuOpen(false);
    }
  });
  sidebar.querySelectorAll("a").forEach((link) => {
    link.addEventListener("click", () => {
      if (window.matchMedia("(max-width: 800px)").matches) setMenuOpen(false);
    });
  });
  window.addEventListener("resize", () => {
    if (!window.matchMedia("(max-width: 800px)").matches && toggle.getAttribute("aria-expanded") === "true") {
      sidebar.classList.remove("is-open");
      scrim.hidden = true;
      toggle.setAttribute("aria-expanded", "false");
      toggle.setAttribute("aria-label", "Open navigation");
      document.body.classList.remove("menu-open");
    }
  });
})();

// Password visibility and clipboard actions require explicit user interaction.
const passwordOutput = document.getElementById("generated-password");
const revealButton = document.getElementById("reveal-password");
if (passwordOutput && revealButton) {
  revealButton.addEventListener("click", () => {
    const revealed = passwordOutput.dataset.revealed !== "true";
    passwordOutput.textContent = revealed
      ? passwordOutput.dataset.password
      : "•".repeat((passwordOutput.dataset.password || "").length);
    passwordOutput.dataset.revealed = String(revealed);
    passwordOutput.setAttribute("aria-label", revealed ? "Generated password, visible" : "Generated password, hidden");
    revealButton.setAttribute("aria-pressed", String(revealed));
    revealButton.setAttribute("aria-label", revealed ? "Hide password" : "Reveal password");
    revealButton.textContent = revealed ? "Hide" : "Reveal";
  });
}

document.querySelectorAll("[data-copy-target]").forEach((button) => {
  button.addEventListener("click", async () => {
    const target = document.getElementById(button.dataset.copyTarget);
    const status = document.getElementById("copy-status");
    if (!target || !status) return;
    // Copy the actual value even when the visible output is masked.
    const value = target.dataset.password ?? target.textContent ?? "";
    try {
      if (!navigator.clipboard || !window.isSecureContext) {
        throw new Error("Clipboard access is unavailable in this context.");
      }
      await navigator.clipboard.writeText(value);
      status.textContent = "Copied to clipboard. Clear it when you no longer need it.";
    } catch (_error) {
      status.textContent = "Could not copy automatically. Check clipboard permissions or select the revealed password and copy it manually.";
    }
  });
});

const lengthControl = document.getElementById("length");
const lengthValue = document.getElementById("length-value");
if (lengthControl && lengthValue) {
  lengthControl.addEventListener("input", () => {
    lengthValue.value = lengthControl.value;
    lengthValue.textContent = lengthControl.value;
  });
}


// Password analysis stays entirely in this browser; never submit the field to Flask.
(() => {
  "use strict";
  const form = document.getElementById("analyzer-form");
  const input = document.getElementById("analysis-password");
  const visibility = document.getElementById("analysis-visibility");
  const clear = document.getElementById("analysis-clear");
  const results = document.getElementById("analysis-results");
  if (!form || !input || !visibility || !clear || !results) return;

  const common = new Set([
    "123456", "123456789", "12345678", "password", "password1",
    "qwerty", "qwerty123", "letmein", "admin", "welcome", "iloveyou",
    "abc123", "dragon", "monkey", "football", "sunshine", "princess",
    "master", "login", "passw0rd"
  ]);
  const sequences = [
    "0123456789", "9876543210", "abcdefghijklmnopqrstuvwxyz",
    "zyxwvutsrqponmlkjihgfedcba", "qwertyuiop", "poiuytrewq",
    "asdfghjkl", "lkjhgfdsa", "zxcvbnm", "mnbvcxz"
  ];
  const normalize = (value) => value.normalize("NFKC").toLocaleLowerCase();
  const hasSequence = (value) => {
    const folded = normalize(value);
    return sequences.some((sequence) => {
      for (let width = 3; width <= Math.min(6, sequence.length); width++) {
        for (let i = 0; i <= sequence.length - width; i++) {
          if (folded.includes(sequence.slice(i, i + width))) return true;
        }
      }
      return false;
    });
  };
  const setList = (id, items, fallback) => {
    const list = document.getElementById(id);
    list.replaceChildren();
    (items.length ? items : [fallback]).forEach((text) => {
      const li = document.createElement("li");
      li.textContent = text;
      list.appendChild(li);
    });
  };
  const analyze = (password) => {
    const length = password.length;
    if (!length) return {
      score: 0, rating: "Very Weak", length: 0, unique: 0, groups: 0,
      weaknesses: ["Enter a password to begin analysis."], positives: [],
      recommendations: ["Use a unique password or passphrase of at least 16 characters."]
    };
    const folded = normalize(password);
    const groups = [
      /[a-z]/i.test(password) && /[a-z]/.test(password),
      /[A-Z]/.test(password),
      /\d/.test(password),
      /[^A-Za-z0-9\s]/u.test(password)
    ].filter(Boolean).length;
    const unique = new Set(password).size;
    let score = 0;
    const weaknesses = [], positives = [], recommendations = [];
    if (length < 8) {
      score += 4; weaknesses.push("Very short length makes guessing easier.");
      recommendations.push("Use at least 16 characters for an important account.");
    } else if (length < 12) {
      score += 15; weaknesses.push("Shorter than the recommended length for a strong password.");
      recommendations.push("Increase the length to 16 characters or more.");
    } else if (length < 16) {
      score += 28; weaknesses.push("Moderate length; a longer password would improve resilience.");
      recommendations.push("Prefer 16–20 or more characters.");
    } else if (length < 20) {
      score += 42; positives.push("Good length provides a useful foundation.");
    } else if (length < 24) {
      score += 60; positives.push("Long password length is a positive security signal.");
    } else {
      score += 72; positives.push("Very long password length is a positive security signal.");
    }
    if (groups >= 3) { score += 8; positives.push("Uses several character categories."); }
    else if (groups === 2) { score += 4; positives.push("Uses more than one character category."); }
    else {
      weaknesses.push("Uses only one character category.");
      recommendations.push("Consider a longer passphrase with less predictable wording.");
    }
    if (unique <= Math.max(1, Math.floor(length / 3))) {
      score -= 22; weaknesses.push("Contains substantial character repetition.");
      recommendations.push("Avoid repeated characters and repeated chunks.");
    } else if (/(.)\1{2,}/u.test(password)) {
      score -= 12; weaknesses.push("Contains a run of repeated characters.");
      recommendations.push("Replace repeated runs with unrelated characters.");
    }
    if (common.has(folded)) {
      score = Math.min(score, 5);
      weaknesses.push("Matches a common password in the bundled reference list.");
      recommendations.push("Replace it with a unique password not based on a common phrase.");
    } else if (["password", "qwerty", "letmein", "admin"].some((word) => folded.includes(word))) {
      score -= 15; weaknesses.push("Contains a recognizable common-password word.");
      recommendations.push("Avoid common words and familiar password templates.");
    }
    if (hasSequence(password)) {
      score -= 18; weaknesses.push("Contains a recognizable alphabetic, numeric, or keyboard sequence.");
      recommendations.push("Avoid sequences such as 123456, abcdef, or keyboard walks.");
    }
    if (/(19|20)\d{2}/u.test(password)) {
      score -= 8; weaknesses.push("Contains a year-like number that may be predictable.");
      recommendations.push("Avoid years and date-like patterns others could guess.");
    }
    if (/(.{2,})\1/iu.test(password)) {
      score -= 12; weaknesses.push("Contains a repeated multi-character substring.");
      recommendations.push("Avoid repeating a word, chunk, or template.");
    }
    if (/(?:p[a@]ssw[o0]rd|[a@]dm[i1]n)/iu.test(password)) {
      score -= 10; weaknesses.push("Contains a predictable word with a common character substitution.");
      recommendations.push("Do not rely on substitutions such as @ for a or 0 for o.");
    }
    score = Math.max(0, Math.min(100, score));
    if (weaknesses.some((item) => /common password|sequence/i.test(item))) score = Math.min(score, 59);
    const rating = score < 20 ? "Very Weak" : score < 40 ? "Weak" :
      score < 60 ? "Fair" : score < 80 ? "Strong" : "Very Strong";
    if (!recommendations.length) recommendations.push("Use it for one account only and store it in a reputable password manager.");
    return { score, rating, length, unique, groups, weaknesses: [...new Set(weaknesses)],
      positives: [...new Set(positives)], recommendations: [...new Set(recommendations)] };
  };
  const render = (data) => {
    document.getElementById("analysis-rating").textContent = data.rating;
    document.getElementById("analysis-score").textContent = String(data.score);
    document.getElementById("analysis-length").textContent = String(data.length);
    document.getElementById("analysis-unique").textContent = String(data.unique);
    document.getElementById("analysis-groups").textContent = `${data.groups}/4`;
    const meter = document.getElementById("analysis-meter");
    meter.setAttribute("aria-valuenow", String(data.score));
    document.getElementById("analysis-meter-fill").style.width = `${data.score}%`;
    setList("analysis-weaknesses", data.weaknesses, "No obvious weakness detected by these basic checks.");
    setList("analysis-positives", data.positives, "No strong positive indicator identified yet.");
    setList("analysis-recommendations", data.recommendations, "Use a unique password.");
    results.hidden = false;
  };
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    render(analyze(input.value));
  });
  visibility.addEventListener("click", () => {
    const show = input.type === "password";
    input.type = show ? "text" : "password";
    visibility.textContent = show ? "Hide" : "Show";
    visibility.setAttribute("aria-pressed", String(show));
    visibility.setAttribute("aria-label", show ? "Hide password" : "Show password");
    input.focus({ preventScroll: true });
  });
  clear.addEventListener("click", () => {
    input.value = "";
    input.type = "password";
    visibility.textContent = "Show";
    visibility.setAttribute("aria-pressed", "false");
    visibility.setAttribute("aria-label", "Show password");
    results.hidden = true;
    input.focus({ preventScroll: true });
  });
})();

// Crack-time estimates run only in this browser; no password is sent or persisted.
(() => {
  "use strict";
  const form = document.getElementById("crack-time-form");
  const input = document.getElementById("crack-time-password");
  const visibility = document.getElementById("crack-time-visibility");
  const clear = document.getElementById("crack-time-clear");
  const results = document.getElementById("crack-time-results");
  const scenarioContainer = document.getElementById("crack-time-scenarios");
  if (!form || !input || !visibility || !clear || !results || !scenarioContainer) return;

  const common = new Set([
    "123456", "123456789", "12345678", "password", "password1", "qwerty",
    "qwerty123", "letmein", "admin", "welcome", "iloveyou", "abc123", "dragon",
    "monkey", "football", "sunshine", "princess", "master", "login", "passw0rd"
  ]);
  const sequences = ["0123456789", "9876543210", "abcdefghijklmnopqrstuvwxyz",
    "zyxwvutsrqponmlkjihgfedcba", "qwertyuiop", "poiuytrewq", "asdfghjkl", "lkjhgfdsa", "zxcvbnm", "mnbvcxz"];
  const scenarios = [
    { key: "rate-limited", name: "Rate-limited online", rate: 1 / 600, rateLabel: "1 guess every 10 minutes", note: "Lockouts or MFA may make guessing less useful." },
    { key: "permissive-online", name: "Permissive online", rate: 1, rateLabel: "1 guess/second", note: "Hypothetical weak throttling and no effective lockout." },
    { key: "slow-hash", name: "Offline, slow password hash", rate: 1000, rateLabel: "1,000 guesses/second", note: "Illustrative expensive-hash throughput; hardware and work factor matter." },
    { key: "fast-hash", name: "Offline, fast hash", rate: 1e10, rateLabel: "10 billion guesses/second", note: "Hypothetical high-throughput hardware against a fast hash." }
  ];
  // Sort a copy by numeric throughput; faster scenarios have shorter estimates.
  const orderedScenarios = [...scenarios].sort((a, b) => b.rate - a.rate);
  const fold = (value) => value.normalize("NFKC").toLocaleLowerCase();
  const hasSequence = (value) => {
    const normalized = fold(value);
    return sequences.some((sequence) => {
      for (let width = 3; width <= Math.min(6, sequence.length); width++) {
        for (let i = 0; i <= sequence.length - width; i++) {
          if (normalized.includes(sequence.slice(i, i + width))) return true;
        }
      }
      return false;
    });
  };
  const effectiveBits = (password) => {
    if (!password) return { bits: 0, observations: ["No password entered."] };
    const length = password.length, folded = fold(password);
    const lower = /[a-z]/i.test(password) && /[a-z]/.test(password);
    const upper = /[A-Z]/.test(password), digit = /\d/u.test(password);
    const symbol = /[^\p{L}\p{N}\s]/u.test(password);
    const groups = [lower, upper, digit, symbol].filter(Boolean).length;
    let perChar = symbol ? (groups >= 3 ? 6.55 : 6.0) : digit && (lower || upper) ? (groups >= 3 ? 6.15 : 5.7) : lower && upper ? 5.7 : lower || upper ? 4.7 : digit ? 3.3 : 4.0;
    let bits = 0;
    for (let i = 0; i < length; i++) bits += Math.min(perChar, Math.max(2, perChar * (1 - Math.max(0, i - 24) / 120)));
    const observations = [];
    if (common.has(folded)) { bits = Math.min(bits, 5); observations.push("Matches a common password or familiar pattern."); }
    else {
      const token = ["password", "qwerty", "letmein", "admin", "welcome", "iloveyou"].find((word) => folded.includes(word));
      if (token) { bits -= Math.min(24, 8 + token.length * 1.5); bits = Math.min(bits, Math.max(12, length * 1.5)); observations.push("Contains a recognizable common-password word."); }
    }
    if (hasSequence(password)) { bits -= Math.min(18, Math.max(8, length * 0.7)); bits = Math.min(bits, Math.max(12, length * 1.5)); observations.push("Contains a familiar numeric, alphabetic, or keyboard sequence."); }
    const unique = new Set(password).size;
    if (unique <= Math.max(1, Math.floor(length / 3))) { bits -= Math.min(45, length * 1.4); bits = Math.min(bits, Math.max(8, unique * 3 + length * 0.3)); observations.push("Contains substantial character repetition."); }
    else if (/(.)\1{2,}/u.test(password)) { bits -= 8; observations.push("Contains a run of repeated characters."); }
    if (/(19|20)\d{2}/u.test(password)) { bits -= 5; observations.push("Contains a year-like number."); }
    if (/(.{2,})\1/iu.test(password)) { bits -= Math.min(20, length * 0.6); observations.push("Contains a repeated multi-character chunk."); }
    if (groups === 1 && length < 12) { bits -= 3; observations.push("Uses one character category and is short."); }
    if (!observations.length) observations.push("No obvious common pattern detected by these basic checks.");
    return { bits: Math.max(0, Math.min(1024, bits)), observations: [...new Set(observations)] };
  };
  const duration = (log2Seconds) => {
    const log10 = log2Seconds * Math.LOG10E * Math.LN2;
    if (log10 < 0) return "under 1 second";
    if (log10 < Math.log10(60)) return "under 1 minute";
    const year = 365.25 * 24 * 60 * 60;
    if (log10 >= 18) {
      const exponent = Math.floor(log10 - Math.log10(year));
      return exponent < 1000 ? `about 10^${exponent} years` : "an astronomically large duration";
    }
    const units = [[60, "minute"], [3600, "hour"], [86400, "day"], [year, "year"], [1000 * year, "millennium"]];
    let unit = [1, "second"];
    for (const candidate of units) if (log10 >= Math.log10(candidate[0])) unit = candidate;
    const amount = Math.max(1, Math.round(10 ** (log10 - Math.log10(unit[0]))));
    return `about ${amount.toLocaleString()} ${unit[1]}${amount === 1 ? "" : "s"}`;
  };
  const render = (password) => {
    const estimate = effectiveBits(password);
    document.getElementById("crack-time-summary").textContent = password ? "Estimated time range by scenario" : "Enter a password to begin";
    document.getElementById("crack-time-observations").textContent = estimate.observations.join(" ");
    scenarioContainer.replaceChildren();
    orderedScenarios.forEach((scenario) => {
      const card = document.createElement("article");
      card.className = "crack-scenario-result";
      const heading = document.createElement("h3"); heading.textContent = scenario.name;
      const rate = document.createElement("p"); rate.className = "crack-rate"; rate.textContent = scenario.rateLabel;
      const time = document.createElement("p"); time.className = "crack-time-range";
      const low = Math.max(-20, estimate.bits - 2 - Math.log2(scenario.rate));
      const high = Math.max(-20, estimate.bits - Math.log2(scenario.rate));
      const lowText = duration(low), highText = duration(high);
      time.textContent = lowText === highText ? highText : `${lowText} – ${highText}`;
      const note = document.createElement("p"); note.className = "crack-scenario-note"; note.textContent = scenario.note;
      card.append(heading, rate, time, note); scenarioContainer.appendChild(card);
    });
    results.hidden = false;
  };
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    if (!input.value) {
      scenarioContainer.replaceChildren();
      document.getElementById("crack-time-summary").textContent = "Enter a password to begin";
      document.getElementById("crack-time-observations").textContent = "No password entered; no estimate was calculated.";
      results.hidden = false;
      return;
    }
    render(input.value);
  });
  visibility.addEventListener("click", () => {
    const show = input.type === "password";
    input.type = show ? "text" : "password";
    visibility.textContent = show ? "Hide" : "Show";
    visibility.setAttribute("aria-pressed", String(show));
    visibility.setAttribute("aria-label", show ? "Hide password" : "Show password");
    input.focus({ preventScroll: true });
  });
  clear.addEventListener("click", () => {
    input.value = ""; input.type = "password";
    visibility.textContent = "Show"; visibility.setAttribute("aria-pressed", "false");
    visibility.setAttribute("aria-label", "Show password");
    scenarioContainer.replaceChildren();
    document.getElementById("crack-time-summary").textContent = "Enter a password to begin";
    document.getElementById("crack-time-observations").textContent = "";
    results.hidden = true; input.focus({ preventScroll: true });
  });
})();
