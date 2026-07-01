const authSection = document.getElementById("authSection");
const pricingSection = document.getElementById("pricingSection");
const howItWorksSection = document.getElementById("howItWorksSection");
const navLoginLink = document.getElementById("navLoginLink");
const navDashboardLink = document.getElementById("navDashboardLink");
const publicNavLinks = document.querySelectorAll(".public-nav-link");
const appSection = document.getElementById("appSection");
const authMessage = document.getElementById("authMessage");
const userInfo = document.getElementById("userInfo");
const usageInfo = document.getElementById("usageInfo");

const registerBtn = document.getElementById("registerBtn");
const loginBtn = document.getElementById("loginBtn");
const logoutBtn = document.getElementById("logoutBtn");
const upgradeBtn = document.getElementById("upgradeBtn");

const registerName = document.getElementById("registerName");
const registerEmail = document.getElementById("registerEmail");
const registerPassword = document.getElementById("registerPassword");

const loginEmail = document.getElementById("loginEmail");
const loginPassword = document.getElementById("loginPassword");

const analyzeBtn = document.getElementById("analyzeBtn");
const messageInput = document.getElementById("messageInput");
const categorySelect = document.getElementById("categorySelect");
const resultBox = document.getElementById("resultBox");
const historyList = document.getElementById("historyList");
const clearHistoryBtn = document.getElementById("clearHistoryBtn");
const deleteDataBtn = document.getElementById("deleteDataBtn");
const deleteAccountBtn = document.getElementById("deleteAccountBtn");
const totalScansStat = document.getElementById("totalScansStat");
const highRiskStat = document.getElementById("highRiskStat");
const mediumRiskStat = document.getElementById("mediumRiskStat");
const remainingStat = document.getElementById("remainingStat");

let token = localStorage.getItem("choicewise_token");
let currentUser = JSON.parse(localStorage.getItem("choicewise_user") || "null");

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function saveAuth(data) {
  token = data.token;
  currentUser = data.user;

  localStorage.setItem("choicewise_token", token);
  localStorage.setItem("choicewise_user", JSON.stringify(currentUser));

  updateUI();
}

function clearAuth() {
  token = null;
  currentUser = null;

  localStorage.removeItem("choicewise_token");
  localStorage.removeItem("choicewise_user");

  resultBox.classList.add("hidden");
  resultBox.innerHTML = "";
  historyList.innerHTML = "";
  usageInfo.textContent = "";
  upgradeBtn.classList.add("hidden");

  updateUI();
}

function updateUI() {
  if (token && currentUser) {
  authSection.classList.add("hidden");
  pricingSection.classList.add("hidden");
  howItWorksSection.classList.add("hidden");
  appSection.classList.remove("hidden");
  navLoginLink.classList.add("hidden");
navDashboardLink.classList.remove("hidden");

publicNavLinks.forEach((link) => {
  link.classList.add("hidden");
});
    const trialDate = new Date(currentUser.trialEndsAt).toLocaleDateString();

    userInfo.textContent = `Logged in as ${currentUser.email} | Plan: ${currentUser.plan} | Trial ends: ${trialDate}`;

    
    loadHistory();
loadUsage();
loadDashboardStats();
    
  } else {
  authSection.classList.remove("hidden");
  pricingSection.classList.remove("hidden");
  howItWorksSection.classList.remove("hidden");
  appSection.classList.add("hidden");
  navLoginLink.classList.remove("hidden");
navDashboardLink.classList.add("hidden");

publicNavLinks.forEach((link) => {
  link.classList.remove("hidden");
});
  }
}

async function apiRequest(url, options = {}) {
  const headers = {
    "Content-Type": "application/json",
    ...(options.headers || {}),
  };

  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const response = await fetch(url, {
    ...options,
    headers,
    cache: options.cache || "no-store",
  });

  const data = await response.json();

  if (!response.ok) {
    throw new Error(data.error || "Something went wrong.");
  }

  return data;
}

// Register
registerBtn.addEventListener("click", async () => {
  const name = registerName.value.trim();
  const email = registerEmail.value.trim();
  const password = registerPassword.value.trim();

  if (!name || !email || !password) {
    authMessage.textContent = "Please fill in all register fields.";
    return;
  }

  registerBtn.textContent = "Creating account...";
  registerBtn.disabled = true;

  try {
    const data = await apiRequest("/api/auth/register", {
      method: "POST",
      body: JSON.stringify({ name, email, password }),
    });

    authMessage.textContent = data.message;
    saveAuth(data);
  } catch (error) {
    authMessage.textContent = error.message;
  } finally {
    registerBtn.textContent = "Create Account";
    registerBtn.disabled = false;
  }
});

// Login
loginBtn.addEventListener("click", async () => {
  const email = loginEmail.value.trim();
  const password = loginPassword.value.trim();

  if (!email || !password) {
    authMessage.textContent = "Please fill in your email and password.";
    return;
  }

  loginBtn.textContent = "Logging in...";
  loginBtn.disabled = true;

  try {
    const data = await apiRequest("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });

    authMessage.textContent = data.message;
    saveAuth(data);
  } catch (error) {
    authMessage.textContent = error.message;
  } finally {
    loginBtn.textContent = "Login";
    loginBtn.disabled = false;
  }
});

// Logout
logoutBtn.addEventListener("click", () => {
  clearAuth();
});
clearHistoryBtn.addEventListener("click", async () => {
  const confirmed = confirm("Are you sure you want to clear all your scan history?");

  if (!confirmed) {
    return;
  }

  clearHistoryBtn.textContent = "Clearing...";
  clearHistoryBtn.disabled = true;

  try {
    await apiRequest("/api/history", {
      method: "DELETE",
    });

    historyList.innerHTML = `<p class="privacy-note">No scans yet.</p>`;
    resultBox.innerHTML = "";
    resultBox.classList.add("hidden");
  } catch (error) {
    alert(error.message);
  } finally {
    clearHistoryBtn.textContent = "Clear All";
    clearHistoryBtn.disabled = false;
  }
});

deleteDataBtn.addEventListener("click", async () => {
  const confirmed = confirm(
    "This will delete all your saved scan data. Your account will remain active. Continue?"
  );

  if (!confirmed) {
    return;
  }

  deleteDataBtn.textContent = "Deleting...";
  deleteDataBtn.disabled = true;

  try {
    const data = await apiRequest("/api/account/data", {
      method: "DELETE",
    });

    alert(data.message);

    historyList.innerHTML = `<p class="privacy-note">No scans yet.</p>`;
    resultBox.innerHTML = "";
    resultBox.classList.add("hidden");

    loadHistory();
    loadUsage();
    loadDashboardStats();
  } catch (error) {
    alert(error.message);
  } finally {
    deleteDataBtn.textContent = "Delete My Scan Data";
    deleteDataBtn.disabled = false;
  }
});
deleteAccountBtn.addEventListener("click", async () => {
  const firstConfirm = confirm(
    "This will permanently delete your account and all your scan data. This cannot be undone. Continue?"
  );

  if (!firstConfirm) {
    return;
  }

  const password = prompt("Enter your password to confirm account deletion:");

  if (!password) {
    alert("Account deletion cancelled.");
    return;
  }

  deleteAccountBtn.textContent = "Deleting account...";
  deleteAccountBtn.disabled = true;

  try {
    const data = await apiRequest("/api/account/delete", {
      method: "DELETE",
      body: JSON.stringify({ password }),
    });

    alert(data.message);

    clearAuth();
  } catch (error) {
    alert(error.message);
  } finally {
    deleteAccountBtn.textContent = "Delete My Account";
    deleteAccountBtn.disabled = false;
  }
});
upgradeBtn.addEventListener("click", async () => {
  const confirmed = confirm(
    "You will be redirected to Lemon Squeezy checkout to buy 100 scan credits. Continue?"
  );

  if (!confirmed) {
    return;
  }

  upgradeBtn.textContent = "Opening checkout...";
  upgradeBtn.disabled = true;

  try {
    const data = await apiRequest("/api/payments/lemonsqueezy/checkout", {
      method: "POST",
      body: JSON.stringify({}),
    });

    window.location.href = data.checkoutUrl;
  } catch (error) {
    alert(error.message);
    upgradeBtn.textContent = "Buy 100 Scan Credits";
    upgradeBtn.disabled = false;
  }
});
// Analyze message
analyzeBtn.addEventListener("click", async () => {
  const message = messageInput.value.trim();
  const category = categorySelect.value;

  if (!message) {
    alert("Please paste a message first.");
    return;
  }

  analyzeBtn.textContent = "Analyzing...";
  analyzeBtn.disabled = true;

  try {
    const data = await apiRequest("/api/analyze", {
      method: "POST",
      body: JSON.stringify({ message, category }),
    });

    showResult(data.result);
messageInput.value = "";
showResult(data.result);
messageInput.value = "";
loadHistory();
loadUsage();
loadDashboardStats();
  } catch (error) {
    resultBox.classList.remove("hidden");
    resultBox.innerHTML = `
      <h3>Error</h3>
      <p>${escapeHtml(error.message)}</p>
    `;

    if (error.message.toLowerCase().includes("login")) {
      clearAuth();
    }
  } finally {
  analyzeBtn.textContent = "Analyze Message";
  analyzeBtn.disabled = false;
  loadUsage();
}
});

function showResult(result) {
  resultBox.classList.remove("hidden");

  let levelClass = "low";

  if (result.riskLevel === "Medium Risk") {
    levelClass = "medium";
  }

  if (result.riskLevel === "High Risk") {
    levelClass = "high";
  }

  const flagsHtml =
    result.redFlags.length > 0
      ? result.redFlags.map((flag) => `<li>${escapeHtml(flag)}</li>`).join("")
      : "<li>No major red flags detected.</li>";
      const safeActionsHtml =
  result.safeActions && result.safeActions.length > 0
    ? result.safeActions.map((action) => `<li>${escapeHtml(action)}</li>`).join("")
    : "<li>Verify the sender before taking action.</li>";

resultBox.innerHTML = `
  <h3>Analysis Result</h3>

  <p class="${levelClass}">
    <strong>${escapeHtml(result.riskLevel)}</strong>
  </p>

  <div class="risk-score ${levelClass}">
  ${result.riskScore}/100
</div>

<div class="risk-bar">
  <div class="risk-bar-fill ${levelClass}" style="width: ${result.riskScore}%"></div>
</div>

  <p class="privacy-note">
  Category: ${escapeHtml(result.category || "General Message")}
  | Analysis mode: ${escapeHtml(result.analysisType || "Rule-based")}
  | Confidence: ${escapeHtml(result.confidence || "Medium")}
</p>
  <h4>Red Flags Found:</h4>
  <ul>
    ${flagsHtml}
  </ul>

  <h4>Safe Actions:</h4>
  <ul>
    ${safeActionsHtml}
  </ul>

  <h4>Recommendation:</h4>
  <p class="recommendation">
    ${escapeHtml(result.recommendation)}
  </p>
`;
}

async function loadDashboardStats() {
  try {
    const data = await apiRequest("/api/dashboard/stats");
    const stats = data.stats;
    const usage = stats.usage;

    totalScansStat.textContent = stats.totalScans;
    highRiskStat.textContent = stats.highRiskScans;
    mediumRiskStat.textContent = stats.mediumRiskScans;

    remainingStat.textContent = usage.totalScansRemaining;
  } catch (error) {
    totalScansStat.textContent = "-";
    highRiskStat.textContent = "-";
    mediumRiskStat.textContent = "-";
    remainingStat.textContent = "-";
  }
}
//usage
async function loadUsage() {
  try {
    const data = await apiRequest("/api/account/usage");
    const usage = data.usage;

    usageInfo.textContent = `Free scans left: ${usage.freeScansRemaining} | Paid credits: ${usage.paidScanCredits} | Total remaining: ${usage.totalScansRemaining}`;

    if (!usage.canScan) {
      analyzeBtn.disabled = true;
      analyzeBtn.textContent = "Buy Credits Required";
      messageInput.disabled = true;
      upgradeBtn.classList.remove("hidden");
    } else {
      analyzeBtn.disabled = false;
      analyzeBtn.textContent = "Analyze Message";
      messageInput.disabled = false;
      upgradeBtn.classList.remove("hidden");
    }
  } catch (error) {
    usageInfo.textContent = "Could not load usage.";
  }
}

async function loadHistory() {
  try {
    const data = await apiRequest("/api/history");

    if (!data.scans || data.scans.length === 0) {
      historyList.innerHTML = `<p class="privacy-note">No scans yet.</p>`;
      loadDashboardStats();
      return;
    }

    historyList.innerHTML = data.scans
      .map((scan) => {
        let levelClass = "low";

        if (scan.riskLevel === "Medium Risk") {
          levelClass = "medium";
        }

        if (scan.riskLevel === "High Risk") {
          levelClass = "high";
        }

        const date = new Date(scan.createdAt).toLocaleString();

        return `
          <div class="history-item">
            <div class="history-item-top">
              <strong class="${levelClass}">
                ${escapeHtml(scan.riskLevel)} - ${scan.riskScore}/100
              </strong>
            </div>

            <p class="history-preview">
              ${escapeHtml(scan.messagePreview)}
            </p>

           <p class="history-date">
  ${escapeHtml(date)}
  | ${escapeHtml(scan.category || "General Message")}
  | ${escapeHtml(scan.analysisType || "Rule-based")}
</p>
<button class="delete-scan-btn" data-id="${scan._id}">
  Delete
</button>
          </div>
        `;
      })
      .join("");
      document.querySelectorAll(".delete-scan-btn").forEach((button) => {
  button.addEventListener("click", async () => {
    const scanId = button.dataset.id;

    const confirmed = confirm("Delete this scan?");

    if (!confirmed) {
      return;
    }

    button.textContent = "Deleting...";
    button.disabled = true;

    try {
      await apiRequest(`/api/history/${scanId}`, {
        method: "DELETE",
      });

      loadHistory();
      loadUsage();
      loadDashboardStats();
    } catch (error) {
      alert(error.message);
      button.textContent = "Delete";
      button.disabled = false;
    }
  });
});
  } catch (error) {
    historyList.innerHTML = `
      <p class="privacy-note">${escapeHtml(error.message)}</p>
    `;
  }
}

updateUI();
