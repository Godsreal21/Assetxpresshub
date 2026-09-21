async function api(path, options = {}) {
  const response = await fetch("/api" + path, {
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {})
    },
    ...options
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(data.error || "Something went wrong.");
  }

  return data;
}

function openModal(type) {
  document.getElementById("modal").classList.add("show");

  if (type === "register") {
    showRegister();
  } else {
    showLogin();
  }
}

function closeModal() {
  document.getElementById("modal").classList.remove("show");
}

function showRegister() {
  document.getElementById("loginForm").classList.add("hidden");
  document.getElementById("registerForm").classList.remove("hidden");
  document.getElementById("loginMessage").textContent = "";
  document.getElementById("registerMessage").textContent = "";
}

function showLogin() {
  document.getElementById("registerForm").classList.add("hidden");
  document.getElementById("loginForm").classList.remove("hidden");
  document.getElementById("loginMessage").textContent = "";
  document.getElementById("registerMessage").textContent = "";
}

async function registerUser(event) {
  event.preventDefault();

  const message = document.getElementById("registerMessage");
  message.textContent = "Creating your account...";

  const name = document.getElementById("registerName").value.trim();
  const email = document.getElementById("registerEmail").value.trim();
  const password = document.getElementById("registerPassword").value;

  try {
    await api("/register", {
      method: "POST",
      body: JSON.stringify({ name, email, password })
    });

    message.textContent = "Account created successfully.";

    setTimeout(() => {
      closeModal();
      loadAccount();
    }, 800);

  } catch (error) {
    message.textContent = error.message;
  }
}

async function loginUser(event) {
  event.preventDefault();

  const message = document.getElementById("loginMessage");
  message.textContent = "Signing in...";

  const email = document.getElementById("loginEmail").value.trim();
  const password = document.getElementById("loginPassword").value;

  try {
    await api("/login", {
      method: "POST",
      body: JSON.stringify({ email, password })
    });

    message.textContent = "Login successful.";

    setTimeout(() => {
      closeModal();
      loadAccount();
    }, 500);

  } catch (error) {
    message.textContent = error.message;
  }
}

async function loadAccount() {
  try {
    const data = await api("/me");

    if (!data.user) {
      return;
    }

    showDashboard(data.user);
  } catch (error) {
    console.log("Account check:", error.message);
  }
}

function showDashboard(user) {
  const old = document.getElementById("accountPanel");

  if (old) {
    old.remove();
  }

  const panel = document.createElement("section");
  panel.id = "accountPanel";
  panel.className = "section";

  panel.innerHTML = `
    <div class="section-title">
      <span class="eyebrow">MY ACCOUNT</span>
      <h2>Welcome, ${escapeHtml(user.name)}</h2>
      <p>Your Assetxpresshub account is ready.</p>
    </div>

    <div class="cards">
      <div class="card">
        <div class="card-icon">$</div>
        <h3>Account Balance</h3>
        <p class="balance">$${Number(user.balance || 0).toFixed(2)}</p>
      </div>

      <div class="card">
        <div class="card-icon">◎</div>
        <h3>Account Status</h3>
        <p>Active account</p>
      </div>

      <div class="card">
        <div class="card-icon">↗</div>
        <h3>Account Type</h3>
        <p>${escapeHtml(user.role || "user")}</p>
      </div>
    </div>

    <button class="btn btn-outline" onclick="logoutUser()" style="margin-top:25px">
      Logout
    </button>
  `;

  document.querySelector("main").appendChild(panel);
  panel.scrollIntoView({ behavior: "smooth" });
}

async function logoutUser() {
  try {
    await api("/logout", { method: "POST" });
    location.reload();
  } catch (error) {
    alert(error.message);
  }
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

window.addEventListener("click", function(event) {
  const modal = document.getElementById("modal");

  if (event.target === modal) {
    closeModal();
  }
});

loadAccount();
