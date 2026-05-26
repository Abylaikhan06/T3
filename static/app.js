const state = {
  token: localStorage.getItem("access_token"),
  user: null,
  orders: []
};

const byId = (id) => document.getElementById(id);
const views = ["guest", "dashboard", "orders", "admin"];

function notify(message, isError = false) {
  const toast = byId("toast");
  toast.textContent = message;
  toast.classList.toggle("error", isError);
  toast.classList.remove("hidden");
  clearTimeout(notify.timeout);
  notify.timeout = setTimeout(() => toast.classList.add("hidden"), 3500);
}

function detailMessage(data) {
  if (Array.isArray(data.detail)) {
    return data.detail.map((item) => item.msg).join(". ");
  }
  return data.detail || "Не удалось выполнить действие";
}

async function api(path, options = {}) {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (state.token) {
    headers.Authorization = `Bearer ${state.token}`;
  }
  const response = await fetch(path, { ...options, headers });
  const data = await response.json().catch(() => ({}));
  if (response.status === 401 && path !== "/auth/login") {
    clearSession();
    showAuth("login");
  }
  if (!response.ok) {
    throw new Error(detailMessage(data));
  }
  return data;
}

function showView(name) {
  views.forEach((view) => byId(`${view}-view`).classList.toggle("hidden", view !== name));
  document.querySelectorAll(".nav-link").forEach((link) => {
    link.classList.toggle("active", link.dataset.view === name);
  });
}

function setAuthorizationView() {
  const loggedIn = Boolean(state.user);
  document.querySelectorAll(".auth-only").forEach((item) => item.classList.toggle("hidden", !loggedIn));
  document.querySelectorAll(".admin-only").forEach((item) => {
    item.classList.toggle("hidden", !loggedIn || !state.user.roles.includes("admin"));
  });
  byId("open-auth").classList.toggle("hidden", loggedIn);
  byId("logout").classList.toggle("hidden", !loggedIn);
  byId("identity").textContent = loggedIn ? state.user.full_name : "";
}

function renderProfile() {
  byId("welcome-name").textContent = state.user.full_name;
  byId("profile-name").textContent = state.user.full_name;
  byId("profile-email").textContent = state.user.email;
  byId("role-badge").textContent = state.user.roles.join(", ");
  setAuthorizationView();
}

function formatMoney(value) {
  return new Intl.NumberFormat("ru-RU", { style: "currency", currency: "KZT" }).format(value);
}

function renderOrders() {
  const preview = byId("orders-preview");
  const grid = byId("orders-grid");
  preview.innerHTML = state.orders.slice(0, 3).map((order) => `
    <div class="order-item">
      <div><strong>${escapeHtml(order.title)}</strong><br><span>${escapeHtml(order.owner_email)}</span></div>
      <strong>${formatMoney(order.amount)}</strong>
    </div>`).join("") || "<p class='muted'>Нет доступных заказов.</p>";
  grid.innerHTML = state.orders.map((order) => `
    <article class="card order-card">
      <p class="eyebrow">Заказ #${order.id}</p>
      <h2>${escapeHtml(order.title)}</h2>
      <p class="muted">Владелец: ${escapeHtml(order.owner_email)}</p>
      <p class="amount">${formatMoney(order.amount)}</p>
      <div class="order-actions">
        <button class="text-button edit-order" data-id="${order.id}">Изменить</button>
        <button class="text-button danger delete-order" data-id="${order.id}">Удалить</button>
      </div>
    </article>`).join("") || "<p class='muted'>Нет доступных заказов.</p>";
}

function escapeHtml(value) {
  const element = document.createElement("span");
  element.textContent = String(value);
  return element.innerHTML;
}

async function loadOrders() {
  state.orders = await api("/resources/orders");
  renderOrders();
}

async function openDashboard() {
  state.user = await api("/users/me");
  renderProfile();
  await loadOrders();
  showView("dashboard");
}

function saveSession(token) {
  state.token = token;
  localStorage.setItem("access_token", token);
}

function clearSession() {
  state.token = null;
  state.user = null;
  state.orders = [];
  localStorage.removeItem("access_token");
  setAuthorizationView();
  showView("guest");
}

function showAuth(tabName) {
  byId("auth-modal").classList.remove("hidden");
  const login = tabName === "login";
  byId("login-tab").classList.toggle("active", login);
  byId("register-tab").classList.toggle("active", !login);
  byId("login-form").classList.toggle("hidden", !login);
  byId("register-form").classList.toggle("hidden", login);
}

function closeModal(id) {
  byId(id).classList.add("hidden");
}

async function renderRules() {
  const rules = await api("/admin/rules");
  const permissions = [
    "read_permission",
    "read_all_permission",
    "create_permission",
    "update_permission",
    "update_all_permission",
    "delete_permission",
    "delete_all_permission"
  ];
  byId("rules-body").innerHTML = rules.map((rule) => `
    <tr data-role="${rule.role}" data-element="${rule.element}">
      <td><strong>${rule.role}</strong><span>${rule.element}</span></td>
      ${permissions.map((name) => `<td><input type="checkbox" name="${name}" ${rule[name] ? "checked" : ""}></td>`).join("")}
      <td><button class="button outline small save-rule">Сохранить</button></td>
    </tr>`).join("");
}

async function routeTo(name) {
  if (name === "dashboard") {
    if (state.user) {
      await openDashboard();
    } else {
      showView("guest");
    }
    return;
  }
  if (!state.user) {
    showAuth("login");
    return;
  }
  if (name === "orders") {
    await loadOrders();
    showView("orders");
  }
  if (name === "admin" && state.user.roles.includes("admin")) {
    await renderRules();
    showView("admin");
  }
}

document.addEventListener("click", async (event) => {
  const viewButton = event.target.closest("[data-view]");
  if (viewButton) {
    await routeTo(viewButton.dataset.view).catch((error) => notify(error.message, true));
  }
  if (event.target.closest("#open-auth") || event.target.closest("#start-login")) {
    showAuth("login");
  }
  if (event.target.closest("#start-register")) {
    showAuth("register");
  }
  if (event.target.closest("#login-tab")) {
    showAuth("login");
  }
  if (event.target.closest("#register-tab")) {
    showAuth("register");
  }
  const close = event.target.closest("[data-close]");
  if (close) {
    closeModal(close.dataset.close);
  }
  if (event.target.closest("#logout")) {
    try {
      await api("/auth/logout", { method: "POST" });
    } catch (error) {
      notify(error.message, true);
    }
    clearSession();
    notify("Вы вышли из системы");
  }
  if (event.target.closest("#edit-profile")) {
    const form = byId("profile-form");
    form.elements.full_name.value = state.user.full_name;
    form.elements.email.value = state.user.email;
    byId("profile-modal").classList.remove("hidden");
  }
  if (event.target.closest("#delete-account")) {
    if (confirm("Удалить аккаунт? После удаления войти в него будет нельзя.")) {
      try {
        await api("/users/me", { method: "DELETE" });
        clearSession();
        notify("Аккаунт удалён");
      } catch (error) {
        notify(error.message, true);
      }
    }
  }
  if (event.target.closest("#new-order")) {
    const form = byId("order-form");
    form.reset();
    form.elements.id.value = "";
    byId("order-form-title").textContent = "Новый заказ";
    byId("order-modal").classList.remove("hidden");
  }
  const editOrder = event.target.closest(".edit-order");
  if (editOrder) {
    const order = state.orders.find((item) => item.id === Number(editOrder.dataset.id));
    const form = byId("order-form");
    form.elements.id.value = order.id;
    form.elements.title.value = order.title;
    form.elements.amount.value = order.amount;
    byId("order-form-title").textContent = "Изменить заказ";
    byId("order-modal").classList.remove("hidden");
  }
  const deleteOrder = event.target.closest(".delete-order");
  if (deleteOrder && confirm("Удалить этот заказ?")) {
    try {
      await api(`/resources/orders/${deleteOrder.dataset.id}`, { method: "DELETE" });
      await loadOrders();
      notify("Заказ удалён");
    } catch (error) {
      notify(error.message, true);
    }
  }
  const saveRule = event.target.closest(".save-rule");
  if (saveRule) {
    const row = saveRule.closest("tr");
    const values = {};
    row.querySelectorAll("input").forEach((input) => {
      values[input.name] = input.checked;
    });
    try {
      await api(`/admin/rules/${row.dataset.role}/${row.dataset.element}`, {
        method: "PUT",
        body: JSON.stringify(values)
      });
      notify("Правило сохранено");
    } catch (error) {
      notify(error.message, true);
    }
  }
});

byId("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.target;
  try {
    const response = await api("/auth/login", {
      method: "POST",
      body: JSON.stringify({ email: form.elements.email.value, password: form.elements.password.value })
    });
    saveSession(response.access_token);
    state.user = response.user;
    closeModal("auth-modal");
    await openDashboard();
    notify("Вход выполнен");
  } catch (error) {
    notify(error.message, true);
  }
});

byId("register-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.target;
  const body = {
    full_name: form.elements.full_name.value,
    email: form.elements.email.value,
    password: form.elements.password.value,
    password_repeat: form.elements.password_repeat.value
  };
  try {
    await api("/auth/register", { method: "POST", body: JSON.stringify(body) });
    const response = await api("/auth/login", {
      method: "POST",
      body: JSON.stringify({ email: body.email, password: body.password })
    });
    saveSession(response.access_token);
    state.user = response.user;
    closeModal("auth-modal");
    await openDashboard();
    notify("Регистрация завершена");
  } catch (error) {
    notify(error.message, true);
  }
});

byId("profile-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.target;
  try {
    state.user = await api("/users/me", {
      method: "PUT",
      body: JSON.stringify({ full_name: form.elements.full_name.value, email: form.elements.email.value })
    });
    renderProfile();
    closeModal("profile-modal");
    notify("Профиль обновлён");
  } catch (error) {
    notify(error.message, true);
  }
});

byId("order-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.target;
  const id = form.elements.id.value;
  try {
    await api(id ? `/resources/orders/${id}` : "/resources/orders", {
      method: id ? "PATCH" : "POST",
      body: JSON.stringify({ title: form.elements.title.value, amount: Number(form.elements.amount.value) })
    });
    closeModal("order-modal");
    await loadOrders();
    notify("Заказ сохранён");
  } catch (error) {
    notify(error.message, true);
  }
});

async function initialize() {
  setAuthorizationView();
  if (state.token) {
    try {
      await openDashboard();
      return;
    } catch (error) {
      clearSession();
    }
  }
  showView("guest");
}

initialize();
