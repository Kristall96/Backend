const apiUrl = "http://localhost:4000/api/auth"; // ✅ Add this line at the top
let csrfToken = ""; // 🔥 Store CSRF Token

async function fetchCsrfToken() {
  try {
    const response = await fetch("http://localhost:4000/api/csrf-token", {
      credentials: "include",
    });
    const data = await response.json();
    csrfToken = data.csrfToken; // ✅ Update token dynamically
  } catch (error) {
    console.error("❌ Failed to fetch CSRF token:", error);
  }
}

// ✅ Fetch CSRF token on page load
document.addEventListener("DOMContentLoaded", async () => {
  await fetchCsrfToken(); // ✅ Fetch CSRF token first
  checkAuthStatus(); // ✅ Call this AFTER `apiUrl` is defined
});

// 🔹 Function to check if user is authenticated
async function checkAuthStatus() {
  try {
    const response = await fetch(`${apiUrl}/verify-token`, {
      method: "GET",
      credentials: "include",
      headers: {
        "X-CSRF-Token": csrfToken, // ✅ Include CSRF token
      },
    });

    if (response.ok) {
      updateNavbar(true);
    } else {
      updateNavbar(false);
    }
  } catch (error) {
    console.error("❌ Auth check failed:", error);
    updateNavbar(false);
  }
}

// 🔹 Function to update the navbar dynamically
function updateNavbar(isAuthenticated) {
  document.getElementById("login-link").style.display = isAuthenticated
    ? "none"
    : "block";
  document.getElementById("register-link").style.display = isAuthenticated
    ? "none"
    : "block";
  document.getElementById("logout-link").style.display = isAuthenticated
    ? "block"
    : "none";
  document.getElementById("profile-link").style.display = isAuthenticated
    ? "block"
    : "none";
  document.getElementById("welcome-message").innerText = isAuthenticated
    ? "Welcome Back!"
    : "Welcome to the Authentication System";
}

// 🔹 Helper Function for Fetch Requests with CSRF Token
async function sendRequest(url, method, body = null) {
  const options = {
    method,
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": csrfToken, // ✅ Ensure CSRF token is included
    },
    credentials: "include",
  };

  if (body) options.body = JSON.stringify(body);

  return fetch(url, options);
}

async function register() {
  const username = document.getElementById("reg-username").value;
  const email = document.getElementById("reg-email").value;
  const password = document.getElementById("reg-password").value;

  try {
    const response = await fetch("http://localhost:4000/api/auth/register", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": csrfToken, // ✅ Send CSRF Token
      },
      credentials: "include",
      body: JSON.stringify({ username, email, password }),
    });

    const data = await response.json();
    alert(data.message);

    if (response.ok) {
      updateNavbar(true);
    }
  } catch (error) {
    console.error("❌ Registration error:", error);
    alert("Registration failed. Please try again.");
  }
}

async function login() {
  const email = document.getElementById("login-email").value;
  const password = document.getElementById("login-password").value;

  try {
    const response = await fetch(`${apiUrl}/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": csrfToken,
      },
      credentials: "include",
      body: JSON.stringify({ email, password }),
    });

    const data = await response.json();
    alert(data.message);

    if (response.ok) {
      csrfToken = data.csrfToken; // ✅ Update CSRF Token After Login
      updateNavbar(true);
    }
  } catch (error) {
    console.error("❌ Login request error:", error);
    alert("Login request failed. Please try again.");
  }
}

async function logout() {
  try {
    const response = await fetch(`${apiUrl}/logout`, {
      method: "POST",
      headers: {
        "X-CSRF-Token": csrfToken,
      },
      credentials: "include",
    });

    const data = await response.json();
    alert(data.message);

    csrfToken = data.csrfToken; // ✅ Update CSRF Token After Logout
    updateNavbar(false);
  } catch (error) {
    console.error("❌ Logout error:", error);
  }
}

// ✅ Fetch CSRF Token Before Running Any Request
document.addEventListener("DOMContentLoaded", async () => {
  await fetchCsrfToken();
  checkAuthStatus();
});

// ✅ Attach event listeners after fetching CSRF token
document.getElementById("register-button").addEventListener("click", register);
document.getElementById("login-button").addEventListener("click", login);
document
  .getElementById("logout-link")
  .addEventListener("click", function (event) {
    event.preventDefault();
    logout();
  });
