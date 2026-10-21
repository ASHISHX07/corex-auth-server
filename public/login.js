const form = document.querySelector("#login-form");
const usernameInput = document.querySelector("#username");
const passwordInput = document.querySelector("#password");
const submitButton = document.querySelector("#login-submit");
const errorElement = document.querySelector("#login-error");
const togglePasswordButton =
    document.querySelector("#toggle-password");

function showError(message) {
    errorElement.textContent = message;
    errorElement.hidden = false;
}

function clearError() {
    errorElement.textContent = "";
    errorElement.hidden = true;
}

togglePasswordButton.addEventListener("click", () => {
    const showingPassword = passwordInput.type === "password";

    passwordInput.type = showingPassword ? "text" : "password";

    togglePasswordButton.textContent =
        showingPassword ? "Hide" : "Show";

    togglePasswordButton.setAttribute(
        "aria-label",
        showingPassword ? "Hide password" : "Show password"
    );
});

form.addEventListener("submit", async (event) => {
    event.preventDefault();
    clearError();

    const username = usernameInput.value.trim();
    const password = passwordInput.value;

    if (!username || !password) {
        showError("Enter your admin ID and password.");
        return;
    }

    submitButton.disabled = true;
    submitButton.classList.add("loading");

    try {
        const response = await fetch("/api/v1/admin/login", {
            method: "POST",
            credentials: "same-origin",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ username, password })
        });

        if (response.ok) {
            window.location.replace("/");
            return;
        }

        if (response.status === 401) {
            showError("Invalid admin ID or password.");
        } else if (response.status === 429) {
            showError(
                "Too many login attempts. Please wait before trying again."
            );
        } else if (response.status === 403) {
            showError(
                "The request was rejected. Refresh the page and try again."
            );
        } else {
            showError(
                "Login is temporarily unavailable. Please try again later."
            );
        }
    } catch {
        showError(
            "Unable to reach CoreX. Check your connection and try again."
        );
    } finally {
        submitButton.disabled = false;
        submitButton.classList.remove("loading");
    }
});