document.addEventListener("DOMContentLoaded", function () {
    const registerForm = document.getElementById("registerForm");
    if (registerForm) {
        registerForm.addEventListener("submit", function (e) {
            e.preventDefault();
            const data = {
                username: document.getElementById("username").value,
                email: document.getElementById("email").value,
                phone: document.getElementById("phone").value,
                password: document.getElementById("password").value
            };

            fetch("/register", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(data)
            })
            .then(response => response.json())
            .then(data => alert(data.message || data.error))
            .catch(error => console.error("Error:", error));
        });
    }

    const loginForm = document.getElementById("loginForm");
    if (loginForm) {
        loginForm.addEventListener("submit", function (e) {
            e.preventDefault();
            const data = {
                identifier: document.getElementById("identifier").value,
                password: document.getElementById("password").value
            };

            fetch("/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(data)
            })
            .then(response => response.json())
            .then(data => alert(data.message || data.error))
            .catch(error => console.error("Error:", error));
        });
    }

    const forgotPasswordForm = document.getElementById("forgotPasswordForm");
    if (forgotPasswordForm) {
        forgotPasswordForm.addEventListener("submit", function (e) {
            e.preventDefault();
            const data = {
                identifier: document.getElementById("identifier").value
            };

            fetch("/forgot-password", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(data)
            })
            .then(response => response.json())
            .then(data => alert(data.message || data.error))
            .catch(error => console.error("Error:", error));
        });
    }
});
