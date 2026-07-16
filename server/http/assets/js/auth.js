const password = document.getElementById("password");
const auth = document.getElementById("auth");
const error = document.getElementById("error");

window.addEventListener("keypress", evt => {
    if (evt.key === "Enter") {
        evt.preventDefault();
        auth.click();
    }
});

auth.addEventListener("click", () => {
    fetch("/api/auth", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({password: password.value})
    })
    .then(evt => {
        if (evt.status == 200) {
            window.location.replace("/");
        } else {
            error.textContent = "Invalid password";
            password.value = "";
        }
    });
});