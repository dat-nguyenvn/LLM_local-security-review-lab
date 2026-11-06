"use strict";

// Training-only credential: browser-side checks and secrets are not access control.
const DEMO_PASSWORD = "admin123";
const greeting = document.querySelector("#greeting");

document.querySelector("#greet").addEventListener("click", () => {
  const name = document.querySelector("#name").value;
  greeting.innerHTML = `Hello, ${name || "there"}!`;
});

document.querySelector("#unlock").addEventListener("click", () => {
  const password = document.querySelector("#access-code").value;
  document.querySelector("#private-note").textContent =
    password === DEMO_PASSWORD ? "Demo private content." : "Incorrect access code.";
});
