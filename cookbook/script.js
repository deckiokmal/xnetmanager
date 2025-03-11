document.getElementById('loginForm').addEventListener('submit', function(event) {
    event.preventDefault(); // Mencegah reload halaman
    
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;

    if (email.trim() === "" || password.trim() === "") {
        alert("Harap isi email dan password!");
        return;
    }

    // Simulasi login berhasil
    alert("Login berhasil!");
    window.location.href = "dashboard.html"; // Redirect ke halaman dashboard
});
