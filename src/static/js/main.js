// show flash message login.html
document.addEventListener("DOMContentLoaded", function () {
    // Seleksi semua alert
    let alerts = document.querySelectorAll(".alert");

    alerts.forEach(function (alert) {
        // Tambahkan efek fade-in
        setTimeout(() => {
            alert.classList.add("show");
        }, 100);

        // Hapus otomatis setelah 5 detik
        setTimeout(() => {
            alert.classList.remove("show");
            setTimeout(() => alert.remove(), 500);
        }, 10000);
    });
});

// copy secret key 2fa
function copySecret() {
    var copyText = document.getElementById("secret");
    copyText.select();
    copyText.setSelectionRange(0, 99999); /*For mobile devices*/
    document.execCommand("copy");
    alert("Successfully copied TOTP secret token!");
}