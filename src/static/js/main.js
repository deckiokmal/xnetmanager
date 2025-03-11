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

// Toggle tampilan dinamis di mobile
function toggleInstructions() {
    const instruction = document.querySelector('.tfa-instruction');
    const toggleBtn = document.querySelector('.mobile-instruction-toggle');
    instruction.classList.toggle('show');
    
    if (instruction.classList.contains('show')) {
        toggleBtn.textContent = 'Sembunyikan Instruksi';
    } else {
        toggleBtn.textContent = 'Tampilkan Instruksi';
    }
}

function showAlert(message, type) {
    const alert = document.createElement('div');
    alert.className = `alert alert-${type} alert-dismissible fade show`;
    alert.role = "alert";
    alert.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    document.querySelector('.tfa-form').prepend(alert);
}