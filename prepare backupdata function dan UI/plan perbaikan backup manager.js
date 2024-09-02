<!-- Modal untuk memilih command dan melakukan backup -->
<div class="modal fade" id="backupConfigModal" tabindex="-1" aria-labelledby="backupConfigModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content bg-black text-light">
            <div class="modal-header">
                <h5 class="modal-title" id="backupConfigModalLabel">Backup Configuration</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <div class="modal-body">
                <form id="backupConfigForm">
                    <div class="mb-3">
                        <label for="commandSelect" class="form-label">Pilih Command</label>
                        <select id="commandSelect" class="form-select" required>
                            <option value="" selected disabled>Select a command</option>
                            <option value="show full-configuration">Fortinet</option>
                            <option value="show running-config">Cisco</option>
                            <option value="export compact terse">MikroTik</option>
                            <!-- Tambahkan vendor lain sesuai kebutuhan -->
                        </select>
                    </div>
                    <!-- Tambahkan input untuk pesan commit -->
                    <div class="mb-3">
                        <label for="commitMessage" class="form-label">Commit Message</label>
                        <textarea id="commitMessage" class="form-control" rows="3" placeholder="Enter commit message..."></textarea>
                    </div>
                    <button type="button" class="btn btn-primary" id="confirmBackupConfigBtn">Backup Konfigurasi</button>
                </form>
            </div>
        </div>
    </div>
</div>


// Event klik tombol Confirm Backup Konfigurasi
document.getElementById("confirmBackupConfigBtn").addEventListener("click", function () {
    const selectedCommand = document.getElementById("commandSelect").value;
    const commitMessage = document.getElementById("commitMessage").value; // Ambil commit message
    const selectedDevices = [];
    document.querySelectorAll(".btn-check:checked").forEach(function (checkbox) {
        selectedDevices.push(checkbox.getAttribute("data-id"));
    });

    if (selectedCommand && selectedDevices.length > 0) {
        fetch("/backup_config", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                devices: selectedDevices,
                command: selectedCommand,
                commit_message: commitMessage // Sertakan commit message dalam request
            })
        })
            .then(response => response.json())
            .then(data => {
                let tableHTML = '<table class="table table-bordered"><thead><tr><th>Device Name</th><th>Status</th><th>Message</th></tr></thead><tbody>';
                data.results.forEach(result => {
                    tableHTML += `<tr><td>${result.device_name}</td><td>${result.status}</td><td>${result.message}</td></tr>`;
                });
                tableHTML += '</tbody></table>';

                // Tampilkan hasil backup di modal
                const backupResultModal = new bootstrap.Modal(document.getElementById("backupResultModal"));
                document.getElementById("backupResultBody").innerHTML = tableHTML;

                // Tutup modal backupConfigModal dan tampilkan modal backupResultModal
                const backupConfigModal = bootstrap.Modal.getInstance(document.getElementById("backupConfigModal"));
                backupConfigModal.hide();
                backupResultModal.show();
            })
            .catch(error => console.error('Error:', error));
    } else {
        alert("Please select a command and at least one device.");
    }
});



