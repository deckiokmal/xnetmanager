// Utility Functions
function showLoadingOverlay() {
    document.getElementById('loadingOverlay').style.display = 'flex';
}

function hideLoadingOverlay() {
    document.getElementById('loadingOverlay').style.display = 'none';
}

function handleFetchError(error) {
    console.error('Fetch Error:', error);
    alert('An error occurred. Please try again.');
}

// Event Handlers
document.addEventListener('DOMContentLoaded', function () {
    // Check Status Button
    document.getElementById('checkStatusButton')?.addEventListener('click', function () {
        const currentPage = document.querySelector('.pagination .active a')?.textContent.trim() || 1;
        const perPage = parseInt(document.getElementById('itemsPerPage').value, 10) || 10;
        const searchQuery = document.getElementById('searchInput').value.trim() || '';
        const csrfToken = document.querySelector('input[name="csrf_token"]').value;

        showLoadingOverlay();

        fetch('/check_status', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            },
            body: JSON.stringify({
                page: currentPage,
                per_page: perPage,
                search_query: searchQuery
            })
        })
        .then(response => response.json())
        .then(data => {
            Object.keys(data).forEach(deviceId => {
                const statusIndicator = document.getElementById(`statusIndicator${deviceId}`);
                if (statusIndicator) {
                    statusIndicator.classList.toggle('status-indicator-green', data[deviceId] === 'success');
                    statusIndicator.classList.toggle('status-indicator-red', data[deviceId] !== 'success');
                }
            });
        })
        .catch(handleFetchError)
        .finally(hideLoadingOverlay);
    });

    // Select Devices Button
    document.getElementById('selectDevicesBtn')?.addEventListener('click', function () {
        const checklistButtons = document.getElementsByClassName('checklist-buttons');
        const isChecklistVisible = checklistButtons[0]?.style.display !== 'none';
        Array.from(checklistButtons).forEach(button => {
            button.style.display = isChecklistVisible ? 'none' : 'block';
        });
    });

    // Push Config Button
    document.getElementById('pushConfigBtn')?.addEventListener('click', function () {
        const selectedDevices = Array.from(document.querySelectorAll('.btn-check:checked')).map(checkbox => checkbox.getAttribute('data-ip'));
        if (selectedDevices.length > 0) {
            const selectConfigModal = new bootstrap.Modal(document.getElementById('selectConfigModal'));
            selectConfigModal.show();
        } else {
            alert('Please select at least one device.');
        }
    });

    // Backup Multiple Button
    document.getElementById('backupMultipleBtn')?.addEventListener('click', function () {
        const selectedDevices = Array.from(document.querySelectorAll('.btn-check:checked')).map(checkbox => checkbox.getAttribute('data-ip'));
        if (selectedDevices.length > 0) {
            const createBackupModal = new bootstrap.Modal(document.getElementById('createBackupModal'));
            createBackupModal.show();
            document.getElementById('selectedBackupDevices').value = JSON.stringify(selectedDevices);
        } else {
            alert('Please select at least one device.');
        }
    });

    // Initial Configuration Button
    document.getElementById('InitialConfigButton')?.addEventListener('click', function () {
        const csrfToken = document.querySelector('input[name="csrf_token"]').value;
    
        showLoadingOverlay();
    
        fetch('/initial-configuration', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            }
        })
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            return response.text(); // Karena ini merender template, bukan JSON
        })
        .then(html => {
            document.open();
            document.write(html);
            document.close();
        })
        .catch(handleFetchError)
        .finally(hideLoadingOverlay);
    });
    
});


// Fungsi untuk menangani push config ke multiple devices
document.getElementById('confirmPushConfigBtn')?.addEventListener('click', function () {
    const selectedConfig = document.getElementById('configSelect').value;
    const selectedDevices = Array.from(document.querySelectorAll('.btn-check:checked')).map(checkbox => checkbox.getAttribute('data-ip'));
    const csrfToken = document.querySelector('input[name="csrf_token"]').value;

    if (selectedConfig && selectedDevices.length > 0) {
        showLoadingOverlay();

        fetch('/push_configs', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            },
            body: JSON.stringify({ devices: selectedDevices, config_id: selectedConfig })
        })
        .then(response => response.json())
        .then(data => {
            let tableHTML = '<table class="table table-bordered"><thead><tr><th>Device Name</th><th>IP Address</th><th>Status</th><th>Message</th></tr></thead><tbody>';
            data.results.forEach(result => {
                tableHTML += `<tr><td>${result.device_name}</td><td>${result.ip}</td><td>${result.status}</td><td>${result.message}</td></tr>`;
            });
            tableHTML += '</tbody></table>';
            document.getElementById('pushConfigResultTable').innerHTML = tableHTML;

            // Tampilkan modal hasil push config
            const pushConfigResultModal = new bootstrap.Modal(document.getElementById('pushConfigResultModal'));
            pushConfigResultModal.show();
        })
        .catch(error => {
            alert('Error pushing configurations: ' + error.message);
        })
        .finally(() => {
            hideLoadingOverlay();
        });
    } else {
        alert('Please select a config and at least one device.');
    }
});

// Fungsi untuk menangani push config ke single device
document.querySelectorAll('form[id^="pushConfigForm"]').forEach(form => {
    form.addEventListener('submit', function (e) {
        e.preventDefault();

        const deviceId = form.id.replace('pushConfigForm', '');
        const configId = document.getElementById(`configSelect${deviceId}`).value;
        const csrfToken = document.querySelector('input[name="csrf_token"]').value;

        if (!configId) {
            alert('Please select a config.');
            return;
        }

        showLoadingOverlay();

        fetch(`/push_config/${deviceId}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            },
            body: JSON.stringify({ config_id: configId })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert('Configuration successfully applied!');
                // Tutup modal setelah sukses
                const pushConfigModal = bootstrap.Modal.getInstance(document.getElementById(`pushConfigModal${deviceId}`));
                pushConfigModal.hide();
            } else if (data.result && data.result.message) {
                // Tampilkan modal error dengan pesan dari backend
                document.getElementById('pushConfigErrorModalBody').innerText = data.result.message;
                const pushConfigErrorModal = new bootstrap.Modal(document.getElementById('pushConfigErrorModal'));
                pushConfigErrorModal.show();
            } else {
                alert('An unknown error occurred. Please try again.');
            }
        })
        .catch(error => {
            console.error('Error pushing config:', error);
            alert('Error pushing configuration.');
        })
        .finally(() => {
            hideLoadingOverlay();
        });
    });
});

// Reload halaman saat modal pushConfigResultModal ditutup
document.getElementById('pushConfigResultModal')?.addEventListener('hidden.bs.modal', function () {
    location.reload();
});

// Reload halaman saat modal pushConfigErrorModal ditutup
document.getElementById('pushConfigErrorModal')?.addEventListener('hidden.bs.modal', function () {
    location.reload();
});

// Variabel untuk menyimpan vendor yang dipilih
let selectedVendor = null;

// Fungsi untuk mengambil daftar konfigurasi berdasarkan vendor
function fetchConfigsByVendor(vendor, configSelectId = 'configSelect') {
    const csrfToken = document.querySelector('input[name="csrf_token"]').value;

    fetch('/get_configs_by_vendor', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': csrfToken
        },
        body: JSON.stringify({ vendor: vendor })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            const configSelect = document.getElementById(configSelectId);
            configSelect.innerHTML = "<option value='' disabled selected>Select a config</option>";
            data.configs.forEach(config => {
                const option = document.createElement('option');
                option.value = config.id;
                option.textContent = config.name;
                configSelect.appendChild(option);
            });
        } else {
            alert(data.message || 'No configurations available for selected vendor.');
        }
    })
    .catch(error => {
        console.error('Error fetching configurations:', error);
        alert('Error fetching configurations. Please try again.');
    });
}

// Event listener untuk tombol checklist (multiple devices)
document.querySelectorAll('.btn-check').forEach(button => {
    button.addEventListener('change', function () {
        const deviceVendor = this.closest('tr').querySelector('td:nth-child(5)').innerText.trim();

        if (this.checked) {
            if (selectedVendor === null) {
                // Set vendor pertama yang dipilih dan ambil konfigurasi berdasarkan vendor
                selectedVendor = deviceVendor;
                fetchConfigsByVendor(selectedVendor);
            } else if (selectedVendor !== deviceVendor) {
                // Vendor tidak cocok, tampilkan pesan peringatan dan batalkan pemilihan
                alert('You can only select devices with the same vendor.');
                this.checked = false;
            }
        } else {
            // Jika uncheck dan tidak ada perangkat lain yang dipilih, reset selectedVendor
            const anyChecked = Array.from(document.querySelectorAll('.btn-check:checked')).some(cb => cb !== this);
            if (!anyChecked) {
                selectedVendor = null;
                document.getElementById('configSelect').innerHTML = ''; // Kosongkan select config
            }
        }
    });
});

// Event listener untuk tombol Config (single device)
document.querySelectorAll('.btn-primary[data-bs-target^="#pushConfigModal"]').forEach(button => {
    button.addEventListener('click', function () {
        const deviceId = button.getAttribute('data-bs-target').replace('#pushConfigModal', '');
        const deviceVendor = button.closest('tr').querySelector('td:nth-child(5)').innerText.trim();

        // Ambil daftar konfigurasi berdasarkan vendor untuk single device
        fetchConfigsByVendor(deviceVendor, `configSelect${deviceId}`);
    });
});

// Fungsi untuk menangani backup single device
document.querySelectorAll('form[id^="backupForm"]').forEach(form => {
    form.addEventListener('submit', function (e) {
        e.preventDefault();

        const deviceId = form.id.replace('backupForm', ''); // Ambil device ID dari form ID
        const backupData = {
            backup_name: document.getElementById(`backupName${deviceId}`).value,
            description: document.getElementById(`description${deviceId}`).value,
            backup_type: document.getElementById(`backupType${deviceId}`).value,
            command: document.getElementById(`command${deviceId}`).value
        };
        const csrfToken = document.querySelector('input[name="csrf_token"]').value;

        showLoadingOverlay(); // Tampilkan loading overlay

        fetch(`/backups/create_single/${deviceId}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            },
            body: JSON.stringify(backupData)
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert('Backup created successfully!');
                // Tutup modal setelah sukses
                const backupModal = bootstrap.Modal.getInstance(document.getElementById(`backupModal${deviceId}`));
                backupModal.hide();
            } else {
                alert('Failed to create backup: ' + data.message);
            }
        })
        .catch(error => {
            console.error('Error creating backup:', error);
            alert('Error creating backup.');
        })
        .finally(() => {
            hideLoadingOverlay(); // Sembunyikan loading overlay
        });
    });
});

// Fungsi untuk menangani backup multiple devices
document.getElementById('createBackupForm')?.addEventListener('submit', function (e) {
    e.preventDefault();

    const backupData = {
        backup_name: document.getElementById('backupName').value,
        description: document.getElementById('description').value,
        backup_type: document.getElementById('backupType').value,
        retention_days: document.getElementById('retentionDays').value,
        command: document.getElementById('command').value,
        devices: JSON.parse(document.getElementById('selectedBackupDevices').value) // Ambil daftar perangkat yang dipilih
    };
    const csrfToken = document.querySelector('input[name="csrf_token"]').value;

    showLoadingOverlay(); // Tampilkan loading overlay

    fetch('/backups/create_multiple', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': csrfToken
        },
        body: JSON.stringify(backupData)
    })
    .then(response => response.json())
    .then(data => {
        let resultTableHTML = '<table class="table table-bordered"><thead><tr><th>Device Name</th><th>IP Address</th><th>Status</th><th>Message</th></tr></thead><tbody>';
        data.results.forEach(result => {
            resultTableHTML += `<tr><td>${result.device_name}</td><td>${result.ip}</td><td>${result.status}</td><td>${result.message}</td></tr>`;
        });
        resultTableHTML += '</tbody></table>';

        document.getElementById('backupResultTable').innerHTML = resultTableHTML;

        // Tutup modal create backup
        const createBackupModal = bootstrap.Modal.getInstance(document.getElementById('createBackupModal'));
        createBackupModal.hide();

        // Tampilkan modal hasil backup
        const backupResultModal = new bootstrap.Modal(document.getElementById('backupResultModal'));
        backupResultModal.show();
    })
    .catch(error => {
        console.error('Error creating backup:', error);
        alert('Error creating backup.');
    })
    .finally(() => {
        hideLoadingOverlay(); // Sembunyikan loading overlay
    });
});

// Reload halaman saat modal backupResultModal ditutup
document.getElementById('backupResultModal')?.addEventListener('hidden.bs.modal', function () {
    location.reload();
});

// initial configuration wizard

let currentStep = 1;

function nextStep(step) {
    document.getElementById(`step-${currentStep}`).classList.remove('active');
    document.getElementById(`step-${step}`).classList.add('active');
    currentStep = step;
    updateProgressBar();
}

function prevStep(step) {
    document.getElementById(`step-${currentStep}`).classList.remove('active');
    document.getElementById(`step-${step}`).classList.add('active');
    currentStep = step;
    updateProgressBar();
}

function updateProgressBar() {
    const progress = (currentStep - 1) * 20;
    document.getElementById('progress-bar').style.width = `${progress}%`;
    document.getElementById('progress-bar').textContent = `Step ${currentStep}`;
}

function saveConfig() {
    document.getElementById('config-preview').textContent = "Konfigurasi berhasil dibuat dalam format Jinja2 & YAML.";
    nextStep(6);
}

function downloadConfig() {
    alert("File konfigurasi siap diunduh.");
}

function toggleDHCP() {
    const dhcpDiv = document.getElementById("dhcp-options");
    const checkbox = document.getElementById("enable-dhcp");

    if (checkbox.checked) {
        dhcpDiv.style.display = "block";
    } else {
        dhcpDiv.style.display = "none";
    }
}

function toggleNatOptions(type) {
    const optionsDiv = document.getElementById(`nat-${type}-options`);
    const checkbox = document.getElementById(`nat-${type}`);

    if (checkbox.checked) {
        optionsDiv.style.display = "block";
    } else {
        optionsDiv.style.display = "none";
    }
}
