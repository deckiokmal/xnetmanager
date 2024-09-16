// Function to open the Share Backup Modal
function openShareBackupModal(button) {
    const backupId = button.getAttribute("data-backup-id");
    document.getElementById("backupId").value = backupId;

    // Initialize the Bootstrap modal and show it
    const shareModal = new bootstrap.Modal(document.getElementById("shareBackupModal"));
    shareModal.show();
}

// Function to handle sharing a backup
document.getElementById("shareBackupBtn").addEventListener("click", function() {
    const userEmail = document.getElementById("userEmail").value;
    const permissionLevel = document.getElementById("permissionLevel").value;
    const backupId = document.getElementById("backupId").value;

    // Validate that the fields are filled
    if (!userEmail || !permissionLevel || !backupId) {
        alert("Please fill in all fields before submitting.");
        return;
    }

    // Prepare the request body
    const requestBody = JSON.stringify({
        user_email: userEmail,
        backup_id: backupId,
        permission_level: permissionLevel
    });

    // Make the POST request to share the backup
    fetch("/share-backup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: requestBody
    })
    .then(response => {
        // Check if the response is OK
        if (!response.ok) {
            return response.json().then(errorData => {
                throw new Error(errorData.message || 'Error sharing backup');
            });
        }
        return response.json();
    })
    .then(data => {
        alert(data.message);  // Show success message
        // Close the modal after successful sharing
        const shareModal = bootstrap.Modal.getInstance(document.getElementById("shareBackupModal"));
        shareModal.hide();
        location.reload();  // Reload the page to reflect changes
    })
    .catch(error => {
        console.error('Error:', error);
        alert("An error occurred while sharing the backup: " + error.message);
    });
});


// Function to delete a backup
function deleteBackup(backupId) {
    if (confirm("Are you sure you want to delete this backup?")) {
        fetch(`/delete-backup/${backupId}`, { method: "DELETE" })
            .then(response => response.json())
            .then(data => {
                alert(data.message);
                location.reload();
            })
            .catch(error => console.error('Error:', error));
    }
}

// Function to show Backup Details
function showBackupDetails(button) {
    const backupId = button.getAttribute("data-backup-id");
    fetch(`/detail-backup/${backupId}`)
        .then(response => response.json())
        .then(data => {
            document.getElementById('detailBackupName').textContent = data.backup_name;
            document.getElementById('detailBackupDescription').textContent = data.description;
            document.getElementById('detailBackupVersion').textContent = data.version;
            document.getElementById('detailBackupDate').textContent = new Date(data.created_at).toLocaleString();
            document.getElementById('detailBackupEncrypted').textContent = data.is_encrypted ? "Yes" : "No";
            document.getElementById('detailBackupCompressed').textContent = data.is_compressed ? "Yes" : "No";
            document.getElementById('detailBackupIntegrity').textContent = data.integrity_check || "N/A";
            document.getElementById('detailBackupTags').textContent = data.tags.join(', ') || "None";
            document.getElementById('detailBackupContent').textContent = data.file_content || "No content available.";
            new bootstrap.Modal(document.getElementById("backupDetailModal")).show();
        })
        .catch(error => console.error('Error fetching backup details:', error));
}

// Function to initiate Rollback
function initiateRollback(button) {
    const backupId = button.getAttribute("data-backup-id");
    document.getElementById("confirmRollbackBtn").setAttribute("data-backup-id", backupId);
    new bootstrap.Modal(document.getElementById("rollbackConfirmModal")).show();
}

document.getElementById("confirmRollbackBtn").addEventListener("click", function () {
    const backupId = this.getAttribute("data-backup-id");
    fetch(`/rollback-backup/${backupId}`, { method: "POST", headers: { "Content-Type": "application/json" } })
        .then(response => response.json())
        .then(data => {
            alert(data.message);
            bootstrap.Modal.getInstance(document.getElementById("rollbackConfirmModal")).hide();
        })
        .catch(error => console.error('Error during rollback:', error));
});
