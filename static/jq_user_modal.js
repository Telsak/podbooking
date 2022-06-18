var exampleModal = document.getElementById('userInfo')
    exampleModal.addEventListener('show.bs.modal', function (event) {
        // Button that triggered the modal
        var button = event.relatedTarget
        // Extract info from data-bs-* attributes
        var username = button.getAttribute('data-bs-username')
        // Update the modal's content.
        var modalTitle = exampleModal.querySelector('.modal-title')
        var modalBody = exampleModal.querySelector('.modal-body')
        modalTitle.textContent = 'User Information for ' + username
        modalBody.textContent = 'This is set by the modal script HELLO WORLD'
        }
    )