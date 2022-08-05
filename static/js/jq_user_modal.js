var exampleModal = document.getElementById('userInfo')
    exampleModal.addEventListener('show.bs.modal', function (event) {
        // Button that triggered the modal
        var button = event.relatedTarget
        // Extract info from data-bs-* attributes
        var username = button.getAttribute('data-bs-username')
        var fullname = button.getAttribute('data-bs-fullname')
        var mail = button.getAttribute('data-bs-mail')
        var profile = button.getAttribute('data-bs-profile')
        // Update the modal's content.
        var modalTitle = exampleModal.querySelector('.modal-title')
        modalTitle.textContent = 'User Information for ' + username
        const namediv = document.getElementById("Name");
        const maildiv = document.getElementById("Mail");
        const profilediv = document.getElementById("Profile");
        namediv.innerHTML = fullname;
        maildiv.innerHTML = '<a href="mailto:' + mail + '">' + mail + '</a>';
        profilediv.innerHTML = '<img src="https://mittkonto.hv.se/public/bilder/' + profile + '" height="130" width="100">';
        }
    )