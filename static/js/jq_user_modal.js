var exampleModal = document.getElementById('userInfo')
    exampleModal.addEventListener('show.bs.modal', function (event) {
        // Button that triggered the modal
        var button = event.relatedTarget
        // Extract info from data-bs-* attributes
        var username = button.getAttribute('data-bs-username')
        var fullname = button.getAttribute('data-bs-fullname')
        var mail = button.getAttribute('data-bs-mail')
        var profile = button.getAttribute('data-bs-profile')
        var bookurl = button.getAttribute('data-bs-bookurl')
        var baseurl = button.getAttribute('data-bs-baseurl')
        // Update the modal's content.
        var modalTitle = exampleModal.querySelector('.modal-title')
        // modalTitle.textContent = 'User Information for ' + username
        const namediv = document.getElementById("Name");
        const maildiv = document.getElementById("Mail");
        const profilediv = document.getElementById("Profile");
        const loggedin = document.getElementById("Username").innerText;
        const urldelete = document.getElementById("Delete");
        namediv.innerHTML = '<h5 class="name">' + fullname + '</h5>';
        maildiv.innerHTML = '<p class="mail"><a href="mailto:' + mail + '">' + mail + '</a></p>';
        profilediv.innerHTML = '<img src="https://mittkonto.hv.se/public/bilder/' + profile + '" height="130" width="100">';
        if (loggedin != 'no') {
            //urldelete.innerHTML = '<a class="btn btn-danger" href="/delete/' + bookurl + '" role="button">Delete booking</a>&nbsp;'
            urldelete.outerHTML = '<a class="btn btn-danger mr-auto" href="' + baseurl + 'delete/' + bookurl + '" role="button">Delete booking</a>'
            }        
        }
    )