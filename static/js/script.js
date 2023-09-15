
// Expand vertical menu
if (document.getElementById("expandVerticalMenu")) {
    document.getElementById("expandVerticalMenu").addEventListener("click", () => {
        nav = document.getElementById("verticalNav");
        nav_active = nav.classList.contains("nav-hidden")
    
        if (verticalMenu) {
            nav.classList.add("nav-hidden");
        } else {
            nav.classList.remove("nav-hidden");
        }
    });
}

// Redirect user to page
function redirect(path) {
    window.location.href = path;
}

// Get navbar status and update with server
function sendData() {
    var nav_active = document.getElementById('verticalNav').classList.contains('nav-hidden');
    $.ajax({
        url: '/navbar',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ 'value': nav_active }),
        success: function(response) {
            if (response.result)
            {
                document.getElementById('verticalNav').classList.remove('nav-hidden');
            } else {
                document.getElementById('verticalNav').classList.add('nav-hidden');
            }
        },
        error: function(error) {
            console.log(error);
        }
    });
}

// Show trash icon on checkbox select
checkboxes = document.querySelectorAll(".checkbox-table");
trash_icon = document.querySelector("#button-delete-selected");

checkboxes.forEach(element => {
    element.addEventListener("change", function() {
        for (checkbox of checkboxes) {
            if (checkbox.checked) {
                trash_icon.removeAttribute("hidden");
                break;
            }
            trash_icon.setAttribute("hidden", "");
        }
    });
});