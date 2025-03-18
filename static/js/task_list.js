function loadTasks() {
    const accessToken = getAccessToken();  // Get the token from cookies
    if (!accessToken) {
        alert("You need to be logged in to view the tasks.");
        return;
    }

    // Make the fetch request with Authorization header
    fetch('/task-list/', {
        method: 'GET',
        headers: {
            'Authorization': `Bearer ${accessToken}`  // Attach the JWT token
        }
    })
    .then(response => {
        if (response.status === 401) {
            alert("Your session has expired. Please log in again.");
            // Optionally, redirect to the login page or refresh the page
            window.location.href = "/login";  // Redirect to login page
        }
        return response.json();
    })
    .then(data => {
        if (data.error) {
            alert(data.error);  // Handle any error responses
        } else {
            displayTasks(data);  // Pass the data to the function to render tasks
        }
    })
    .catch(error => {
        console.error("Error fetching task list:", error);
        alert("Failed to load tasks.");
    });
}
