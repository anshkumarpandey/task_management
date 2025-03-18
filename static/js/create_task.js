fetch("http://127.0.0.1/api/tasks/", {
    method: "GET",
    headers: {
        "Authorization": `Bearer ${localStorage.getItem('access_token')}`,
        "Content-Type": "application/json"
    }
})
.then(response => response.json())
.then(data => console.log(data))
.catch(error => console.error('Error:', error));
