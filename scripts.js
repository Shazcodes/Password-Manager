const apiUrl = 'http://127.0.0.1:3000';

async function addPassword() {
    const site = document.getElementById('site').value;
    const password = document.getElementById('password').value;
    const expiry_days = document.getElementById('expiry_days').value;

    const response = await fetch(`${apiUrl}/add_password`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ site, password, expiry_days })
    });

    const data = await response.json();
    displayResult(data.message);
}

async function getPassword() {
    const site = document.getElementById('site').value;

    const response = await fetch(`${apiUrl}/get_password`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ site })
    });

    const data = await response.json();
    if (response.ok) {
        displayResult(`Password for ${site}: ${data.password}`);
    } else {
        displayResult(data.message);
    }
}

async function generatePassword() {
    const response = await fetch(`${apiUrl}/generate_password`);
    const data = await response.json();
    document.getElementById('password').value = data.password;
}

async function analyzePassword() {
    const password = document.getElementById('password').value;

    const response = await fetch(`${apiUrl}/analyze_password`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ password })
    });

    const data = await response.json();
    displayResult(`Password strength: ${data.strength}`);
}

async function autoFill() {
    const site = document.getElementById('site').value;

    const response = await fetch(`${apiUrl}/auto_fill`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ site })
    });

    const data = await response.json();
    if (response.ok) {
        document.getElementById('password').value = data.password;
    } else {
        displayResult(data.message);
    }
}

async function verify2FA() {
    const code = document.getElementById('2fa_code').value;

    const response = await fetch(`${apiUrl}/verify_2fa`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ code })
    });

    const data = await response.json();
    displayResult(data.message);
}

function displayResult(message) {
    const resultElement = document.getElementById('result');
    resultElement.textContent = message;
}