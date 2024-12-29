document.addEventListener('DOMContentLoaded', () => {
    const loginScreen = document.getElementById('login-screen');
    const registerScreen = document.getElementById('register-screen');
    const registerBtn = document.getElementById('register-btn');
    const registerForm = document.getElementById('register-form');

    // Show the registration screen when "Register now!" is clicked
    registerBtn.addEventListener('click', () => {
        loginScreen.classList.add('hidden');
        registerScreen.classList.remove('hidden');
    });

    // Automatically redirect to login screen after successful registration
    registerForm.addEventListener('submit', (e) => {
        e.preventDefault(); // Prevent default form submission for demo purposes

        // Simulate successful registration
        alert('Registration successful! Redirecting to login...');
        registerScreen.classList.add('hidden');
        loginScreen.classList.remove('hidden');
    });
});
