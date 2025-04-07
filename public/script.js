'use strict'

const $ = document.querySelector.bind(document);

// Store the authentication token
let currentAuthToken = null;
let currentUsername = null;

// API base URL
const API_BASE_URL = '/api';

// DOM elements
const messageEl = document.getElementById('message');
const authSection = document.getElementById('auth-section');
const profileSection = document.getElementById('profile-section');
const usersSection = document.getElementById('users-section');
const loginForm = document.getElementById('login-form');
const registerForm = document.getElementById('register-form');

// Form elements
const emailInput = document.getElementById('email');
const passwordInput = document.getElementById('password');
const registerUsernameInput = document.getElementById('register-username');
const registerNameInput = document.getElementById('register-name');
const registerEmailInput = document.getElementById('register-email');
const registerPasswordInput = document.getElementById('register-password');
const registerPasswordConfirmInput = document.getElementById('register-password-confirm');
const profileEmailInput = document.getElementById('profile-email');
const newPasswordInput = document.getElementById('new-password');

// Button elements
const loginButton = document.getElementById('login-button');
const registerButton = document.getElementById('register-button');
const showRegisterButton = document.getElementById('show-register-button');
const showLoginButton = document.getElementById('show-login-button');
const updateProfileButton = document.getElementById('update-profile-button');
const deleteAccountButton = document.getElementById('delete-account-button');

// State
let authToken = localStorage.getItem('authToken');

// Helper function to display messages/errors
function showMessage(text, isError = false) {
    messageEl.textContent = text;
    messageEl.className = isError ? 'error' : 'success';
    messageEl.classList.remove('hidden');
    setTimeout(() => {
        messageEl.classList.add('hidden');
    }, 5000);
}

function setLoading(button, isLoading) {
    button.disabled = isLoading;
    button.classList.toggle('loading', isLoading);
}

async function handleApiError(response) {
    if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'An error occurred');
    }
    return response.json();
}

// Helper function to update UI based on authentication state
function updateUIForAuthState() {
    const authElements = document.querySelectorAll('.auth-required');
    const noAuthElements = document.querySelectorAll('.no-auth-required');
    
    authElements.forEach(el => {
        el.style.display = currentAuthToken ? 'block' : 'none';
    });
    
    noAuthElements.forEach(el => {
        el.style.display = currentAuthToken ? 'none' : 'block';
    });

    if (currentUsername) {
        const usernameSpan = document.getElementById('current-username');
        if (usernameSpan) {
            usernameSpan.textContent = currentUsername;
        }
    }
}

// Screen management
function showAuthScreen() {
    authSection.classList.remove('hidden');
    profileSection.classList.add('hidden');
    usersSection.classList.add('hidden');
    localStorage.removeItem('authToken');
    currentAuthToken = null;
    currentUsername = null;
    updateUIForAuthState();
}

function showProfileScreen() {
    authSection.classList.add('hidden');
    profileSection.classList.remove('hidden');
    usersSection.classList.remove('hidden');
    profileEmailInput.value = JSON.parse(atob(currentAuthToken.split('.')[1])).email;
    updateUIForAuthState();
}

// Show/hide forms
function showLoginForm() {
    loginForm.classList.remove('hidden');
    registerForm.classList.add('hidden');
}

function showRegisterForm() {
    loginForm.classList.add('hidden');
    registerForm.classList.remove('hidden');
}

// Form validation
function validateEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// Registration
async function register() {
    try {
        const username = registerUsernameInput.value.trim();
        const name = registerNameInput.value.trim();
        const email = registerEmailInput.value.trim();
        const password = registerPasswordInput.value;
        const passwordConfirm = registerPasswordConfirmInput.value;

        // Validate inputs
        if (!username || !name || !email || !password || !passwordConfirm) {
            showMessage('Please fill in all fields', true);
            return;
        }

        if (!validateEmail(email)) {
            showMessage('Please enter a valid email address', true);
            return;
        }

        if (password !== passwordConfirm) {
            showMessage('Passwords do not match', true);
            return;
        }

        const response = await fetch('/users', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username,
                password,
                email,
                name
            })
        });

        const data = await handleApiError(response);
        
        if (data.authenticationToken) {
            currentAuthToken = data.authenticationToken;
            currentUsername = data.username;
            localStorage.setItem('authToken', currentAuthToken);
            showProfileScreen();
            loadUsers();
            showMessage('Registration successful!');
            // Clear registration form
            registerUsernameInput.value = '';
            registerNameInput.value = '';
            registerEmailInput.value = '';
            registerPasswordInput.value = '';
            registerPasswordConfirmInput.value = '';
        }
    } catch (error) {
        showMessage(error.message, true);
    }
}

async function login() {
    try {
        const email = emailInput.value;
        const password = passwordInput.value;

        const response = await fetch('/users/auth', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username: email, password })
        });

        const data = await handleApiError(response);
        
        if (data.authenticationToken) {
            currentAuthToken = data.authenticationToken;
            currentUsername = data.username;
            localStorage.setItem('authToken', currentAuthToken);
            showProfileScreen();
            loadUsers();
        }
    } catch (error) {
        showMessage(error.message, true);
    }
}

async function updateProfile(newPassword) {
    try {
        setLoading(updateProfileButton, true);
        const response = await fetch(`${API_BASE_URL}/profile`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${currentAuthToken}`
            },
            body: JSON.stringify({ newPassword })
        });
        await handleApiError(response);
        showMessage('Profile updated successfully!');
        newPasswordInput.value = '';
    } catch (error) {
        showMessage(error.message, true);
    } finally {
        setLoading(updateProfileButton, false);
    }
}

async function deleteAccount() {
    if (!confirm('Are you sure you want to delete your account? This action cannot be undone.')) {
        return;
    }

    try {
        setLoading(deleteAccountButton, true);
        const response = await fetch(`${API_BASE_URL}/profile`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${currentAuthToken}`
            }
        });
        await handleApiError(response);
        showMessage('Account deleted successfully!');
        showAuthScreen();
    } catch (error) {
        showMessage(error.message, true);
    } finally {
        setLoading(deleteAccountButton, false);
    }
}

async function loadUsers() {
    try {
        const response = await fetch('/users', {
            headers: {
                'Authorization': `Bearer ${currentAuthToken}`
            }
        });
        const users = await handleApiError(response);
        const usersList = document.getElementById('users-list');
        usersList.innerHTML = users.map(user => `
            <div class="user-item">
                <p>Username: ${user.username}</p>
                <p>Name: ${user.name}</p>
                <p>Created: ${new Date(user.createdAt).toLocaleString()}</p>
            </div>
        `).join('');
    } catch (error) {
        showMessage(error.message, true);
    }
}

// Event listeners
showRegisterButton.addEventListener('click', showRegisterForm);
showLoginButton.addEventListener('click', showLoginForm);
registerButton.addEventListener('click', register);

loginButton.addEventListener('click', () => {
    const email = emailInput.value.trim();
    const password = passwordInput.value;
    if (!email || !password) {
        showMessage('Please enter both email and password', true);
        return;
    }
    login();
});

updateProfileButton.addEventListener('click', () => {
    const newPassword = newPasswordInput.value;
    if (newPassword) {
        updateProfile(newPassword);
    } else {
        showMessage('Please enter a new password', true);
    }
});

deleteAccountButton.addEventListener('click', deleteAccount);

// Initialize
if (currentAuthToken) {
    try {
        // Verify token is valid
        const payload = JSON.parse(atob(currentAuthToken.split('.')[1]));
        if (payload.exp && payload.exp < Date.now() / 1000) {
            throw new Error('Token expired');
        }
        showProfileScreen();
        loadUsers();
    } catch (error) {
        showAuthScreen();
    }
} else {
    showAuthScreen();
}

