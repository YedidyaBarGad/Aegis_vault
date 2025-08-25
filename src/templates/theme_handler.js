// This script manages the dark mode theme for the web application. It handles:
// - Initializing the theme based on user preference or system settings.

// Function to apply the dark mode styles and update localStorage.
const setDarkMode = (isDark) => {
    // Check if the body element exists before trying to modify it.
    if (document.body) {
        if (isDark) {
            document.body.classList.add('dark-mode');
            // Save the user's choice to localStorage.
            localStorage.setItem('theme', 'dark');
        } else {
            document.body.classList.remove('dark-mode');
            // Save the user's choice to localStorage.
            localStorage.setItem('theme', 'light');
        }
    }
};

// This function is the main entry point for theme initialization.
// It should be called on every page load.
const initializeTheme = () => {
    // Get the stored theme preference from localStorage.
    const currentTheme = localStorage.getItem('theme');
    
    // Check the user's system preference for dark mode.
    const prefersDarkScheme = window.matchMedia("(prefers-color-scheme: dark)");

    if (currentTheme) {
        // If a theme is saved, use it.
        setDarkMode(currentTheme === 'dark');
    } else if (prefersDarkScheme.matches) {
        // If no theme is saved, use the system preference.
        setDarkMode(true);
    }
};

// Event listener for the theme toggle button.
const setupThemeToggle = () => {
    // Get all buttons with the data attribute for theme toggling.
    const toggleButtons = document.querySelectorAll('[data-bs-toggle="dark-mode"]');
    
    toggleButtons.forEach(button => {
        button.addEventListener('click', () => {
            // Check the current theme state from the body class.
            const isDarkMode = document.body.classList.contains('dark-mode');
            // Toggle the theme.
            setDarkMode(!isDarkMode);
        });
    });
};

// Run the initialization and setup when the DOM is fully loaded.
document.addEventListener('DOMContentLoaded', () => {
    initializeTheme();
    setupThemeToggle();
});
