// Runs before the app: apply the theme chosen in the UI ("light" / "dark"), if any.
try {
	const theme = localStorage.getItem('cved-theme');
	if (theme === 'light' || theme === 'dark') document.documentElement.dataset.theme = theme;
} catch {
	// Storage unavailable (private mode): follow the system preference.
}
