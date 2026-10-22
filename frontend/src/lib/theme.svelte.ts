export type ThemeChoice = 'system' | 'light' | 'dark';

const KEY = 'cved-theme';

function read(): ThemeChoice {
	try {
		const value = localStorage.getItem(KEY);
		return value === 'light' || value === 'dark' ? value : 'system';
	} catch {
		return 'system';
	}
}

export const theme = $state<{ choice: ThemeChoice }>({ choice: read() });

/** Apply and remember the theme; "system" follows the operating system setting. */
export function setTheme(choice: ThemeChoice): void {
	theme.choice = choice;
	const root = document.documentElement;
	if (choice === 'system') delete root.dataset.theme;
	else root.dataset.theme = choice;
	try {
		if (choice === 'system') localStorage.removeItem(KEY);
		else localStorage.setItem(KEY, choice);
	} catch {
		// Storage unavailable: the choice lasts until the page is reloaded.
	}
}
