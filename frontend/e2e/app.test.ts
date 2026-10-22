import { expect, test, type Page } from '@playwright/test';

// Any console error (e.g. a Content-Security-Policy violation) fails the test.
let consoleErrors: string[] = [];
test.beforeEach(({ page }) => {
	consoleErrors = [];
	page.on('console', (message) => {
		// Failed logins and logged-out session checks are expected 401 responses.
		if (message.type() === 'error' && !message.text().includes('401')) {
			consoleErrors.push(message.text());
		}
	});
	page.on('pageerror', (error) => consoleErrors.push(error.message));
});
test.afterEach(() => {
	expect(consoleErrors).toEqual([]);
});

async function login(page: Page) {
	await page.goto('/');
	await expect(page).toHaveURL(/\/login\?next=%2F$/);
	await page.getByLabel('Username').fill('admin');
	await page.getByLabel('Password').fill('e2e-password');
	await page.getByRole('button', { name: 'Log in' }).click();
	await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
}

test('login is required and wrong passwords are rejected', async ({ page }) => {
	await page.goto('/findings');
	await expect(page).toHaveURL(/\/login\?next=%2Ffindings$/);
	await page.getByLabel('Username').fill('admin');
	await page.getByLabel('Password').fill('wrong');
	await page.getByRole('button', { name: 'Log in' }).click();
	await expect(page.getByRole('alert')).toHaveText('Wrong username or password.');

	await page.getByLabel('Password').fill('e2e-password');
	await page.getByRole('button', { name: 'Log in' }).click();
	await expect(page.getByRole('heading', { name: 'Findings' })).toBeVisible();
});

test('dashboard summarizes the demo projects', async ({ page }) => {
	await login(page);
	const tiles = page.getByRole('region', { name: 'Open findings by severity' });
	await expect(tiles.getByRole('link', { name: /critical/ })).toContainText('1');
	await expect(tiles.getByRole('link', { name: /high/ })).toContainText('2');
	await expect(page.getByRole('link', { name: 'demo-shop' }).first()).toBeVisible();
	await expect(page.getByText('Email is not configured')).toBeVisible();
});

test('findings can be searched and suppressed', async ({ page }) => {
	await login(page);
	await page.getByRole('link', { name: 'Findings', exact: true }).click();
	await page.getByLabel('Search').fill('CVE-2099-2026-0002');
	await page.getByRole('button', { name: 'Apply filters' }).click();
	await expect(page.getByText('1 finding', { exact: true })).toBeVisible();

	await page.getByRole('button', { name: 'DEMO-2026-0002' }).click();
	await expect(page.getByText('Fixed in')).toBeVisible();
	await page.getByRole('button', { name: 'Suppress…' }).click();
	const dialog = page.getByRole('dialog');
	await dialog.getByLabel('Reason').fill('Redirects are disabled in our client');
	await dialog.getByRole('button', { name: 'Suppress' }).click();
	await expect(dialog).toBeHidden();
	await expect(page.getByRole('button', { name: 'Remove suppression' })).toBeVisible();

	await page.getByRole('link', { name: 'Suppressions' }).click();
	await expect(page.getByRole('cell', { name: 'Redirects are disabled in our client' })).toBeVisible();
});

test('dependencies can be added, upgraded and imported', async ({ page }) => {
	await login(page);
	await page.getByRole('link', { name: 'Projects', exact: true }).click();
	await page.getByLabel('New project name').fill('e2e-project');
	await page.getByRole('button', { name: 'Create project' }).click();
	await expect(page.getByRole('heading', { name: 'e2e-project' })).toBeVisible();

	await page.getByLabel('Package').fill('demo-http-client');
	await page.getByLabel('Version or range').fill('2.3.1');
	await page.getByRole('button', { name: 'Add dependency' }).click();
	await page.getByRole('button', { name: /Change version of demo-http-client/ }).click();
	await page.getByLabel('New version').fill('2.4.0');
	await page.getByRole('button', { name: 'Save' }).click();
	await expect(page.getByRole('button', { name: /Change version of demo-http-client/ })).toHaveText(
		'2.4.0'
	);

	await page.getByRole('link', { name: 'Import manifest' }).click();
	await page.getByLabel('Manifest file').setInputFiles({
		name: 'package.json',
		mimeType: 'application/json',
		buffer: Buffer.from(
			JSON.stringify({ dependencies: { 'demo-date-utils': '1.9.0' }, devDependencies: {} })
		)
	});
	await page.getByRole('button', { name: 'Preview changes' }).click();
	await expect(page.getByText('to add')).toContainText('1');
	await page.getByRole('button', { name: 'Apply changes' }).click();
	await expect(page.getByRole('status')).toContainText('1 added');
	await expect(page.getByRole('link', { name: 'Dependencies (2)' })).toBeVisible();
});

test('logging out ends the session', async ({ page }) => {
	await login(page);
	await page.getByRole('button', { name: 'Log out' }).click();
	await expect(page).toHaveURL(/\/login$/);
	await page.goto('/projects');
	await expect(page).toHaveURL(/\/login\?next=%2Fprojects$/);
});
