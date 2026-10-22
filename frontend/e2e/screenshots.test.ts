import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import process from 'node:process';
import { expect, test } from '@playwright/test';

// Screenshots of the demo dataset, e.g. for the README: SCREENSHOTS=dir npm run test:e2e
const outDir = process.env.SCREENSHOTS;
test.skip(!outDir, 'set SCREENSHOTS=<directory> to take screenshots');

const pages = [
	{ name: 'dashboard', path: '/' },
	{ name: 'project', path: '/projects/1' },
	{ name: 'findings', path: '/findings' },
	{ name: 'dependencies', path: '/projects/2?tab=dependencies' }
];

for (const colorScheme of ['light', 'dark'] as const) {
	test(`screenshots (${colorScheme})`, async ({ page }) => {
		mkdirSync(outDir!, { recursive: true });
		await page.emulateMedia({ colorScheme });
		await page.setViewportSize({ width: 1280, height: 860 });
		await page.goto('/login');
		await page.getByLabel('Username').fill('admin');
		await page.getByLabel('Password').fill('e2e-password');
		await page.getByRole('button', { name: 'Log in' }).click();
		await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
		for (const { name, path } of pages) {
			await page.goto(path);
			await page.waitForLoadState('networkidle');
			await page.screenshot({ path: join(outDir!, `${name}-${colorScheme}.png`), fullPage: true });
		}
		await page.setViewportSize({ width: 390, height: 844 });
		await page.goto('/');
		await page.screenshot({ path: join(outDir!, `mobile-${colorScheme}.png`), fullPage: true });
	});
}
