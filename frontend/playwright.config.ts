import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import process from 'node:process';
import { defineConfig } from '@playwright/test';

// The real backend serves the built UI with a fresh synthetic demo database.
const port = 8137;
const dataDir = process.env.CVED_E2E_DATA_DIR ?? mkdtempSync(join(tmpdir(), 'cved-e2e-'));
process.env.CVED_E2E_DATA_DIR = dataDir;

export default defineConfig({
	testDir: 'e2e',
	fullyParallel: false,
	workers: 1,
	reporter: process.env.CI ? 'github' : 'list',
	use: {
		baseURL: `http://127.0.0.1:${port}`,
		// Locally use the installed Chrome; CI installs Playwright's Chromium.
		channel: process.env.CI ? undefined : 'chrome',
		trace: 'retain-on-failure'
	},
	webServer: {
		command:
			'npm run build && cd ../backend && uv run python -m cve_detector.demo && ' +
			`uv run uvicorn cve_detector.main:app --host 127.0.0.1 --port ${port}`,
		url: `http://127.0.0.1:${port}/api/health`,
		timeout: 120_000,
		reuseExistingServer: false,
		env: {
			CVED_DATA_DIR: dataDir,
			CVED_WEB_DIR: join(process.cwd(), 'build'),
			CVED_ADMIN_USERNAME: 'admin',
			CVED_ADMIN_PASSWORD: 'e2e-password',
			CVED_SCHEDULER_ENABLED: 'false'
		}
	}
});
