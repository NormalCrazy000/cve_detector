<script lang="ts">
	import { refreshAll } from '$app/navigation';
	import { api, call, type Schemas } from '#lib/api/client.ts';
	import { setTheme, theme, type ThemeChoice } from '#lib/theme.svelte.ts';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	let testTo = $state('');
	let testResult = $state<Schemas['TestResult'] | null>(null);
	let testBusy = $state(false);

	let importFile = $state<File | null>(null);
	let importResult = $state<Schemas['ImportResult'] | null>(null);
	let importError = $state('');

	async function sendTest(event: SubmitEvent) {
		event.preventDefault();
		testBusy = true;
		testResult = null;
		try {
			testResult = await call(api.POST('/api/notifications/test', { body: { to: testTo.trim() } }));
		} catch (e) {
			testResult = { success: false, error: (e as Error).message };
		} finally {
			testBusy = false;
		}
	}

	async function importConfig() {
		if (!importFile) return;
		importError = '';
		importResult = null;
		try {
			importResult = await call(
				api.POST('/api/config/import', { body: { content: await importFile.text() } })
			);
			await refreshAll();
		} catch (e) {
			importError = (e as Error).message;
		}
	}
</script>

<svelte:head>
	<title>Settings · cve_detector</title>
</svelte:head>

<h1>Settings</h1>

<section class="card stack">
	<h2>Email notifications</h2>
	{#if data.channels.email_configured}
		<p>Email is configured. Send a test message to check that it arrives.</p>
	{:else}
		<div class="alert warn">
			Email is not configured. Set <code>CVED_SMTP_HOST</code>, <code>CVED_SMTP_PORT</code>,
			<code>CVED_SMTP_USERNAME</code>, <code>CVED_SMTP_PASSWORD</code> and
			<code>CVED_SMTP_FROM</code> in the <code>.env</code> file and restart. Credentials are never
			shown here.
		</div>
	{/if}
	<p class="muted small">
		Admin alerts for failing scans: {data.channels.admin_alerts
			? 'enabled'
			: 'disabled (set CVED_ADMIN_EMAIL to enable them)'}.
	</p>
	<form class="row" onsubmit={sendTest}>
		<label for="test-to" class="visually-hidden">Send a test email to</label>
		<input id="test-to" type="email" placeholder="you@example.com" bind:value={testTo} required />
		<button type="submit" disabled={testBusy || !data.channels.email_configured}>
			Send test email
		</button>
	</form>
	{#if testResult}
		<div class="alert {testResult.success ? 'ok' : 'error'}" role="status">
			{testResult.success ? 'Test email sent.' : `Sending failed: ${testResult.error}`}
		</div>
	{/if}
</section>

<section class="card stack">
	<h2>Configuration backup</h2>
	<p>
		Export projects, dependencies, recipients and suppressions as YAML (no credentials). Importing
		merges: projects with the same name are updated, the rest is added, nothing is deleted.
	</p>
	<div class="row">
		<a class="button" href="/api/config/export" download>Export YAML</a>
	</div>
	<div class="row">
		<label for="import-file" class="visually-hidden">Configuration file</label>
		<input
			id="import-file"
			type="file"
			accept=".yaml,.yml"
			onchange={(e) => (importFile = e.currentTarget.files?.[0] ?? null)}
		/>
		<button onclick={importConfig} disabled={!importFile}>Import YAML</button>
	</div>
	{#if importError}<div class="alert error" role="alert">{importError}</div>{/if}
	{#if importResult}
		<div class="alert ok" role="status">
			Imported: {importResult.projects_created} projects created, {importResult.projects_updated}
			updated, {importResult.dependencies_added} dependencies and {importResult.recipients_added}
			recipients added, {importResult.suppressions_added + importResult.suppressions_updated}
			suppressions saved.
		</div>
	{/if}
</section>

<section class="card stack">
	<h2>Appearance</h2>
	<fieldset class="row">
		<legend class="visually-hidden">Theme</legend>
		{#each ['system', 'light', 'dark'] as ThemeChoice[] as choice (choice)}
			<label class="inline">
				<input
					type="radio"
					name="theme"
					value={choice}
					checked={theme.choice === choice}
					onchange={() => setTheme(choice)}
				/>
				{choice === 'system' ? 'Follow the system' : choice}
			</label>
		{/each}
	</fieldset>
</section>

<style>
	section {
		margin-bottom: 1.5rem;
	}
	section h2 {
		margin-top: 0;
	}
	fieldset {
		border: none;
		padding: 0;
		margin: 0;
		gap: 1.5rem;
	}
	form input {
		flex: 1;
	}
</style>
