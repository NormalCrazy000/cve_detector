<script lang="ts">
	import { goto, refreshAll } from '$app/navigation';
	import { page } from '$app/state';
	import { api, call } from '#lib/api/client.ts';
	import FindingsTable from '#lib/components/FindingsTable.svelte';
	import DependenciesPanel from '#lib/components/project/DependenciesPanel.svelte';
	import ManifestImport from '#lib/components/project/ManifestImport.svelte';
	import ProjectSettings from '#lib/components/project/ProjectSettings.svelte';
	import RecipientsPanel from '#lib/components/project/RecipientsPanel.svelte';
	import SeverityCounts from '#lib/components/SeverityCounts.svelte';
	import { dateTime, timeAgo } from '#lib/format.ts';
	import type { PageProps } from './$types';
	import type { Tab } from './+page.ts';

	let { data }: PageProps = $props();

	let project = $derived(data.project);
	let message = $state('');
	let error = $state('');

	let tabs = $derived<{ id: Tab; label: string }[]>([
		{ id: 'findings', label: `Findings (${data.findings.total})` },
		{ id: 'dependencies', label: `Dependencies (${data.dependencies.length})` },
		{ id: 'import', label: 'Import manifest' },
		{ id: 'recipients', label: `Recipients (${data.recipients.length})` },
		{ id: 'settings', label: 'Settings' }
	]);

	function tabHref(tab: Tab): string {
		const url = new URL(page.url.href);
		url.searchParams.set('tab', tab);
		return url.pathname + url.search;
	}

	async function scanNow() {
		error = '';
		try {
			await call(
				api.POST('/api/projects/{project_id}/scan', {
					params: { path: { project_id: project.id } }
				})
			);
			message = 'Scan queued: it starts right away, or after the scan in progress.';
			await refreshAll();
		} catch (e) {
			error = (e as Error).message;
		}
	}

	async function remove() {
		const answer = prompt(
			`This deletes ${project.name} with its dependencies, findings and history.\nType the project name to confirm:`
		);
		if (answer !== project.name) return;
		try {
			await call(
				api.DELETE('/api/projects/{project_id}', { params: { path: { project_id: project.id } } })
			);
			await goto('/projects');
		} catch (e) {
			error = (e as Error).message;
		}
	}

	function toggleResolved(event: Event & { currentTarget: HTMLInputElement }) {
		const url = new URL(page.url.href);
		if (event.currentTarget.checked) url.searchParams.set('resolved', '1');
		else url.searchParams.delete('resolved');
		goto(url.pathname + url.search, { replace: true, reset: false });
	}
</script>

<svelte:head>
	<title>{project.name} · cve_detector</title>
</svelte:head>

<div class="row spread head">
	<div>
		<p class="muted small crumbs"><a href="/projects">Projects</a> /</p>
		<h1>{project.name}</h1>
		{#if project.description}<p class="muted">{project.description}</p>{/if}
	</div>
	<div class="row">
		<button class="primary" onclick={scanNow}>Scan now</button>
		<button class="danger" onclick={remove}>Delete project</button>
	</div>
</div>

{#if message}<div class="alert ok" role="status">{message}</div>{/if}
{#if error}<div class="alert error" role="alert">{error}</div>{/if}
{#if project.last_scan_error}
	<div class="alert error">Last scan failed: {project.last_scan_error}</div>
{/if}

<dl class="card facts">
	<div><dt>Open findings</dt><dd><SeverityCounts counts={project.open_findings} /></dd></div>
	<div>
		<dt>Last scan</dt>
		<dd title={dateTime(project.last_scan_at)}>{timeAgo(project.last_scan_at)}</dd>
	</div>
	<div>
		<dt>Next scan</dt>
		<dd title={dateTime(project.next_scan_at)}>
			{project.next_scan_at ? timeAgo(project.next_scan_at) : 'as soon as possible'}
		</dd>
	</div>
	<div>
		<dt>Last notification</dt>
		<dd title={dateTime(project.last_notified_at)}>{timeAgo(project.last_notified_at)}</dd>
	</div>
	<div><dt>Notifies from</dt><dd>{project.min_severity}</dd></div>
</dl>

<nav class="tabs" aria-label="Project sections">
	{#each tabs as tab (tab.id)}
		<a href={tabHref(tab.id)} aria-current={data.tab === tab.id ? 'page' : undefined}>{tab.label}</a>
	{/each}
</nav>

{#if data.tab === 'findings'}
	<label class="inline toggle">
		<input type="checkbox" checked={data.showResolved} onchange={toggleResolved} />
		Show resolved and withdrawn findings
	</label>
	<FindingsTable findings={data.findings.items} showProject={false} onchanged={refreshAll} />
{:else if data.tab === 'dependencies'}
	<DependenciesPanel projectId={project.id} dependencies={data.dependencies} onchanged={refreshAll} />
{:else if data.tab === 'import'}
	<ManifestImport projectId={project.id} onapplied={refreshAll} />
{:else if data.tab === 'recipients'}
	<RecipientsPanel projectId={project.id} recipients={data.recipients} onchanged={refreshAll} />
{:else}
	<ProjectSettings {project} onsaved={refreshAll} />
{/if}

<style>
	.head {
		align-items: flex-start;
	}
	.crumbs {
		margin: 0;
	}
	h1 {
		margin-bottom: 0.25rem;
	}
	.facts {
		display: flex;
		flex-wrap: wrap;
		gap: 0.75rem 2rem;
		margin: 1rem 0;
	}
	.facts dt {
		color: var(--muted);
		font-size: 0.8rem;
	}
	.facts dd {
		margin: 0;
		font-weight: 600;
	}
	.tabs {
		display: flex;
		gap: 0.25rem;
		flex-wrap: wrap;
		border-bottom: 1px solid var(--border);
		margin-bottom: 1rem;
	}
	.tabs a {
		padding: 0.5rem 0.8rem;
		color: var(--text);
		border-bottom: 2px solid transparent;
		margin-bottom: -1px;
	}
	.tabs a:hover {
		text-decoration: none;
		border-bottom-color: var(--border);
	}
	.tabs a[aria-current='page'] {
		font-weight: 600;
		border-bottom-color: var(--accent);
	}
	.toggle {
		margin-bottom: 0.75rem;
	}
</style>
