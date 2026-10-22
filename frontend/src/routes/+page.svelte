<script lang="ts">
	import type { Severity } from '#lib/api/client.ts';
	import SeverityCounts from '#lib/components/SeverityCounts.svelte';
	import { dateTime, SEVERITIES, timeAgo } from '#lib/format.ts';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	let totals = $derived(
		Object.fromEntries(
			SEVERITIES.map((severity: Severity) => [
				severity,
				data.projects.reduce((sum, p) => sum + (p.open_findings[severity] ?? 0), 0)
			])
		) as Record<Severity, number>
	);
	let failing = $derived(data.projects.filter((p) => p.last_scan_error));
	let failedSends = $derived(data.notifications.items.filter((n) => !n.success));
	let projectNames = $derived(new Map(data.projects.map((p) => [p.id, p.name])));
</script>

<svelte:head>
	<title>Dashboard · cve_detector</title>
</svelte:head>

<h1>Dashboard</h1>

{#if !data.channels.email_configured}
	<div class="alert warn">
		Email is not configured: findings are recorded but nobody is notified. Set the
		<code>CVED_SMTP_*</code> variables, then send a test email from <a href="/settings">Settings</a>.
	</div>
{/if}
{#each failing as project (project.id)}
	<div class="alert error">
		Last scan of <a href="/projects/{project.id}">{project.name}</a> failed: {project.last_scan_error}
	</div>
{/each}

<section class="tiles" aria-label="Open findings by severity">
	{#each SEVERITIES.filter((s) => s !== 'none') as severity (severity)}
		<a class="tile card sev-{severity}" href="/findings?min_severity={severity}">
			<span class="value">{totals[severity]}</span>
			<span class="label">{severity}</span>
		</a>
	{/each}
</section>
<p class="muted small">
	Open, not suppressed findings across all projects, regardless of each project's notification
	threshold.
</p>

<h2>Projects</h2>
{#if data.projects.length === 0}
	<p class="card">No projects yet. <a href="/projects">Create the first one</a>.</p>
{:else}
	<table class="data">
		<thead>
			<tr>
				<th>Project</th>
				<th>Open findings</th>
				<th class="num">Dependencies</th>
				<th>Last scan</th>
				<th>Next scan</th>
			</tr>
		</thead>
		<tbody>
			{#each data.projects as project (project.id)}
				<tr>
					<td data-label="Project"><a href="/projects/{project.id}">{project.name}</a></td>
					<td data-label="Open findings"><SeverityCounts counts={project.open_findings} /></td>
					<td data-label="Dependencies" class="num">{project.dependency_count}</td>
					<td data-label="Last scan" title={dateTime(project.last_scan_at)}>
						{#if project.last_scan_error}<span class="error">failed</span>{/if}
						{timeAgo(project.last_scan_at)}
					</td>
					<td data-label="Next scan" title={dateTime(project.next_scan_at)}>
						{project.next_scan_at ? timeAgo(project.next_scan_at) : 'as soon as possible'}
					</td>
				</tr>
			{/each}
		</tbody>
	</table>
{/if}

<div class="columns">
	<section>
		<h2>Recent scans</h2>
		{#if data.scans.items.length === 0}
			<p class="muted">No scans yet.</p>
		{:else}
			<ul class="card list">
				{#each data.scans.items as scan (scan.id)}
					<li>
						<span class={{ error: scan.status === 'failed' }}>{scan.status}</span>
						<span title={dateTime(scan.started_at)}>{timeAgo(scan.started_at)}</span>
						<span class="muted small">
							{scan.projects_scanned} projects, {scan.libraries_queried} libraries,
							{scan.findings_new} new findings
						</span>
						{#if scan.error}<div class="small error">{scan.error}</div>{/if}
					</li>
				{/each}
			</ul>
		{/if}
	</section>
	<section>
		<h2>Recent notifications</h2>
		{#if failedSends.length}
			<p class="error small">{failedSends.length} of the last deliveries failed.</p>
		{/if}
		{#if data.notifications.items.length === 0}
			<p class="muted">Nothing sent yet.</p>
		{:else}
			<ul class="card list">
				{#each data.notifications.items as entry (entry.id)}
					<li>
						<span class={{ error: !entry.success }}>{entry.success ? 'sent' : 'failed'}</span>
						{entry.kind.replace('_', ' ')}
						{#if entry.project_id}
							· {projectNames.get(entry.project_id) ?? `project ${entry.project_id}`}
						{/if}
						<span class="muted small" title={dateTime(entry.sent_at)}>{timeAgo(entry.sent_at)}</span>
						{#if entry.error}<div class="small error">{entry.error}</div>{/if}
					</li>
				{/each}
			</ul>
		{/if}
		<p class="small"><a href="/activity">All activity →</a></p>
	</section>
</div>

<style>
	.tiles {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(8rem, 1fr));
		gap: 0.75rem;
	}
	.tile {
		display: flex;
		flex-direction: column;
		color: inherit;
		border-top: 3px solid currentColor;
	}
	.tile:hover {
		text-decoration: none;
		border-color: currentColor;
	}
	.tile .value {
		font-size: 1.8rem;
		font-weight: 700;
	}
	.tile .label {
		text-transform: capitalize;
		color: var(--muted);
	}
	.sev-critical {
		color: var(--sev-critical);
	}
	.sev-high {
		color: var(--sev-high);
	}
	.sev-medium {
		color: var(--sev-medium);
	}
	.sev-low {
		color: var(--sev-low);
	}
	.sev-unknown {
		color: var(--sev-none);
	}
	.columns {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(20rem, 1fr));
		gap: 1.5rem;
	}
	.list {
		list-style: none;
		margin: 0;
		padding: 0.25rem 1rem;
	}
	.list li {
		padding: 0.5rem 0;
		border-bottom: 1px solid var(--border);
	}
	.list li:last-child {
		border-bottom: none;
	}
	.error {
		color: var(--danger);
		font-weight: 600;
	}
</style>
