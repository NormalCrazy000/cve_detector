<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import Pager from '#lib/components/Pager.svelte';
	import { dateTime } from '#lib/format.ts';
	import type { PageProps } from './$types';
	import { PAGE_SIZE } from './+page.ts';

	let { data }: PageProps = $props();

	let projectNames = $derived(new Map(data.projects.map((p) => [p.id, p.name])));

	function go(key: 'scans' | 'log', offset: number) {
		const url = new URL(page.url.href);
		url.searchParams.set(key, String(offset));
		goto(url.pathname + url.search, { reset: false });
	}
</script>

<svelte:head>
	<title>Activity · cve_detector</title>
</svelte:head>

<h1>Activity</h1>

<h2>Scans</h2>
{#if data.scans.items.length === 0}
	<p class="muted">No scans yet.</p>
{:else}
	<table class="data">
		<thead>
			<tr>
				<th>Started</th>
				<th>Status</th>
				<th class="num">Projects</th>
				<th class="num">Libraries</th>
				<th class="num">New findings</th>
				<th>Error</th>
			</tr>
		</thead>
		<tbody>
			{#each data.scans.items as scan (scan.id)}
				<tr>
					<td data-label="Started">{dateTime(scan.started_at)}</td>
					<td data-label="Status" class={{ error: scan.status === 'failed' }}>{scan.status}</td>
					<td data-label="Projects" class="num">{scan.projects_scanned}</td>
					<td data-label="Libraries" class="num">{scan.libraries_queried}</td>
					<td data-label="New findings" class="num">{scan.findings_new}</td>
					<td data-label="Error" class="small">{scan.error ?? ''}</td>
				</tr>
			{/each}
		</tbody>
	</table>
	<Pager total={data.scans.total} limit={PAGE_SIZE} offset={data.scansOffset} onchange={(o) => go('scans', o)} />
{/if}

<h2>Notifications</h2>
{#if data.log.items.length === 0}
	<p class="muted">Nothing sent yet.</p>
{:else}
	<table class="data">
		<thead>
			<tr>
				<th>Sent</th>
				<th>Kind</th>
				<th>Project</th>
				<th>To</th>
				<th>Result</th>
			</tr>
		</thead>
		<tbody>
			{#each data.log.items as entry (entry.id)}
				<tr>
					<td data-label="Sent">{dateTime(entry.sent_at)}</td>
					<td data-label="Kind">{entry.kind.replace('_', ' ')}</td>
					<td data-label="Project">
						{#if entry.project_id}
							<a href="/projects/{entry.project_id}">
								{projectNames.get(entry.project_id) ?? entry.project_id}
							</a>
						{:else}
							—
						{/if}
					</td>
					<td data-label="To" class="small">{entry.targets.join(', ')}</td>
					<td data-label="Result" class={{ error: !entry.success }}>
						{entry.success ? 'sent' : 'failed'}
						{#if entry.error}<div class="small">{entry.error}</div>{/if}
					</td>
				</tr>
			{/each}
		</tbody>
	</table>
	<Pager total={data.log.total} limit={PAGE_SIZE} offset={data.logOffset} onchange={(o) => go('log', o)} />
{/if}

<style>
	.error {
		color: var(--danger);
		font-weight: 600;
	}
</style>
