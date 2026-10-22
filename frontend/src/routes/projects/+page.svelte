<script lang="ts">
	import { goto } from '$app/navigation';
	import { api, call } from '#lib/api/client.ts';
	import SeverityCounts from '#lib/components/SeverityCounts.svelte';
	import { dateTime, timeAgo } from '#lib/format.ts';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	let name = $state('');
	let error = $state('');
	let busy = $state(false);

	async function create(event: SubmitEvent) {
		event.preventDefault();
		busy = true;
		error = '';
		try {
			const project = await call(api.POST('/api/projects', { body: { name: name.trim() } }));
			await goto(`/projects/${project.id}?tab=dependencies`);
		} catch (e) {
			error = (e as Error).message;
		} finally {
			busy = false;
		}
	}
</script>

<svelte:head>
	<title>Projects · cve_detector</title>
</svelte:head>

<h1>Projects</h1>

<form class="card row new" onsubmit={create}>
	<label for="new-project" class="visually-hidden">New project name</label>
	<input id="new-project" placeholder="New project name" bind:value={name} required maxlength="200" />
	<button class="primary" type="submit" disabled={busy || !name.trim()}>Create project</button>
</form>
{#if error}<div class="alert error" role="alert">{error}</div>{/if}

{#if data.projects.length === 0}
	<p class="muted">No projects yet.</p>
{:else}
	<table class="data">
		<thead>
			<tr>
				<th>Project</th>
				<th>Open findings</th>
				<th class="num">Dependencies</th>
				<th class="num">Recipients</th>
				<th>Every</th>
				<th>Last scan</th>
			</tr>
		</thead>
		<tbody>
			{#each data.projects as project (project.id)}
				<tr>
					<td data-label="Project">
						<a href="/projects/{project.id}">{project.name}</a>
						{#if project.description}<div class="muted small">{project.description}</div>{/if}
					</td>
					<td data-label="Open findings"><SeverityCounts counts={project.open_findings} /></td>
					<td data-label="Dependencies" class="num">{project.dependency_count}</td>
					<td data-label="Recipients" class="num">
						{#if project.recipient_count === 0}
							<span class="warn" title="Nobody is notified">0</span>
						{:else}
							{project.recipient_count}
						{/if}
					</td>
					<td data-label="Every">{project.scan_interval_hours} h</td>
					<td data-label="Last scan" title={dateTime(project.last_scan_at)}>
						{timeAgo(project.last_scan_at)}
					</td>
				</tr>
			{/each}
		</tbody>
	</table>
{/if}

<style>
	.new {
		margin-bottom: 1rem;
	}
	.new input {
		flex: 1;
	}
	.warn {
		color: var(--danger);
		font-weight: 600;
	}
</style>
