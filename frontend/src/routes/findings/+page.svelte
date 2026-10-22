<script lang="ts">
	import { goto, refreshAll } from '$app/navigation';
	import FindingsTable from '#lib/components/FindingsTable.svelte';
	import Pager from '#lib/components/Pager.svelte';
	import { plural, SEVERITIES, STATUS_LABELS } from '#lib/format.ts';
	import type { FindingStatus } from '#lib/api/client.ts';
	import type { PageProps } from './$types';
	import { PAGE_SIZE } from './+page.ts';

	let { data }: PageProps = $props();

	const STATUSES = Object.keys(STATUS_LABELS) as FindingStatus[];

	// Editable copy of the filters in the URL.
	let form = $derived.by(() => {
		const copy = $state({
			project_id: data.filters.project_id?.toString() ?? '',
			min_severity: data.filters.min_severity ?? '',
			status: data.filters.status.length ? data.filters.status : ['affected', 'potentially_affected'],
			suppressed: data.filters.suppressed === undefined ? '' : String(data.filters.suppressed),
			q: data.filters.q ?? ''
		});
		return copy;
	});

	function search(offset = 0) {
		const params = new URLSearchParams();
		if (form.project_id) params.set('project_id', form.project_id);
		if (form.min_severity) params.set('min_severity', form.min_severity);
		for (const status of form.status) params.append('status', status);
		if (form.suppressed) params.set('suppressed', form.suppressed);
		if (form.q.trim()) params.set('q', form.q.trim());
		if (offset) params.set('offset', String(offset));
		goto(`/findings?${params}`, { reset: false });
	}
</script>

<svelte:head>
	<title>Findings · cve_detector</title>
</svelte:head>

<h1>Findings</h1>

<form class="card filters" onsubmit={(e) => (e.preventDefault(), search())}>
	<div class="grid">
		<div>
			<label for="f-q">Search</label>
			<input id="f-q" type="search" placeholder="Advisory, CVE, package…" bind:value={form.q} />
		</div>
		<div>
			<label for="f-project">Project</label>
			<select id="f-project" bind:value={form.project_id}>
				<option value="">All projects</option>
				{#each data.projects as project (project.id)}
					<option value={String(project.id)}>{project.name}</option>
				{/each}
			</select>
		</div>
		<div>
			<label for="f-severity">Minimum severity</label>
			<select id="f-severity" bind:value={form.min_severity}>
				<option value="">Any</option>
				{#each SEVERITIES.filter((s) => s !== 'unknown') as severity (severity)}
					<option value={severity}>{severity}</option>
				{/each}
			</select>
		</div>
		<div>
			<label for="f-suppressed">Suppressed</label>
			<select id="f-suppressed" bind:value={form.suppressed}>
				<option value="">Include</option>
				<option value="false">Hide</option>
				<option value="true">Only suppressed</option>
			</select>
		</div>
	</div>
	<fieldset>
		<legend class="visually-hidden">Status</legend>
		{#each STATUSES as status (status)}
			<label class="inline">
				<input type="checkbox" value={status} bind:group={form.status} />
				{STATUS_LABELS[status]}
			</label>
		{/each}
	</fieldset>
	<button class="primary" type="submit">Apply filters</button>
</form>

<p class="muted">{plural(data.findings.total, 'finding')}</p>
<FindingsTable findings={data.findings.items} onchanged={refreshAll} />
<Pager
	total={data.findings.total}
	limit={PAGE_SIZE}
	offset={data.filters.offset}
	onchange={(offset) => search(offset)}
/>

<style>
	.filters {
		margin-bottom: 1rem;
	}
	.grid {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(12rem, 1fr));
		gap: 0.75rem;
	}
	fieldset {
		border: none;
		padding: 0;
		margin: 0.75rem 0;
	}
	fieldset label {
		margin-right: 1rem;
	}
</style>
