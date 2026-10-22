<script lang="ts">
	import { refreshAll } from '$app/navigation';
	import { api, call, type Suppression } from '#lib/api/client.ts';
	import { dateTime, fromDateInput, toDateInput } from '#lib/format.ts';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	let projectNames = $derived(new Map(data.projects.map((p) => [p.id, p.name])));
	let reference = $state('');
	let projectId = $state('');
	let reason = $state('');
	let expires = $state('');
	let error = $state('');
	let editing = $state<number | null>(null);
	let editReason = $state('');
	let editExpires = $state('');

	async function run(action: () => Promise<unknown>): Promise<boolean> {
		error = '';
		try {
			await action();
			await refreshAll();
			return true;
		} catch (e) {
			error = (e as Error).message;
			return false;
		}
	}

	async function create(event: SubmitEvent) {
		event.preventDefault();
		const ok = await run(() =>
			call(
				api.POST('/api/suppressions', {
					body: {
						advisory_ref: reference.trim(),
						project_id: projectId ? Number(projectId) : null,
						reason,
						expires_at: fromDateInput(expires)
					}
				})
			)
		);
		if (ok) {
			reference = '';
			reason = '';
			expires = '';
		}
	}

	function edit(suppression: Suppression) {
		editing = suppression.id;
		editReason = suppression.reason;
		editExpires = toDateInput(suppression.expires_at);
	}

	async function save(suppression: Suppression) {
		const ok = await run(() =>
			call(
				api.PATCH('/api/suppressions/{suppression_id}', {
					params: { path: { suppression_id: suppression.id } },
					body: { reason: editReason, expires_at: fromDateInput(editExpires) }
				})
			)
		);
		if (ok) editing = null;
	}

	function remove(suppression: Suppression) {
		if (!confirm(`Remove the suppression of ${suppression.advisory_ref}? Its findings will be notified again.`))
			return;
		run(() =>
			call(
				api.DELETE('/api/suppressions/{suppression_id}', {
					params: { path: { suppression_id: suppression.id } }
				})
			)
		);
	}
</script>

<svelte:head>
	<title>Suppressions · cve_detector</title>
</svelte:head>

<h1>Suppressions</h1>
<p class="muted">
	A suppression silences an advisory (by its id or an alias such as a CVE id) for one project or
	for all of them. When it expires or is removed, its findings are notified again.
</p>

{#if error}<div class="alert error" role="alert">{error}</div>{/if}

<form class="card new" onsubmit={create}>
	<h2>New suppression</h2>
	<div class="grid">
		<div>
			<label for="s-ref">Advisory or CVE id</label>
			<input id="s-ref" bind:value={reference} placeholder="CVE-2021-44228" required maxlength="100" />
		</div>
		<div>
			<label for="s-project">Applies to</label>
			<select id="s-project" bind:value={projectId}>
				<option value="">All projects</option>
				{#each data.projects as project (project.id)}
					<option value={String(project.id)}>{project.name}</option>
				{/each}
			</select>
		</div>
		<div>
			<label for="s-expires">Expires <span class="hint">(optional)</span></label>
			<input id="s-expires" type="date" bind:value={expires} />
		</div>
	</div>
	<div class="field">
		<label for="s-reason">Reason</label>
		<textarea id="s-reason" bind:value={reason} required maxlength="5000"></textarea>
	</div>
	<button class="primary" type="submit" disabled={!reference.trim() || !reason.trim()}>
		Add suppression
	</button>
</form>

{#if data.suppressions.length === 0}
	<p class="muted">No suppressions.</p>
{:else}
	<table class="data">
		<thead>
			<tr>
				<th>Advisory</th>
				<th>Applies to</th>
				<th>Reason</th>
				<th>Expires</th>
				<th><span class="visually-hidden">Actions</span></th>
			</tr>
		</thead>
		<tbody>
			{#each data.suppressions as suppression (suppression.id)}
				<tr class={{ inactive: !suppression.active }}>
					<td data-label="Advisory"><code>{suppression.advisory_ref}</code></td>
					<td data-label="Applies to">
						{#if suppression.project_id}
							<a href="/projects/{suppression.project_id}">
								{projectNames.get(suppression.project_id) ?? suppression.project_id}
							</a>
						{:else}
							all projects
						{/if}
					</td>
					{#if editing === suppression.id}
						<td data-label="Reason">
							<label for="e-reason-{suppression.id}" class="visually-hidden">Reason</label>
							<textarea id="e-reason-{suppression.id}" bind:value={editReason} required></textarea>
						</td>
						<td data-label="Expires">
							<label for="e-exp-{suppression.id}" class="visually-hidden">Expires</label>
							<input id="e-exp-{suppression.id}" type="date" bind:value={editExpires} />
						</td>
						<td class="row">
							<button class="primary" onclick={() => save(suppression)} disabled={!editReason.trim()}>
								Save
							</button>
							<button onclick={() => (editing = null)}>Cancel</button>
						</td>
					{:else}
						<td data-label="Reason">{suppression.reason}</td>
						<td data-label="Expires">
							{suppression.expires_at ? dateTime(suppression.expires_at) : 'never'}
							{#if !suppression.active}<span class="muted">(expired)</span>{/if}
						</td>
						<td class="row">
							<button onclick={() => edit(suppression)}>Edit</button>
							<button class="danger" onclick={() => remove(suppression)}>Remove</button>
						</td>
					{/if}
				</tr>
			{/each}
		</tbody>
	</table>
{/if}

<style>
	.new {
		margin-bottom: 1.5rem;
	}
	.new h2 {
		margin-top: 0;
	}
	.grid {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(12rem, 1fr));
		gap: 0.75rem;
		margin-bottom: 0.75rem;
	}
	.field {
		margin-bottom: 0.75rem;
	}
	tr.inactive td {
		opacity: 0.6;
	}
</style>
