<script lang="ts">
	import { api, call, type DependencyScope, type Project, type Schemas } from '#lib/api/client.ts';
	import { SEVERITIES } from '#lib/format.ts';

	let { project, onsaved }: { project: Project; onsaved: () => void } = $props();

	const SCOPES: { value: DependencyScope; label: string }[] = [
		{ value: 'runtime', label: 'Runtime' },
		{ value: 'provided', label: 'Provided / peer' },
		{ value: 'optional', label: 'Optional' },
		{ value: 'development', label: 'Development / test' }
	];

	// An editable copy, reset whenever the saved project changes.
	let form = $derived.by(() => {
		const copy = $state<Schemas['ProjectUpdate'] & { included_scopes: DependencyScope[] }>({
			name: project.name,
			description: project.description,
			scan_interval_hours: project.scan_interval_hours,
			min_severity: project.min_severity,
			included_scopes: [...project.included_scopes],
			notify_minor_updates: project.notify_minor_updates,
			all_clear_policy: project.all_clear_policy,
			email_delivery: project.email_delivery
		});
		return copy;
	});
	let error = $state('');
	let saved = $state(false);
	let busy = $state(false);

	async function save(event: SubmitEvent) {
		event.preventDefault();
		busy = true;
		error = '';
		saved = false;
		try {
			await call(
				api.PATCH('/api/projects/{project_id}', {
					params: { path: { project_id: project.id } },
					body: form
				})
			);
			saved = true;
			onsaved();
		} catch (e) {
			error = (e as Error).message;
		} finally {
			busy = false;
		}
	}
</script>

<form class="card" onsubmit={save}>
	{#if error}<div class="alert error" role="alert">{error}</div>{/if}
	{#if saved}<div class="alert ok" role="status">Settings saved.</div>{/if}

	<div class="field">
		<label for="p-name">Name</label>
		<input id="p-name" bind:value={form.name} required maxlength="200" />
	</div>
	<div class="field">
		<label for="p-description">Description</label>
		<input id="p-description" bind:value={form.description} maxlength="5000" />
	</div>
	<div class="field">
		<label for="p-interval">Scan every (hours)</label>
		<input id="p-interval" type="number" min="1" max="720" bind:value={form.scan_interval_hours} />
	</div>
	<div class="field">
		<label for="p-severity">
			Notify from severity <span class="hint">(findings without a severity are always notified)</span>
		</label>
		<select id="p-severity" bind:value={form.min_severity}>
			{#each SEVERITIES.filter((s) => s !== 'unknown') as severity (severity)}
				<option value={severity}>{severity}</option>
			{/each}
		</select>
	</div>
	<fieldset class="field">
		<legend>Notify findings in these dependency types</legend>
		{#each SCOPES as scope (scope.value)}
			<label class="inline">
				<input type="checkbox" value={scope.value} bind:group={form.included_scopes} />
				{scope.label}
			</label>
		{/each}
		<p class="hint">Findings of the other types are still recorded and shown here.</p>
	</fieldset>
	<div class="field">
		<label class="inline">
			<input type="checkbox" bind:checked={form.notify_minor_updates} />
			Also notify minor advisory changes (new links, reworded text)
		</label>
	</div>
	<div class="field">
		<label for="p-allclear">"No new issues" report</label>
		<select id="p-allclear" bind:value={form.all_clear_policy}>
			<option value="never">Never</option>
			<option value="every_run">After every scan without news</option>
			<option value="daily">At most daily</option>
			<option value="weekly">At most weekly</option>
		</select>
	</div>
	<div class="field">
		<label for="p-delivery">Recipients receive</label>
		<select id="p-delivery" bind:value={form.email_delivery}>
			<option value="separate">One private email each</option>
			<option value="together">One email with everybody in "To"</option>
		</select>
	</div>
	<button class="primary save" type="submit" disabled={busy || form.included_scopes.length === 0}>
		Save settings
	</button>
</form>

<style>
	fieldset {
		border: none;
		padding: 0;
		margin: 0.75rem 0 0;
	}
	legend {
		font-weight: 600;
		margin-bottom: 0.25rem;
	}
	fieldset label.inline {
		margin-right: 1rem;
	}
	.save {
		margin-top: 1rem;
	}
</style>
