<script lang="ts">
	import { api, call, type Finding } from '#lib/api/client.ts';
	import { fromDateInput } from '#lib/format.ts';

	let { onsaved }: { onsaved: () => void } = $props();

	let dialog: HTMLDialogElement | undefined = $state();
	let finding = $state<Finding | null>(null);
	let reason = $state('');
	let scope: 'project' | 'global' = $state('project');
	let reference = $state('');
	let expires = $state('');
	let error = $state('');
	let saving = $state(false);

	/** Show the dialog for a finding (the CVE alias is preselected when there is one). */
	export function open(target: Finding) {
		finding = target;
		reference =
			target.advisory.aliases.find((alias) => alias.startsWith('CVE-')) ??
			target.advisory.source_id;
		reason = '';
		scope = 'project';
		expires = '';
		error = '';
		dialog?.showModal();
	}

	function close() {
		dialog?.close();
	}

	async function save(event: SubmitEvent) {
		event.preventDefault();
		if (!finding) return;
		saving = true;
		error = '';
		try {
			await call(
				api.POST('/api/suppressions', {
					body: {
						advisory_ref: reference,
						project_id: scope === 'project' ? finding.project_id : null,
						reason,
						expires_at: fromDateInput(expires)
					}
				})
			);
			close();
			onsaved();
		} catch (e) {
			error = (e as Error).message;
		} finally {
			saving = false;
		}
	}
</script>

<dialog bind:this={dialog} onclose={() => (finding = null)} aria-labelledby="suppress-title">
	{#if finding}
		<form onsubmit={save}>
			<h2 id="suppress-title">Suppress {finding.advisory.source_id}</h2>
			<p class="muted small">
				A suppressed finding is not notified until the suppression expires or is removed.
			</p>
			{#if error}<div class="alert error" role="alert">{error}</div>{/if}
			<div class="field">
				<label for="suppress-ref">Advisory</label>
				<select id="suppress-ref" bind:value={reference}>
					{#each [finding.advisory.source_id, ...finding.advisory.aliases] as ref (ref)}
						<option value={ref}>{ref}</option>
					{/each}
				</select>
			</div>
			<div class="field">
				<span class="label">Applies to</span>
				<label class="inline">
					<input type="radio" bind:group={scope} value="project" />
					project {finding.project_name}
				</label>
				<label class="inline">
					<input type="radio" bind:group={scope} value="global" />
					all projects
				</label>
			</div>
			<div class="field">
				<label for="suppress-reason">Reason</label>
				<textarea id="suppress-reason" bind:value={reason} required maxlength="5000"
				></textarea>
			</div>
			<div class="field">
				<label for="suppress-expires">
					Expires <span class="hint">(optional; the finding comes back afterwards)</span>
				</label>
				<input id="suppress-expires" type="date" bind:value={expires} />
			</div>
			<div class="row actions">
				<button type="submit" class="primary" disabled={saving || !reason.trim()}>Suppress</button>
				<button type="button" onclick={close}>Cancel</button>
			</div>
		</form>
	{/if}
</dialog>

<style>
	dialog {
		width: min(34rem, calc(100vw - 2rem));
		border: 1px solid var(--border);
		border-radius: var(--radius);
		background: var(--surface);
		color: var(--text);
		padding: 1.25rem;
	}
	dialog::backdrop {
		background: rgb(0 0 0 / 0.45);
	}
	h2 {
		margin-top: 0;
	}
	.label {
		display: block;
		font-weight: 600;
		margin-bottom: 0.25rem;
	}
	.label + label {
		margin-right: 1rem;
	}
	.actions {
		margin-top: 1rem;
	}
</style>
