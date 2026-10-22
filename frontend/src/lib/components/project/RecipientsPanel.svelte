<script lang="ts">
	import { api, call, type Schemas } from '#lib/api/client.ts';

	let {
		projectId,
		recipients,
		onchanged
	}: { projectId: number; recipients: Schemas['RecipientOut'][]; onchanged: () => void } =
		$props();

	let target = $state('');
	let error = $state('');

	async function add(event: SubmitEvent) {
		event.preventDefault();
		error = '';
		try {
			await call(
				api.POST('/api/projects/{project_id}/recipients', {
					params: { path: { project_id: projectId } },
					body: { target: target.trim() }
				})
			);
			target = '';
			onchanged();
		} catch (e) {
			error = (e as Error).message;
		}
	}

	async function remove(recipient: Schemas['RecipientOut']) {
		if (!confirm(`Stop notifying ${recipient.target}?`)) return;
		error = '';
		try {
			await call(
				api.DELETE('/api/projects/{project_id}/recipients/{recipient_id}', {
					params: { path: { project_id: projectId, recipient_id: recipient.id } }
				})
			);
			onchanged();
		} catch (e) {
			error = (e as Error).message;
		}
	}
</script>

{#if error}<div class="alert error" role="alert">{error}</div>{/if}
{#if recipients.length === 0}
	<div class="alert warn">Nobody is notified about this project yet.</div>
{:else}
	<ul class="card list">
		{#each recipients as recipient (recipient.id)}
			<li class="row spread">
				<span>{recipient.target}</span>
				<button class="danger" onclick={() => remove(recipient)}>Remove</button>
			</li>
		{/each}
	</ul>
{/if}
<form class="row add" onsubmit={add}>
	<label for="r-target" class="visually-hidden">Email address</label>
	<input id="r-target" type="email" placeholder="name@example.com" bind:value={target} required />
	<button class="primary" type="submit" disabled={!target.trim()}>Add recipient</button>
</form>

<style>
	.list {
		list-style: none;
		padding: 0.25rem 1rem;
		margin: 0;
	}
	.list li {
		padding: 0.4rem 0;
		border-bottom: 1px solid var(--border);
	}
	.list li:last-child {
		border-bottom: none;
	}
	.add {
		margin-top: 1rem;
	}
	.add input {
		flex: 1;
	}
</style>
