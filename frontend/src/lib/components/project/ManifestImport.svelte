<script lang="ts">
	import { api, call, type Schemas } from '#lib/api/client.ts';

	let { projectId, onapplied }: { projectId: number; onapplied: () => void } = $props();

	type Preview = Schemas['ManifestPreview'];

	let file = $state<File | null>(null);
	let content = $state('');
	let source = $state<Schemas['DependencySource'] | ''>('');
	let preview = $state<Preview | null>(null);
	let resolved = $state<Record<string, string>>({});
	let skipped = $state<Record<string, boolean>>({});
	let error = $state('');
	let busy = $state(false);
	let done = $state<Preview | null>(null);

	let missing = $derived(
		preview?.unresolved.filter((u) => !skipped[u.name] && !resolved[u.name]?.trim()) ?? []
	);
	let hasChanges = $derived(
		!!preview && preview.added.length + preview.changed.length + preview.removed.length > 0
	);

	async function choose(event: Event & { currentTarget: HTMLInputElement }) {
		file = event.currentTarget.files?.[0] ?? null;
		preview = null;
		done = null;
		error = '';
		content = file ? await file.text() : '';
	}

	function body() {
		return { filename: file?.name ?? '', content, source: source || null };
	}

	async function showPreview() {
		busy = true;
		error = '';
		try {
			preview = await call(
				api.POST('/api/projects/{project_id}/manifest/preview', {
					params: { path: { project_id: projectId } },
					body: body()
				})
			);
			resolved = {};
			skipped = {};
		} catch (e) {
			error = (e as Error).message;
		} finally {
			busy = false;
		}
	}

	async function apply() {
		busy = true;
		error = '';
		try {
			done = await call(
				api.POST('/api/projects/{project_id}/manifest/apply', {
					params: { path: { project_id: projectId } },
					body: {
						...body(),
						resolved: Object.fromEntries(
							Object.entries(resolved).filter(([name, spec]) => spec.trim() && !skipped[name])
						),
						skip: Object.keys(skipped).filter((name) => skipped[name])
					}
				})
			);
			preview = null;
			onapplied();
		} catch (e) {
			error = (e as Error).message;
		} finally {
			busy = false;
		}
	}
</script>

<div class="card stack">
	<p>
		Import <code>pom.xml</code>, <code>package.json</code>, <code>package-lock.json</code> or the
		output of <code>mvn dependency:list</code>. Dependencies previously imported from the same kind
		of file are synchronized (added, updated, removed); manual entries and other files are left
		alone. You review the changes before anything is saved.
	</p>
	<div class="row">
		<label for="m-file" class="visually-hidden">Manifest file</label>
		<input id="m-file" type="file" accept=".xml,.pom,.json,.txt,.lst" onchange={choose} />
		<label for="m-source" class="visually-hidden">Format</label>
		<select id="m-source" bind:value={source} class="format">
			<option value="">Detect format from the file name</option>
			<option value="pom.xml">Maven pom.xml</option>
			<option value="mvn-dependency-list">mvn dependency:list output</option>
			<option value="package.json">npm package.json</option>
			<option value="package-lock.json">npm package-lock.json</option>
		</select>
		<button onclick={showPreview} disabled={!content || busy}>Preview changes</button>
	</div>
</div>

{#if error}<div class="alert error" role="alert">{error}</div>{/if}
{#if done}
	<div class="alert ok" role="status">
		Imported: {done.added.length} added, {done.changed.length} changed, {done.removed.length} removed.
		A scan will run within a few minutes.
	</div>
{/if}

{#if preview}
	<section class="card stack preview">
		<h2>Changes from {file?.name}</h2>
		{#each preview.warnings as warning (warning)}<div class="alert warn">{warning}</div>{/each}
		<p>
			<strong>{preview.added.length}</strong> to add,
			<strong>{preview.changed.length}</strong> to change,
			<strong>{preview.removed.length}</strong> to remove, {preview.unchanged} unchanged.
		</p>
		{#if preview.added.length}
			<details open>
				<summary>Added</summary>
				<ul>
					{#each preview.added as entry (entry.name + entry.version_spec)}
						<li><code>{entry.name}</code> {entry.version_spec} <span class="muted">({entry.scope})</span></li>
					{/each}
				</ul>
			</details>
		{/if}
		{#if preview.changed.length}
			<details open>
				<summary>Changed</summary>
				<ul>
					{#each preview.changed as entry (entry.name + entry.version_spec)}
						<li>
							<code>{entry.name}</code>
							{entry.previous_spec === entry.version_spec
								? `${entry.version_spec} (now ${entry.scope})`
								: `${entry.previous_spec} → ${entry.version_spec}`}
						</li>
					{/each}
				</ul>
			</details>
		{/if}
		{#if preview.removed.length}
			<details open>
				<summary>Removed</summary>
				<ul>
					{#each preview.removed as entry (entry.name + entry.version_spec)}
						<li><code>{entry.name}</code> {entry.version_spec}</li>
					{/each}
				</ul>
			</details>
		{/if}
		{#if preview.skipped.length}
			<p class="muted small">
				Already present from another source, left as is: {preview.skipped.join(', ')}
			</p>
		{/if}
		{#if preview.unresolved.length}
			<div>
				<h3>Versions to complete</h3>
				<p class="hint">
					The file alone does not tell these versions (e.g. inherited from a parent POM). Enter a
					version or skip the entry.
				</p>
				{#each preview.unresolved as entry (entry.name)}
					<div class="row unresolved">
						<code>{entry.name}</code>
						<label for="u-{entry.name}" class="visually-hidden">Version of {entry.name}</label>
						<input
							id="u-{entry.name}"
							class="spec"
							placeholder="version"
							bind:value={resolved[entry.name]}
							disabled={skipped[entry.name]}
						/>
						<label class="inline">
							<input type="checkbox" bind:checked={skipped[entry.name]} /> skip
						</label>
						{#if entry.problem}<span class="muted small">{entry.problem}</span>{/if}
					</div>
				{/each}
			</div>
		{/if}
		<div class="row">
			<button
				class="primary"
				onclick={apply}
				disabled={busy || missing.length > 0 || (!hasChanges && !preview.unresolved.length)}
			>
				Apply changes
			</button>
			<button onclick={() => (preview = null)}>Cancel</button>
			{#if missing.length}<span class="muted small">{missing.length} versions missing</span>{/if}
		</div>
	</section>
{/if}

<style>
	.format {
		width: auto;
	}
	.preview {
		margin-top: 1rem;
	}
	.preview h2 {
		margin-top: 0;
	}
	h3 {
		font-size: 1rem;
		margin: 0 0 0.25rem;
	}
	ul {
		margin: 0.25rem 0;
	}
	.unresolved {
		margin: 0.35rem 0;
	}
	.spec {
		max-width: 12rem;
	}
</style>
