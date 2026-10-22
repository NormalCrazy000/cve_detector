<script lang="ts">
	import { api, call, type Dependency, type DependencyScope, type Schemas } from '#lib/api/client.ts';
	import { plural } from '#lib/format.ts';

	let {
		projectId,
		dependencies,
		onchanged
	}: { projectId: number; dependencies: Dependency[]; onchanged: () => void } = $props();

	const SCOPES: DependencyScope[] = ['runtime', 'provided', 'optional', 'development'];

	let ecosystem: Schemas['Ecosystem'] = $state('npm');
	let name = $state('');
	let versionSpec = $state('');
	let scope: DependencyScope = $state('runtime');
	let error = $state('');
	let editing = $state<number | null>(null);
	let editedSpec = $state('');
	let filter = $state('');

	let shown = $derived(
		filter.trim()
			? dependencies.filter((d) => d.name.toLowerCase().includes(filter.trim().toLowerCase()))
			: dependencies
	);

	async function run(action: () => Promise<unknown>) {
		error = '';
		try {
			await action();
			onchanged();
			return true;
		} catch (e) {
			error = (e as Error).message;
			return false;
		}
	}

	async function add(event: SubmitEvent) {
		event.preventDefault();
		const ok = await run(() =>
			call(
				api.POST('/api/projects/{project_id}/dependencies', {
					params: { path: { project_id: projectId } },
					body: { ecosystem, name: name.trim(), version_spec: versionSpec.trim(), scope }
				})
			)
		);
		if (ok) {
			name = '';
			versionSpec = '';
		}
	}

	function edit(dependency: Dependency) {
		editing = dependency.id;
		editedSpec = dependency.version_spec;
	}

	async function saveSpec(dependency: Dependency) {
		const ok = await run(() =>
			call(
				api.PATCH('/api/projects/{project_id}/dependencies/{dependency_id}', {
					params: { path: { project_id: projectId, dependency_id: dependency.id } },
					body: { version_spec: editedSpec.trim() }
				})
			)
		);
		if (ok) editing = null;
	}

	function changeScope(dependency: Dependency, value: DependencyScope) {
		run(() =>
			call(
				api.PATCH('/api/projects/{project_id}/dependencies/{dependency_id}', {
					params: { path: { project_id: projectId, dependency_id: dependency.id } },
					body: { scope: value }
				})
			)
		);
	}

	function remove(dependency: Dependency) {
		if (!confirm(`Remove ${dependency.name} ${dependency.version_spec}?`)) return;
		run(() =>
			call(
				api.DELETE('/api/projects/{project_id}/dependencies/{dependency_id}', {
					params: { path: { project_id: projectId, dependency_id: dependency.id } }
				})
			)
		);
	}
</script>

<form class="card add" onsubmit={add}>
	<div class="row">
		<label for="d-eco" class="visually-hidden">Ecosystem</label>
		<select id="d-eco" bind:value={ecosystem} class="eco">
			<option value="npm">npm</option>
			<option value="maven">Maven</option>
		</select>
		<label for="d-name" class="visually-hidden">Package</label>
		<input
			id="d-name"
			class="name"
			bind:value={name}
			placeholder={ecosystem === 'maven' ? 'groupId:artifactId' : 'package-name'}
			required
		/>
		<label for="d-spec" class="visually-hidden">Version or range</label>
		<input
			id="d-spec"
			class="spec"
			bind:value={versionSpec}
			placeholder={ecosystem === 'maven' ? '1.2.3 or [1.0,2.0)' : '1.2.3 or ^1.2.0'}
			required
		/>
		<label for="d-scope" class="visually-hidden">Type</label>
		<select id="d-scope" bind:value={scope} class="eco">
			{#each SCOPES as value (value)}<option {value}>{value}</option>{/each}
		</select>
		<button class="primary" type="submit" disabled={!name.trim() || !versionSpec.trim()}>
			Add dependency
		</button>
	</div>
	<p class="hint">
		Changes are scanned within a few minutes. Changing a version keeps the history, so the next
		digest reports what the upgrade resolved.
	</p>
</form>

{#if error}<div class="alert error" role="alert">{error}</div>{/if}

{#if dependencies.length === 0}
	<p class="muted">No dependencies yet: add them above or import a manifest.</p>
{:else}
	<div class="row spread toolbar">
		<span class="muted">{plural(dependencies.length, 'dependency', 'dependencies')}</span>
		<label for="d-filter" class="visually-hidden">Filter</label>
		<input id="d-filter" class="filter" type="search" placeholder="Filter by name" bind:value={filter} />
	</div>
	<table class="data">
		<thead>
			<tr>
				<th>Package</th>
				<th>Version</th>
				<th>Type</th>
				<th>Source</th>
				<th class="num">Open findings</th>
				<th><span class="visually-hidden">Actions</span></th>
			</tr>
		</thead>
		<tbody>
			{#each shown as dependency (dependency.id)}
				<tr>
					<td data-label="Package">
						<span class="muted small">{dependency.ecosystem}</span>
						<code>{dependency.name}</code>
						{#if dependency.is_direct === false}<span class="muted small">transitive</span>{/if}
					</td>
					<td data-label="Version">
						{#if editing === dependency.id}
							<form class="row" onsubmit={(e) => (e.preventDefault(), saveSpec(dependency))}>
								<label for="edit-{dependency.id}" class="visually-hidden">New version</label>
								<input id="edit-{dependency.id}" class="spec" bind:value={editedSpec} required />
								<button type="submit" class="primary">Save</button>
								<button type="button" onclick={() => (editing = null)}>Cancel</button>
							</form>
						{:else}
							<button
								class="link"
								aria-label="Change version of {dependency.name} ({dependency.version_spec})"
								onclick={() => edit(dependency)}
							>
								{dependency.version_spec}
							</button>
						{/if}
					</td>
					<td data-label="Type">
						<label for="scope-{dependency.id}" class="visually-hidden">Type of {dependency.name}</label>
						<select
							id="scope-{dependency.id}"
							class="eco"
							value={dependency.scope}
							onchange={(e) => changeScope(dependency, e.currentTarget.value as DependencyScope)}
						>
							{#each SCOPES as value (value)}<option {value}>{value}</option>{/each}
						</select>
					</td>
					<td data-label="Source" class="muted">{dependency.source}</td>
					<td data-label="Open findings" class="num">
						{#if dependency.open_findings}
							<a href="?tab=findings" class="count">{dependency.open_findings}</a>
						{:else}
							0
						{/if}
					</td>
					<td>
						<button class="danger" onclick={() => remove(dependency)}>Remove</button>
					</td>
				</tr>
			{/each}
		</tbody>
	</table>
{/if}

<style>
	.add {
		margin-bottom: 1rem;
	}
	.add .hint {
		margin: 0.5rem 0 0;
	}
	.eco {
		width: auto;
	}
	.name {
		flex: 2;
		min-width: 12rem;
	}
	.spec {
		flex: 1;
		min-width: 8rem;
		max-width: 14rem;
	}
	.toolbar {
		margin-bottom: 0.5rem;
	}
	.filter {
		max-width: 16rem;
	}
	.count {
		color: var(--danger);
		font-weight: 600;
	}
</style>
