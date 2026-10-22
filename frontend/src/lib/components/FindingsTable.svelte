<script lang="ts">
	import { api, call, type Finding } from '#lib/api/client.ts';
	import { dateTime, timeAgo } from '#lib/format.ts';
	import SeverityBadge from './SeverityBadge.svelte';
	import StatusBadge from './StatusBadge.svelte';
	import SuppressDialog from './SuppressDialog.svelte';

	let {
		findings,
		showProject = true,
		onchanged
	}: { findings: Finding[]; showProject?: boolean; onchanged: () => void } = $props();

	let expanded = $state<number | null>(null);
	let suppressDialog: SuppressDialog | undefined = $state();
	let error = $state('');

	async function unsuppress(finding: Finding) {
		if (!finding.suppression) return;
		if (!confirm(`Remove the suppression of ${finding.suppression.advisory_ref}?`)) return;
		error = '';
		try {
			await call(
				api.DELETE('/api/suppressions/{suppression_id}', {
					params: { path: { suppression_id: finding.suppression.id } }
				})
			);
			onchanged();
		} catch (e) {
			error = (e as Error).message;
		}
	}
</script>

{#if error}<div class="alert error" role="alert">{error}</div>{/if}

{#if findings.length === 0}
	<p class="muted card">No findings match.</p>
{:else}
	<table class="data findings">
		<thead>
			<tr>
				<th>Severity</th>
				<th>Advisory</th>
				{#if showProject}<th>Project</th>{/if}
				<th>Dependency</th>
				<th>Status</th>
				<th>First seen</th>
			</tr>
		</thead>
		<tbody>
			{#each findings as finding (finding.id)}
				{@const advisory = finding.advisory}
				<tr class={{ suppressed: finding.suppression }}>
					<td data-label="Severity">
						<SeverityBadge severity={advisory.severity} score={advisory.cvss_score} />
					</td>
					<td data-label="Advisory">
						<button
							class="link"
							aria-expanded={expanded === finding.id}
							onclick={() => (expanded = expanded === finding.id ? null : finding.id)}
						>
							{advisory.source_id}
						</button>
						{#if advisory.aliases.length}
							<span class="muted small">{advisory.aliases.join(', ')}</span>
						{/if}
						{#if advisory.is_known_exploited}<strong class="kev">exploited</strong>{/if}
						<div class="small">{advisory.summary}</div>
					</td>
					{#if showProject}
						<td data-label="Project">
							<a href="/projects/{finding.project_id}">{finding.project_name}</a>
						</td>
					{/if}
					<td data-label="Dependency">
						<code>{finding.dependency.name}</code>
						<span class="muted">{finding.dependency.version_spec}</span>
						{#if finding.dependency.scope !== 'runtime'}
							<span class="muted small">({finding.dependency.scope})</span>
						{/if}
					</td>
					<td data-label="Status">
						<StatusBadge status={finding.status} suppressed={!!finding.suppression} />
					</td>
					<td data-label="First seen" title={dateTime(finding.first_seen_at)}>
						{timeAgo(finding.first_seen_at)}
					</td>
				</tr>
				{#if expanded === finding.id}
					<tr class="details">
						<td colspan={showProject ? 6 : 5}>
							<dl>
								<dt>Fixed in</dt>
								<dd>
									{finding.fixed_versions.length
										? finding.fixed_versions.join(', ')
										: 'no fixed version yet'}
								</dd>
								{#if advisory.cvss_vector}
									<dt>CVSS</dt>
									<dd><code>{advisory.cvss_vector}</code></dd>
								{/if}
								<dt>Published</dt>
								<dd>{dateTime(advisory.published_at)}</dd>
								<dt>Notified</dt>
								<dd>{finding.notified ? 'yes' : 'not yet'}</dd>
								{#if finding.resolved_at}
									<dt>Resolved</dt>
									<dd>{dateTime(finding.resolved_at)}</dd>
								{/if}
								{#if finding.suppression}
									<dt>Suppressed</dt>
									<dd>
										{finding.suppression.reason}
										<span class="muted">
											({finding.suppression.project_id ? 'this project' : 'all projects'}, {finding
												.suppression.expires_at
												? `until ${dateTime(finding.suppression.expires_at)}`
												: 'no expiry'})
										</span>
									</dd>
								{/if}
							</dl>
							<div class="row">
								<a class="button" href={advisory.url} target="_blank" rel="noreferrer noopener">
									Open on OSV.dev
								</a>
								{#if finding.suppression}
									<button onclick={() => unsuppress(finding)}>Remove suppression</button>
								{:else if finding.status === 'affected' || finding.status === 'potentially_affected'}
									<button onclick={() => suppressDialog?.open(finding)}>Suppress…</button>
								{/if}
							</div>
						</td>
					</tr>
				{/if}
			{/each}
		</tbody>
	</table>
{/if}

<SuppressDialog bind:this={suppressDialog} onsaved={onchanged} />

<style>
	tr.suppressed td {
		opacity: 0.65;
	}
	tr.details td {
		background: var(--surface-2);
	}
	dl {
		display: grid;
		grid-template-columns: max-content 1fr;
		gap: 0.25rem 1rem;
		margin: 0 0 0.75rem;
	}
	dt {
		color: var(--muted);
	}
	dd {
		margin: 0;
	}
	.kev {
		color: var(--danger);
		font-size: 0.8rem;
		margin-left: 0.3rem;
	}
</style>
