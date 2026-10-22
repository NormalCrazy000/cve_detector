<script lang="ts">
	import type { Schemas, Severity } from '#lib/api/client.ts';
	import { SEVERITIES } from '#lib/format.ts';

	let { counts }: { counts: Schemas['SeverityCounts'] } = $props();

	let shown = $derived(
		SEVERITIES.map((severity: Severity) => ({ severity, count: counts[severity] ?? 0 })).filter(
			(entry) => entry.count > 0
		)
	);
</script>

{#if shown.length}
	<span class="counts">
		{#each shown as { severity, count } (severity)}
			<span class="count sev-{severity}" title="{count} {severity}">{count} {severity}</span>
		{/each}
	</span>
{:else}
	<span class="muted">none open</span>
{/if}

<style>
	.counts {
		display: inline-flex;
		gap: 0.6rem;
		flex-wrap: wrap;
	}
	.count {
		font-weight: 600;
		white-space: nowrap;
	}
	.sev-critical {
		color: var(--sev-critical);
	}
	.sev-high {
		color: var(--sev-high);
	}
	.sev-medium {
		color: var(--sev-medium);
	}
	.sev-low {
		color: var(--sev-low);
	}
	.sev-none,
	.sev-unknown {
		color: var(--sev-none);
	}
</style>
