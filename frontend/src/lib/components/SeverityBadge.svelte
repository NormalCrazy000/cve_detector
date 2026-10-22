<script lang="ts">
	import type { Severity } from '#lib/api/client.ts';

	let { severity, score = null }: { severity: Severity; score?: number | null } = $props();
</script>

<span class="badge sev-{severity}" title="Severity{score != null ? ` (CVSS ${score})` : ''}">
	{severity.toUpperCase()}{#if score != null}&nbsp;{score}{/if}
</span>

<style>
	.badge {
		display: inline-block;
		min-width: 4.5rem;
		padding: 0.05rem 0.45rem;
		border-radius: 999px;
		border: 1px solid currentColor;
		font-size: 0.75rem;
		font-weight: 600;
		text-align: center;
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
