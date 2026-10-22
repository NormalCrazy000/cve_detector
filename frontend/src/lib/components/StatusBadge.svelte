<script lang="ts">
	import type { FindingStatus } from '#lib/api/client.ts';
	import { STATUS_LABELS } from '#lib/format.ts';

	let { status, suppressed = false }: { status: FindingStatus; suppressed?: boolean } = $props();
</script>

<span class="status {status}">{STATUS_LABELS[status]}</span>
{#if suppressed}<span class="status suppressed">Suppressed</span>{/if}

<style>
	.status {
		display: inline-block;
		font-size: 0.8rem;
		padding: 0 0.4rem;
		border-radius: 4px;
		background: var(--surface-2);
		border: 1px solid var(--border);
		white-space: nowrap;
	}
	.affected {
		border-color: var(--danger);
	}
	.fixed {
		border-color: var(--ok);
	}
	.suppressed {
		color: var(--muted);
		font-style: italic;
	}
</style>
