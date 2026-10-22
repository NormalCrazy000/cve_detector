<script lang="ts">
	let {
		total,
		limit,
		offset,
		onchange
	}: { total: number; limit: number; offset: number; onchange: (offset: number) => void } =
		$props();

	let last = $derived(Math.min(offset + limit, total));
</script>

{#if total > limit}
	<nav class="row pager" aria-label="Pagination">
		<button disabled={offset === 0} onclick={() => onchange(Math.max(0, offset - limit))}>
			Previous
		</button>
		<span class="muted">{offset + 1}–{last} of {total}</span>
		<button disabled={last >= total} onclick={() => onchange(offset + limit)}>Next</button>
	</nav>
{/if}

<style>
	.pager {
		margin-top: 0.75rem;
	}
</style>
