<script lang="ts">
	import '../app.css';
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { api } from '#lib/api/client.ts';
	import { session } from '#lib/session.svelte.ts';
	import { setTheme, theme, type ThemeChoice } from '#lib/theme.svelte.ts';
	import type { LayoutProps } from './$types';

	let { children }: LayoutProps = $props();

	const links = [
		{ href: '/', label: 'Dashboard' },
		{ href: '/projects', label: 'Projects' },
		{ href: '/findings', label: 'Findings' },
		{ href: '/suppressions', label: 'Suppressions' },
		{ href: '/activity', label: 'Activity' },
		{ href: '/settings', label: 'Settings' }
	];
	const nextTheme: Record<ThemeChoice, ThemeChoice> = {
		system: 'light',
		light: 'dark',
		dark: 'system'
	};

	function isCurrent(href: string): boolean {
		const path = page.url.pathname;
		return href === '/' ? path === '/' : path === href || path.startsWith(`${href}/`);
	}

	async function logout() {
		await api.POST('/api/auth/logout');
		session.user = null;
		await goto('/login');
	}
</script>

<svelte:head>
	<title>cve_detector</title>
</svelte:head>

{#if session.user}
	<header>
		<div class="bar">
			<a class="brand" href="/">cve_detector</a>
			<nav aria-label="Main">
				{#each links as link (link.href)}
					<a href={link.href} aria-current={isCurrent(link.href) ? 'page' : undefined}>
						{link.label}
					</a>
				{/each}
			</nav>
			<div class="row tools">
				<button
					class="theme"
					title="Theme: {theme.choice} (click to change)"
					onclick={() => setTheme(nextTheme[theme.choice])}
				>
					<svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true">
						{#if theme.choice === 'dark'}
							<path d="M20 14.5A8.5 8.5 0 0 1 9.5 4a8.5 8.5 0 1 0 10.5 10.5z" fill="currentColor" />
						{:else if theme.choice === 'light'}
							<circle cx="12" cy="12" r="4.5" fill="currentColor" />
							<path
								d="M12 2v2.5M12 19.5V22M2 12h2.5M19.5 12H22M4.9 4.9l1.8 1.8M17.3 17.3l1.8 1.8M4.9 19.1l1.8-1.8M17.3 6.7l1.8-1.8"
								stroke="currentColor"
								stroke-width="2"
								stroke-linecap="round"
							/>
						{:else}
							<circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="2" />
							<path d="M12 3a9 9 0 0 1 0 18z" fill="currentColor" />
						{/if}
					</svg>
					<span class="visually-hidden">Theme: {theme.choice}</span>
				</button>
				<span class="muted small">{session.user}</span>
				<button onclick={logout}>Log out</button>
			</div>
		</div>
	</header>
{/if}

<main>
	{@render children()}
</main>

<footer class="muted small">
	Vulnerability data from <a href="https://osv.dev" rel="noreferrer noopener" target="_blank">OSV.dev</a>
	and the databases it aggregates. The absence of findings does not mean the absence of
	vulnerabilities.
</footer>

<style>
	header {
		background: var(--surface);
		border-bottom: 1px solid var(--border);
	}
	.bar {
		max-width: 1200px;
		margin: 0 auto;
		padding: 0.5rem 1rem;
		display: grid;
		grid-template-columns: auto 1fr auto;
		grid-template-areas: 'brand nav tools';
		align-items: center;
		gap: 0.5rem 1.25rem;
	}
	.brand {
		grid-area: brand;
	}
	nav {
		grid-area: nav;
	}
	.tools {
		grid-area: tools;
		justify-content: flex-end;
	}
	@media (max-width: 860px) {
		.bar {
			grid-template-columns: 1fr auto;
			grid-template-areas: 'brand tools' 'nav nav';
		}
	}
	.brand {
		font-weight: 700;
		color: var(--text);
	}
	nav {
		display: flex;
		gap: 0.25rem;
		flex-wrap: wrap;
	}
	nav a {
		color: var(--text);
		padding: 0.3rem 0.6rem;
		border-radius: var(--radius);
	}
	nav a:hover {
		background: var(--surface-2);
		text-decoration: none;
	}
	nav a[aria-current='page'] {
		background: var(--surface-2);
		font-weight: 600;
		box-shadow: inset 0 -2px 0 var(--accent);
	}
	.theme {
		width: 2.2rem;
		justify-content: center;
		padding: 0.4rem 0;
	}
	main {
		max-width: 1200px;
		margin: 0 auto;
		padding: 1.5rem 1rem;
	}
	footer {
		max-width: 1200px;
		margin: 0 auto;
		padding: 1rem;
		border-top: 1px solid var(--border);
	}
</style>
