<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { api, errorMessage } from '#lib/api/client.ts';
	import { session } from '#lib/session.svelte.ts';

	let username = $state('');
	let password = $state('');
	let error = $state('');
	let busy = $state(false);

	/** Only follow same-site paths after login. */
	function nextPath(): string {
		const next = page.url.searchParams.get('next') ?? '/';
		return next.startsWith('/') && !next.startsWith('//') ? next : '/';
	}

	async function login(event: SubmitEvent) {
		event.preventDefault();
		busy = true;
		error = '';
		const { data, error: failure, response } = await api.POST('/api/auth/login', {
			body: { username, password }
		});
		busy = false;
		if (!data) {
			error =
				response.status === 401
					? 'Wrong username or password.'
					: errorMessage(failure, response.status);
			return;
		}
		session.user = data.username;
		await goto(nextPath(), { replace: true });
	}
</script>

<svelte:head>
	<title>Log in · cve_detector</title>
</svelte:head>

<div class="login card">
	<h1>cve_detector</h1>
	<form onsubmit={login}>
		{#if error}<div class="alert error" role="alert">{error}</div>{/if}
		<div class="field">
			<label for="username">Username</label>
			<input id="username" bind:value={username} autocomplete="username" required />
		</div>
		<div class="field">
			<label for="password">Password</label>
			<input
				id="password"
				type="password"
				bind:value={password}
				autocomplete="current-password"
				required
			/>
		</div>
		<button class="primary" type="submit" disabled={busy}>Log in</button>
	</form>
	<p class="muted small">Credentials are set with CVED_ADMIN_USERNAME / CVED_ADMIN_PASSWORD.</p>
</div>

<style>
	.login {
		max-width: 22rem;
		margin: 10vh auto 0;
	}
	button {
		margin-top: 1rem;
		width: 100%;
		justify-content: center;
	}
</style>
