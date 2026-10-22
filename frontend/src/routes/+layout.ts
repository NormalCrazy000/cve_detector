import { redirect } from '@sveltejs/kit';
import { fetchSession } from '#lib/session.svelte.ts';
import type { LayoutLoad } from './$types';

// Everything is rendered in the browser; the backend only serves the API and static files.
export const ssr = false;
export const prerender = false;

export const load: LayoutLoad = async ({ fetch, url }) => {
	const user = await fetchSession(fetch);
	const onLogin = url.pathname === '/login';
	if (!user && !onLogin) {
		redirect(307, `/login?next=${encodeURIComponent(url.pathname + url.search)}`);
	}
	if (user && onLogin) redirect(307, '/');
	return { user };
};
