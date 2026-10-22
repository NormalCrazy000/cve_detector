import { api } from './api/client';

/** The logged-in admin; null when logged out. */
export const session = $state<{ user: string | null }>({ user: null });

export async function fetchSession(fetcher: typeof fetch = fetch): Promise<string | null> {
	const { data } = await api.GET('/api/auth/me', { fetch: fetcher });
	session.user = data?.username ?? null;
	return session.user;
}
