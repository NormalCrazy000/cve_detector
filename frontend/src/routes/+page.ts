import { api, call } from '#lib/api/client.ts';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ fetch }) => {
	const [projects, scans, notifications, channels] = await Promise.all([
		call(api.GET('/api/projects', { fetch })),
		call(api.GET('/api/scans', { fetch, params: { query: { limit: 5 } } })),
		call(api.GET('/api/notifications/log', { fetch, params: { query: { limit: 5 } } })),
		call(api.GET('/api/notifications/status', { fetch }))
	]);
	return { projects, scans, notifications, channels };
};
