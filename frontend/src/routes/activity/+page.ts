import { api, call } from '#lib/api/client.ts';
import type { PageLoad } from './$types';

export const PAGE_SIZE = 25;

export const load: PageLoad = async ({ fetch, url }) => {
	const scansOffset = Number(url.searchParams.get('scans') ?? 0);
	const logOffset = Number(url.searchParams.get('log') ?? 0);
	const [scans, log, projects] = await Promise.all([
		call(api.GET('/api/scans', { fetch, params: { query: { limit: PAGE_SIZE, offset: scansOffset } } })),
		call(
			api.GET('/api/notifications/log', {
				fetch,
				params: { query: { limit: PAGE_SIZE, offset: logOffset } }
			})
		),
		call(api.GET('/api/projects', { fetch }))
	]);
	return { scans, log, projects, scansOffset, logOffset };
};
