import { api, call } from '#lib/api/client.ts';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ fetch }) => {
	const [suppressions, projects] = await Promise.all([
		call(api.GET('/api/suppressions', { fetch })),
		call(api.GET('/api/projects', { fetch }))
	]);
	return { suppressions, projects };
};
