import { api, call } from '#lib/api/client.ts';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ fetch }) => ({
	projects: await call(api.GET('/api/projects', { fetch }))
});
