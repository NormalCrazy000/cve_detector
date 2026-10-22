import { api, call } from '#lib/api/client.ts';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ fetch }) => ({
	channels: await call(api.GET('/api/notifications/status', { fetch }))
});
