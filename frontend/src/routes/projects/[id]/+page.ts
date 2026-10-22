import { error } from '@sveltejs/kit';
import { api, ApiError, call } from '#lib/api/client.ts';
import type { PageLoad } from './$types';

const TABS = ['findings', 'dependencies', 'import', 'recipients', 'settings'] as const;
export type Tab = (typeof TABS)[number];

export const load: PageLoad = async ({ fetch, params, url }) => {
	const project_id = Number(params.id);
	const path = { path: { project_id } };
	const showResolved = url.searchParams.get('resolved') === '1';
	try {
		const [project, dependencies, recipients, findings] = await Promise.all([
			call(api.GET('/api/projects/{project_id}', { fetch, params: path })),
			call(api.GET('/api/projects/{project_id}/dependencies', { fetch, params: path })),
			call(api.GET('/api/projects/{project_id}/recipients', { fetch, params: path })),
			call(
				api.GET('/api/findings', {
					fetch,
					params: {
						query: {
							project_id,
							limit: 500,
							status: showResolved
								? ['affected', 'potentially_affected', 'fixed', 'withdrawn']
								: undefined
						}
					}
				})
			)
		]);
		const requested = url.searchParams.get('tab') as Tab | null;
		const tab: Tab = requested && TABS.includes(requested) ? requested : 'findings';
		return { project, dependencies, recipients, findings, tab, showResolved };
	} catch (e) {
		if (e instanceof ApiError && e.status === 404) error(404, 'Project not found');
		throw e;
	}
};
