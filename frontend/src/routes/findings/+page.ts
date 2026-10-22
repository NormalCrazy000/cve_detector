import { api, call, type FindingStatus, type Severity } from '#lib/api/client.ts';
import type { PageLoad } from './$types';

export const PAGE_SIZE = 50;

export const load: PageLoad = async ({ fetch, url }) => {
	const params = url.searchParams;
	const filters = {
		project_id: params.get('project_id') ? Number(params.get('project_id')) : undefined,
		min_severity: (params.get('min_severity') as Severity | null) ?? undefined,
		status: params.getAll('status') as FindingStatus[],
		suppressed: params.has('suppressed') ? params.get('suppressed') === 'true' : undefined,
		q: params.get('q') ?? undefined,
		offset: Number(params.get('offset') ?? 0)
	};
	const [findings, projects] = await Promise.all([
		call(
			api.GET('/api/findings', {
				fetch,
				params: {
					query: {
						...filters,
						status: filters.status.length ? filters.status : undefined,
						limit: PAGE_SIZE
					}
				}
			})
		),
		call(api.GET('/api/projects', { fetch }))
	]);
	return { findings, projects, filters };
};
