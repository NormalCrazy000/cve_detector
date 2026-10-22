// Typed client of the backend REST API, generated from its OpenAPI schema (npm run gen:api).
import { goto } from '$app/navigation';
import createClient from 'openapi-fetch';
import type { components, paths } from './schema';

export type Schemas = components['schemas'];
export type Project = Schemas['ProjectOut'];
export type Dependency = Schemas['DependencyOut'];
export type Finding = Schemas['FindingOut'];
export type Suppression = Schemas['SuppressionOut'];
export type Severity = Schemas['Severity'];
export type FindingStatus = Schemas['FindingStatus'];
export type DependencyScope = Schemas['DependencyScope'];

export const api = createClient<paths>({ baseUrl: '', credentials: 'same-origin' });

export class ApiError extends Error {
	constructor(
		readonly status: number,
		message: string
	) {
		super(message);
	}
}

type Detail = string | { loc?: (string | number)[]; msg: string }[];

/** Turn a FastAPI error body into one readable sentence. */
export function errorMessage(error: unknown, status: number): string {
	const detail = (error as { detail?: Detail } | undefined)?.detail;
	if (typeof detail === 'string') return detail;
	if (Array.isArray(detail) && detail.length) {
		return detail
			.map((d) => {
				const field = d.loc?.filter((part) => part !== 'body').join('.');
				return field ? `${field}: ${d.msg}` : d.msg;
			})
			.join('; ');
	}
	return `request failed (HTTP ${status})`;
}

/** Await an api call and return its data, or throw an {@link ApiError}. */
export async function call<T>(
	request: Promise<{ data?: T; error?: unknown; response: Response }>
): Promise<T> {
	const { data, error, response } = await request;
	if (response.status === 401 && location.pathname !== '/login') {
		// The session expired or was revoked: log in again, then come back here.
		await goto(`/login?next=${encodeURIComponent(location.pathname + location.search)}`);
	}
	if (!response.ok) throw new ApiError(response.status, errorMessage(error, response.status));
	return data as T;
}
