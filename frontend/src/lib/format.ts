import type { FindingStatus, Severity } from './api/client';

export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'none', 'unknown'];

export const STATUS_LABELS: Record<FindingStatus, string> = {
	affected: 'Affected',
	potentially_affected: 'Potentially affected',
	fixed: 'Resolved',
	withdrawn: 'Withdrawn'
};

const relative = new Intl.RelativeTimeFormat('en', { numeric: 'auto' });
const absolute = new Intl.DateTimeFormat('en', { dateStyle: 'medium', timeStyle: 'short' });
const UNITS: [Intl.RelativeTimeFormatUnit, number][] = [
	['year', 365 * 24 * 3600],
	['month', 30 * 24 * 3600],
	['day', 24 * 3600],
	['hour', 3600],
	['minute', 60]
];

/** "3 hours ago", "in 2 days"; "just now" under a minute. */
export function timeAgo(iso: string | null | undefined, now: Date = new Date()): string {
	if (!iso) return 'never';
	const seconds = (new Date(iso).getTime() - now.getTime()) / 1000;
	for (const [unit, size] of UNITS) {
		if (Math.abs(seconds) >= size) return relative.format(Math.round(seconds / size), unit);
	}
	return 'just now';
}

export function dateTime(iso: string | null | undefined): string {
	return iso ? absolute.format(new Date(iso)) : '—';
}

/** Value for an <input type="date"> from an ISO datetime, and back (end of that day, UTC). */
export function toDateInput(iso: string | null | undefined): string {
	return iso ? iso.slice(0, 10) : '';
}

export function fromDateInput(value: string): string | null {
	return value ? new Date(`${value}T23:59:59Z`).toISOString() : null;
}

export function plural(count: number, singular: string, pluralForm = `${singular}s`): string {
	return `${count} ${count === 1 ? singular : pluralForm}`;
}
