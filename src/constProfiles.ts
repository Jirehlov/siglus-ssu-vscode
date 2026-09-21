export type ConstProfileCatalog = { profiles: number[]; default: number | undefined };

function isProfileNumber(value: unknown): value is number {
	return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

export function parseConstProfileCatalog(validationOutput: string, helpOutput: string): ConstProfileCatalog {
	// The existing CLI reports the exact accepted numbers when -1 is rejected.
	// Read that list rather than extracting numbers from the descriptive help text.
	const expected = validationOutput.match(/invalid --const-profile value:\s*-1\s*\(expected\s+([^\r\n)]+)\)/i)?.[1];
	const values = expected?.replace(/\bor\b/gi, ',').split(',').map((value) => value.trim()).filter(Boolean);
	if (!values?.length || values.some((value) => !/^\d+$/.test(value) || !isProfileNumber(Number(value)))) {
		throw new Error('Cannot read the available profile numbers from siglus-ssu argument validation.');
	}
	const profiles = [...new Set(values.map(Number))].sort((left, right) => left - right);
	const optionHelp = helpOutput.split(/\r?\n/).find((line) => /^\s*--const-profile(?:\s|$)/.test(line));
	const defaultMatch = optionHelp?.match(/\bdefault\s*:\s*(\d+)\b/i);
	const defaultProfile = defaultMatch ? Number(defaultMatch[1]) : undefined;
	return {
		profiles,
		default: defaultProfile !== undefined && profiles.includes(defaultProfile) ? defaultProfile : undefined,
	};
}

/** Explicit settings override legacy arguments; otherwise retain the CLI's last-value behavior. */
export function resolveConstProfile(
	configuredProfile: unknown,
	extraArgs: readonly string[],
): { profile: number | undefined; serverExtraArgs: string[] } {
	const serverExtraArgs: string[] = [];
	let legacyProfile: string | undefined;
	for (let index = 0; index < extraArgs.length; index += 1) {
		const arg = extraArgs[index];
		if (arg === '--') {
			serverExtraArgs.push(...extraArgs.slice(index));
			break;
		}
		if (arg === '--const-profile') {
			const next = extraArgs[index + 1];
			legacyProfile = next ?? '';
			// Keep unrelated flags when an explicit setting repairs an incomplete legacy option.
			if (next !== undefined && !next.startsWith('--')) {
				index += 1;
			}
		} else if (arg.startsWith('--const-profile=')) {
			legacyProfile = arg.slice('--const-profile='.length);
		} else {
			serverExtraArgs.push(arg);
		}
	}
	const value = configuredProfile ?? legacyProfile?.trim();
	if (value === undefined) {
		return { profile: undefined, serverExtraArgs };
	}
	const profile = typeof value === 'string' && value.length > 0 ? Number(value) : value;
	if (!isProfileNumber(profile)) {
		throw new Error('Const profile must be a non-negative integer. Use SiglusSS: Select Const Profile to choose one.');
	}
	return { profile, serverExtraArgs };
}
