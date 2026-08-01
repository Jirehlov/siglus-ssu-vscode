import { spawn } from 'node:child_process';
import { existsSync, statSync } from 'node:fs';
import * as https from 'node:https';
import * as os from 'node:os';
import * as path from 'node:path';
import * as vscode from 'vscode';
import {
	type LanguageClient,
	type LanguageClientOptions,
	type ProgressToken,
	type ServerOptions,
	WorkDoneProgress,
	type WorkDoneProgressBegin,
	type WorkDoneProgressEnd,
	type WorkDoneProgressReport,
} from 'vscode-languageclient/node';

let client: LanguageClient | undefined;
let serverOutput: vscode.LogOutputChannel | undefined;
let installSiglusSsuJob: Promise<void> | undefined;
let installSiglusSsuScheduled = false;
let isInstallingSiglusSsu = false;
let siglusSsuUpdateCheckJob: Promise<void> | undefined;
let siglusSsuUpdateCheckScheduled = false;
const siglusEncodingJobs = new Map<string, Promise<void>>();
const SIGLUS_ENCODINGS = ['shiftjis', 'utf8bom', 'utf8'] as const;
const SKIPPED_SIGLUS_SSU_VERSION_KEY = 'siglusSS.skippedSiglusSsuVersion';
const LSP_PROGRESS_REQUEST_METHODS = new Set([
	'textDocument/diagnostic',
	'textDocument/definition',
	'textDocument/documentSymbol',
	'textDocument/references',
	'textDocument/rename',
	'textDocument/semanticTokens/full',
]);
let lspProgressTokenCounter = 0;
const lspProgressStates = new Map<string, LspNotificationProgressState>();
const lspProgressDisposables = new Map<string, vscode.Disposable>();
let languageServerStatusItem: vscode.StatusBarItem | undefined;

type ExtensionSettings = {
	configuredPath: string;
	serverExtraArgs: string[];
	autoUpdateSiglusSsu: boolean;
};

type CommandSpec = {
	command: string;
	args: string[];
	cwd?: string;
};

type RunProcessOptions = {
	cwd?: string;
	outputChannel?: vscode.OutputChannel;
	token?: vscode.CancellationToken;
};

type InstallProgressReporter = (message: string, increment?: number) => void;

type LspWorkDoneProgress =
	| WorkDoneProgressBegin
	| WorkDoneProgressReport
	| WorkDoneProgressEnd;

type LspNotificationProgressState = {
	closed: boolean;
	progress?: vscode.Progress<{ increment?: number; message?: string }>;
	reportedPercentage: number;
	pending: LspWorkDoneProgress[];
	resolve?: () => void;
};

type DecodedCandidate = {
	encoding: (typeof SIGLUS_ENCODINGS)[number];
	exact: boolean;
	text: string | undefined;
};

class MissingSiglusSsuError extends Error {
	constructor(message: string) {
		super(message);
		this.name = 'MissingSiglusSsuError';
	}
}

function getServerOutputChannel(): vscode.LogOutputChannel {
	if (!serverOutput) {
		serverOutput = vscode.window.createOutputChannel('SiglusSS Language Server', {
			log: true,
		});
	}
	return serverOutput;
}

function getLanguageServerStatusItem(): vscode.StatusBarItem {
	if (!languageServerStatusItem) {
		languageServerStatusItem = vscode.window.createStatusBarItem(
			'siglusSS.languageServer',
			vscode.StatusBarAlignment.Left,
			90,
		);
		languageServerStatusItem.name = 'SiglusSS Language Server';
		languageServerStatusItem.command = 'siglusSS.restartLanguageServer';
	}
	return languageServerStatusItem;
}

function setLanguageServerStatus(text: string, tooltip: string): void {
	const item = getLanguageServerStatusItem();
	item.text = text;
	item.tooltip = tooltip;
	item.show();
}

function hideLanguageServerStatus(): void {
	languageServerStatusItem?.hide();
}

function getSettings(): ExtensionSettings {
	const config = vscode.workspace.getConfiguration('siglusSS');
	return {
		configuredPath: (config.get<string>('siglusSsuPath') || 'siglus-ssu').trim() || 'siglus-ssu',
		serverExtraArgs: normalizeStringArray(config.get<unknown>('serverExtraArgs')),
		autoUpdateSiglusSsu: config.get<boolean>('autoUpdateSiglusSsu') !== false,
	};
}

function normalizeStringArray(value: unknown): string[] {
	return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : [];
}

function stripWrappingQuotes(value: string): string {
	let current = value.trim();
	while (
		current.length >= 2 &&
		((current.startsWith('"') && current.endsWith('"')) ||
			(current.startsWith("'") && current.endsWith("'")))
	) {
		current = current.slice(1, -1).trim();
	}
	return current;
}

function primaryWorkspaceFolder(): vscode.WorkspaceFolder | undefined {
	const activeUri = vscode.window.activeTextEditor?.document.uri;
	if (activeUri) {
		const activeFolder = vscode.workspace.getWorkspaceFolder(activeUri);
		if (activeFolder) {
			return activeFolder;
		}
	}
	return vscode.workspace.workspaceFolders?.[0];
}

function expandConfiguredPath(rawValue: string): string {
	const workspaceFolder = primaryWorkspaceFolder();
	const workspacePath = workspaceFolder?.uri.fsPath;
	const workspaceBaseName = workspacePath ? path.basename(workspacePath) : undefined;
	let value = stripWrappingQuotes(rawValue);
	value = value.replace(/\$\{workspaceFolder\}/g, () => workspacePath ?? '${workspaceFolder}');
	value = value.replace(/\$\{workspaceFolderBasename\}/g, () => workspaceBaseName ?? '${workspaceFolderBasename}');
	value = value.replace(/\$\{userHome\}/g, os.homedir());
	value = value.replace(/\$\{env:([^}]+)\}/g, (_, name: string) => process.env[name] ?? `\${env:${name}}`);
	value = stripWrappingQuotes(value);
	if (value.startsWith('~')) {
		value = path.join(os.homedir(), value.slice(1));
	}
	const looksLikePath =
		value.includes('/') ||
		value.includes('\\') ||
		value.startsWith('.') ||
		/^[A-Za-z]:/.test(value);
	if (looksLikePath && workspacePath && !path.isAbsolute(value)) {
		value = path.resolve(workspacePath, value);
	}
	return value;
}

function looksLikeDirectory(value: string): boolean {
	try {
		return existsSync(value) && statSync(value).isDirectory();
	} catch {
		return false;
	}
}

function resolveCommandSpec(configuredPath: string): CommandSpec {
	const expanded = expandConfiguredPath(configuredPath);
	if (looksLikeDirectory(expanded)) {
		return {
			command: 'uv',
			args: ['run', 'siglus-ssu'],
			cwd: expanded,
		};
	}
	return {
		command: expanded,
		args: [],
	};
}

function isSiglusDocument(document: vscode.TextDocument): boolean {
	if (document.uri.scheme !== 'file' || document.isUntitled) {
		return false;
	}
	if (document.languageId === 'siglusss') {
		return true;
	}
	const lower = document.uri.fsPath.toLowerCase();
	return lower.endsWith('.ss') || lower.endsWith('.inc');
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
	if (left.byteLength !== right.byteLength) {
		return false;
	}
	for (let index = 0; index < left.byteLength; index += 1) {
		if (left[index] !== right[index]) {
			return false;
		}
	}
	return true;
}

function suspiciousTextScore(text: string): number {
	let score = 0;
	for (const char of text) {
		const code = char.charCodeAt(0);
		if (code < 32 && char !== '\n' && char !== '\t') {
			score += 2;
			continue;
		}
		if (code >= 0x80 && code <= 0x9f) {
			score += 2;
			continue;
		}
		if (code >= 0xe000 && code <= 0xf8ff) {
			score += 2;
			continue;
		}
		if (code >= 0xff61 && code <= 0xff9f) {
			score += 1;
		}
	}
	return score;
}

async function decodeCandidate(
	bytes: Uint8Array,
	encoding: (typeof SIGLUS_ENCODINGS)[number],
): Promise<DecodedCandidate> {
	try {
		const text = await vscode.workspace.decode(bytes, { encoding });
		const encoded = await vscode.workspace.encode(text, { encoding });
		return {
			encoding,
			exact: sameBytes(bytes, encoded),
			text,
		};
	} catch {
		return {
			encoding,
			exact: false,
			text: undefined,
		};
	}
}

async function detectSiglusEncoding(uri: vscode.Uri): Promise<(typeof SIGLUS_ENCODINGS)[number]> {
	const bytes = await vscode.workspace.fs.readFile(uri);
	const hadBom =
		bytes.byteLength >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf;
	const shiftJis = await decodeCandidate(bytes, 'shiftjis');
	const utf8 = await decodeCandidate(bytes, hadBom ? 'utf8bom' : 'utf8');
	if (hadBom && utf8.text !== undefined) {
		return utf8.encoding;
	}
	if (shiftJis.exact && !utf8.exact) {
		return shiftJis.encoding;
	}
	if (utf8.exact && !shiftJis.exact) {
		return utf8.encoding;
	}
	if (shiftJis.exact && utf8.exact) {
		return shiftJis.encoding;
	}
	if (shiftJis.text === undefined) {
		return utf8.text === undefined ? 'shiftjis' : utf8.encoding;
	}
	if (utf8.text === undefined) {
		return shiftJis.encoding;
	}
	return suspiciousTextScore(shiftJis.text) <= suspiciousTextScore(utf8.text)
		? shiftJis.encoding
		: utf8.encoding;
}

async function ensureSiglusEncoding(document: vscode.TextDocument): Promise<void> {
	if (!isSiglusDocument(document) || document.isDirty) {
		return;
	}
	const key = document.uri.toString();
	if (siglusEncodingJobs.has(key)) {
		return siglusEncodingJobs.get(key);
	}
	const job = (async () => {
		const desiredEncoding = await detectSiglusEncoding(document.uri);
		const liveDocument = vscode.workspace.textDocuments.find(
			(item) => item.uri.toString() === key,
		);
		if (!liveDocument || liveDocument.isDirty || liveDocument.encoding === desiredEncoding) {
			return;
		}
		await vscode.workspace.openTextDocument(liveDocument.uri, { encoding: desiredEncoding });
	})().finally(() => {
		siglusEncodingJobs.delete(key);
	});
	siglusEncodingJobs.set(key, job);
	return job;
}

async function startLanguageClient(): Promise<void> {
	const { LanguageClient } = await import('vscode-languageclient/node');
	const outputChannel = getServerOutputChannel();
	const settings = getSettings();
	setLanguageServerStatus(
		'$(sync~spin) SiglusSS LSP',
		'Starting SiglusSS language server...',
	);
	const commandSpec = resolveCommandSpec(settings.configuredPath);
	setLanguageServerStatus(
		'$(sync~spin) SiglusSS LSP',
		`Checking ${commandLabel(commandSpec.command, [...commandSpec.args, '-lsp'])}`,
	);
	await ensureLanguageServerCommandAvailable(commandSpec);
	const serverOptions: ServerOptions = {
		command: commandSpec.command,
		args: [...commandSpec.args, '-lsp', ...settings.serverExtraArgs],
		options: commandSpec.cwd ? { cwd: commandSpec.cwd } : undefined,
	};
	const clientOptions: LanguageClientOptions = {
		documentSelector: [{ scheme: 'file', language: 'siglusss' }],
		outputChannel,
		middleware: {
			async sendRequest(type, params, token, next) {
				const method = requestMethodName(type);
				if (!canAttachWorkDoneToken(method, params)) {
					return next(type, params, token);
				}
				const workDoneToken = nextLspProgressToken(method);
				registerLspNotificationProgress(workDoneToken);
				try {
					return await next(type, { ...params, workDoneToken }, token);
				} finally {
					setTimeout(() => finishLspNotificationProgress(workDoneToken), 1000);
				}
			},
		},
		synchronize: {
			configurationSection: 'siglusSS',
		},
	};
	client = new LanguageClient(
		'siglusSS',
		'SiglusSS Language Server',
		serverOptions,
		clientOptions,
	);
	setLanguageServerStatus(
		'$(sync~spin) SiglusSS LSP',
		'Connecting to SiglusSS language server...',
	);
	await client.start();
	setLanguageServerStatus(
		'$(check) SiglusSS LSP',
		'SiglusSS language server is running. Click to restart.',
	);
	setTimeout(() => hideLanguageServerStatus(), 4000);
}

async function stopLanguageClient(): Promise<void> {
	const current = client;
	client = undefined;
	clearLspNotificationProgress();
	setLanguageServerStatus(
		'$(sync~spin) SiglusSS LSP',
		'Stopping SiglusSS language server...',
	);
	if (current) {
		await current.stop();
	}
	hideLanguageServerStatus();
}

function toErrorMessage(error: unknown): string {
	if (error instanceof Error) {
		return error.message;
	}
	return String(error);
}

function isMissingCommandError(error: unknown): boolean {
	const message = toErrorMessage(error);
	return (
		/\bENOENT\b/i.test(message) ||
		/\bnot recognized\b/i.test(message) ||
		/\bcommand not found\b/i.test(message) ||
		/\bnot found\b/i.test(message) ||
		/\bno such file or directory\b/i.test(message) ||
		/\bfailed to spawn\b/i.test(message)
	);
}

function isMissingLanguageClientModuleError(error: unknown): boolean {
	const message = toErrorMessage(error);
	return /Cannot find module ['"]vscode-languageclient\/node['"]/i.test(message);
}

function isCancellationError(error: unknown): boolean {
	return /\bcancelled\b/i.test(toErrorMessage(error));
}

function configurationTarget(): vscode.ConfigurationTarget {
	return primaryWorkspaceFolder()
		? vscode.ConfigurationTarget.Workspace
		: vscode.ConfigurationTarget.Global;
}

function commandLabel(command: string, args: string[]): string {
	return [command, ...args].join(' ');
}

function delay(milliseconds: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function lspProgressTokenKey(token: ProgressToken): string {
	return typeof token === 'string' ? `s:${token}` : `n:${token}`;
}

function nextLspProgressToken(method: string): ProgressToken {
	lspProgressTokenCounter += 1;
	return `siglusSS:${method}:${Date.now()}:${lspProgressTokenCounter}`;
}

function requestMethodName(type: unknown): string {
	if (typeof type === 'string') {
		return type;
	}
	if (type && typeof type === 'object' && 'method' in type) {
		const method = (type as { method?: unknown }).method;
		return typeof method === 'string' ? method : '';
	}
	return '';
}

function canAttachWorkDoneToken(method: string, params: unknown): params is Record<string, unknown> {
	return (
		LSP_PROGRESS_REQUEST_METHODS.has(method) &&
		params !== null &&
		typeof params === 'object' &&
		!Array.isArray(params) &&
		!Object.prototype.hasOwnProperty.call(params, 'workDoneToken')
	);
}

function createLspNotificationProgress(token: ProgressToken, params: WorkDoneProgressBegin): void {
	const key = lspProgressTokenKey(token);
	const existing = lspProgressStates.get(key);
	if (existing) {
		finishLspNotificationProgress(token);
	}
	const state: LspNotificationProgressState = {
		closed: false,
		reportedPercentage: 0,
		pending: [params],
	};
	lspProgressStates.set(key, state);
	void Promise.resolve(
		vscode.window.withProgress(
			{
				location: vscode.ProgressLocation.Notification,
				title: params.title || 'SiglusSS',
				cancellable: false,
			},
			async (progress) => {
				state.progress = progress;
				for (const item of state.pending.splice(0)) {
					reportLspNotificationProgress(state, item);
				}
				if (state.closed) {
					return;
				}
				await new Promise<void>((resolve) => {
					state.resolve = resolve;
					if (state.closed) {
						resolve();
					}
				});
			},
		),
	)
		.finally(() => {
			lspProgressStates.delete(key);
		});
}

function reportLspNotificationProgress(
	state: LspNotificationProgressState,
	params: LspWorkDoneProgress,
): void {
	if (!state.progress) {
		state.pending.push(params);
		return;
	}
	if (params.kind === 'end') {
		if (params.message) {
			state.progress.report({ message: params.message });
		}
		return;
	}
	const message = params.message;
	if (typeof params.percentage === 'number') {
		const percentage = Math.max(0, Math.min(100, params.percentage));
		const increment = Math.max(0, percentage - state.reportedPercentage);
		state.reportedPercentage += increment;
		state.progress.report({ message, increment });
		return;
	}
	state.progress.report({ message });
}

function handleLspNotificationProgress(
	token: ProgressToken,
	params: LspWorkDoneProgress,
): void {
	if (params.kind === 'begin') {
		createLspNotificationProgress(token, params);
		return;
	}
	const state = lspProgressStates.get(lspProgressTokenKey(token));
	if (!state) {
		return;
	}
	reportLspNotificationProgress(state, params);
	if (params.kind === 'end') {
		finishLspNotificationProgress(token);
	}
}

function finishLspNotificationProgress(token: ProgressToken): void {
	const key = lspProgressTokenKey(token);
	const state = lspProgressStates.get(key);
	if (state && !state.closed) {
		state.closed = true;
		state.resolve?.();
	}
	lspProgressDisposables.get(key)?.dispose();
	lspProgressDisposables.delete(key);
}

function registerLspNotificationProgress(token: ProgressToken): void {
	if (!client) {
		return;
	}
	const key = lspProgressTokenKey(token);
	lspProgressDisposables.get(key)?.dispose();
	lspProgressDisposables.set(
		key,
		client.onProgress(WorkDoneProgress.type, token, (params) => {
			handleLspNotificationProgress(token, params);
		}),
	);
}

function clearLspNotificationProgress(): void {
	for (const key of [...lspProgressDisposables.keys()]) {
		const token = key.slice(2);
		finishLspNotificationProgress(key.startsWith('n:') ? Number(token) : token);
	}
}

async function runProcess(
	command: string,
	args: string[],
	options: RunProcessOptions = {},
): Promise<string> {
	const outputChannel = options.outputChannel ?? getServerOutputChannel();
	const label = commandLabel(command, args);
	outputChannel.appendLine('');
	outputChannel.appendLine(`> ${label}`);
	return new Promise<string>((resolve, reject) => {
		let output = '';
		let finished = false;
		let cancellationDisposable: vscode.Disposable | undefined;
		const child = spawn(command, args, {
			cwd: options.cwd,
			windowsHide: true,
		});
		const finish = (callback: () => void) => {
			if (finished) {
				return;
			}
			finished = true;
			cancellationDisposable?.dispose();
			callback();
		};
		const cancel = () => {
			finish(() => {
				child.kill();
				reject(new Error(`${label} was cancelled.`));
			});
		};
		if (options.token?.isCancellationRequested) {
			cancel();
			return;
		}
		cancellationDisposable = options.token?.onCancellationRequested(cancel);
		child.stdout.on('data', (chunk: Buffer) => {
			const text = chunk.toString('utf8');
			output += text;
			outputChannel.append(text);
		});
		child.stderr.on('data', (chunk: Buffer) => {
			const text = chunk.toString('utf8');
			output += text;
			outputChannel.append(text);
		});
		child.on('error', (error) => {
			finish(() => reject(error));
		});
		child.on('close', (code) => {
			finish(() => {
				if (code === 0) {
					resolve(output);
					return;
				}
				const detail = output.trim();
				reject(
					new Error(
						`${label} exited with code ${code ?? 'unknown'}${detail ? `: ${detail}` : '.'}`,
					),
				);
			});
		});
	});
}

async function installSiglusSsuPackage(
	reportProgress: InstallProgressReporter,
	token: vscode.CancellationToken,
	outputChannel: vscode.OutputChannel,
): Promise<string> {
	const args = ['-m', 'pip', 'install', '-U', 'siglus-ssu'];
	reportProgress('Installing package...', 5);
	try {
		await runProcess('python', args, { outputChannel, token });
		return 'python';
	} catch (error) {
		if (!isMissingCommandError(error)) {
			throw error;
		}
		reportProgress('python was not found, trying python3...');
		await runProcess('python3', args, { outputChannel, token });
		return 'python3';
	}
}

async function resolvePythonConsoleScript(
	pythonCommand: string,
	scriptName: string,
	token: vscode.CancellationToken,
	outputChannel: vscode.OutputChannel,
): Promise<string | undefined> {
	const code = [
		'import os, sys, sysconfig',
		`name = ${JSON.stringify(scriptName)}`,
		'if sys.platform == "win32":',
		'    name += ".exe"',
		'print(os.path.join(sysconfig.get_path("scripts"), name))',
	].join('\n');
	const output = await runProcess(pythonCommand, ['-c', code], { outputChannel, token });
	const scriptPath = output.trim().split(/\r?\n/).pop()?.trim();
	return scriptPath || undefined;
}

async function runSiglusSsuInit(
	pythonCommand: string,
	reportProgress: InstallProgressReporter,
	token: vscode.CancellationToken,
	outputChannel: vscode.OutputChannel,
): Promise<void> {
	reportProgress('Locating siglus-ssu...', 55);
	const installedScriptPath = await resolvePythonConsoleScript(
		pythonCommand,
		'siglus-ssu',
		token,
		outputChannel,
	);
	const initCandidates: CommandSpec[] = [];
	if (installedScriptPath && existsSync(installedScriptPath)) {
		initCandidates.push({ command: installedScriptPath, args: [] });
	}
	initCandidates.push({ command: 'siglus-ssu', args: [] });
	reportProgress('Running init --force...', 10);
	let lastError: unknown;
	for (const candidate of initCandidates) {
		try {
			await runProcess(candidate.command, [...candidate.args, 'init', '--force'], {
				outputChannel,
				token,
			});
			if (candidate.command !== 'siglus-ssu' && getSettings().configuredPath === 'siglus-ssu') {
				await vscode.workspace
					.getConfiguration('siglusSS')
					.update('siglusSsuPath', candidate.command, configurationTarget());
			}
			return;
		} catch (error) {
			lastError = error;
			if (!isMissingCommandError(error)) {
				throw error;
			}
		}
	}
	throw lastError instanceof Error ? lastError : new Error('Failed to run siglus-ssu init --force.');
}

async function ensureLanguageServerCommandAvailable(commandSpec: CommandSpec): Promise<void> {
	const args = [...commandSpec.args, '--version'];
	const label = [commandSpec.command, ...args].join(' ');
	await new Promise<void>((resolve, reject) => {
		let output = '';
		let finished = false;
		const child = spawn(commandSpec.command, args, {
			cwd: commandSpec.cwd,
			windowsHide: true,
		});
		const timer = setTimeout(() => {
			if (finished) {
				return;
			}
			finished = true;
			child.kill();
			reject(new Error(`Timed out while checking ${label}.`));
		}, 10000);
		const finish = (callback: () => void) => {
			if (finished) {
				return;
			}
			finished = true;
			clearTimeout(timer);
			callback();
		};
		child.stdout.on('data', (chunk: Buffer) => {
			output += chunk.toString('utf8');
		});
		child.stderr.on('data', (chunk: Buffer) => {
			output += chunk.toString('utf8');
		});
		child.on('error', (error: NodeJS.ErrnoException) => {
			finish(() => {
				if (error.code === 'ENOENT') {
					reject(new MissingSiglusSsuError(`${label} was not found.`));
					return;
				}
				reject(error);
			});
		});
		child.on('close', (code) => {
			finish(() => {
				if (code === 0) {
					resolve();
					return;
				}
				const detail = output.trim();
				const message = `${label} exited with code ${code ?? 'unknown'}${detail ? `: ${detail}` : '.'}`;
				if (isMissingCommandError(message)) {
					reject(new MissingSiglusSsuError(message));
					return;
				}
				reject(new Error(message));
			});
		});
	});
}

function parseSiglusSsuVersion(output: string): string | undefined {
	const match = output.match(
		/\bsiglus-ssu(?:\.exe)?\s+([0-9]+(?:\.[0-9]+){1,3}(?:[-+][^\s]+)?)/i,
	);
	return match?.[1];
}

function versionParts(version: string): number[] {
	return version
		.split(/[.+-]/)
		.slice(0, 4)
		.map((part) => {
			const match = part.match(/^\d+/);
			return match ? Number(match[0]) : 0;
		});
}

function compareVersions(left: string, right: string): number {
	const leftParts = versionParts(left);
	const rightParts = versionParts(right);
	const count = Math.max(leftParts.length, rightParts.length);
	for (let index = 0; index < count; index += 1) {
		const diff = (leftParts[index] ?? 0) - (rightParts[index] ?? 0);
		if (diff !== 0) {
			return diff;
		}
	}
	return 0;
}

function isSiglusSsuAutoUpdateTarget(
	settings: ExtensionSettings,
	commandSpec: CommandSpec,
): boolean {
	if (!settings.autoUpdateSiglusSsu || commandSpec.cwd) {
		return false;
	}
	const configuredPath = stripWrappingQuotes(settings.configuredPath);
	if (!configuredPath || configuredPath === 'siglus-ssu') {
		return true;
	}
	return /^siglus-ssu(?:\.exe)?$/i.test(path.basename(commandSpec.command));
}

function fetchText(url: string): Promise<string> {
	return new Promise((resolve, reject) => {
		const request = https.get(
			url,
			{
				headers: {
					'User-Agent': 'siglus-ssu-vscode',
				},
			},
			(response) => {
				if ((response.statusCode ?? 0) < 200 || (response.statusCode ?? 0) >= 300) {
					response.resume();
					reject(
						new Error(`HTTP ${response.statusCode ?? 'unknown'} while requesting ${url}`),
					);
					return;
				}
				let data = '';
				response.setEncoding('utf8');
				response.on('data', (chunk: string) => {
					data += chunk;
				});
				response.on('end', () => resolve(data));
			},
		);
		request.setTimeout(10000, () => {
			request.destroy(new Error(`Timed out while requesting ${url}`));
		});
		request.on('error', reject);
	});
}

async function fetchLatestSiglusSsuVersion(): Promise<string | undefined> {
	const text = await fetchText('https://pypi.org/pypi/siglus-ssu/json');
	const data = JSON.parse(text) as { info?: { version?: unknown } };
	return typeof data.info?.version === 'string' ? data.info.version : undefined;
}

async function checkSiglusSsuUpdateWithProgress(context: vscode.ExtensionContext): Promise<void> {
	if (siglusSsuUpdateCheckJob) {
		return siglusSsuUpdateCheckJob;
	}
	siglusSsuUpdateCheckJob = (async () => {
		const settings = getSettings();
		const commandSpec = resolveCommandSpec(settings.configuredPath);
		if (!isSiglusSsuAutoUpdateTarget(settings, commandSpec)) {
			return;
		}
		try {
			setLanguageServerStatus(
				'$(sync~spin) SiglusSS update',
				'Checking for siglus-ssu updates...',
			);
			const versionOutput = await runProcess(
				commandSpec.command,
				[...commandSpec.args, '--version'],
				{
					cwd: commandSpec.cwd,
					outputChannel: getServerOutputChannel(),
				},
			);
			const currentVersion = parseSiglusSsuVersion(versionOutput);
			if (!currentVersion) {
				return;
			}
			const latestVersion = await fetchLatestSiglusSsuVersion();
			if (!latestVersion || compareVersions(latestVersion, currentVersion) <= 0) {
				return;
			}
			if (context.globalState.get<string>(SKIPPED_SIGLUS_SSU_VERSION_KEY) === latestVersion) {
				return;
			}
			const action = await vscode.window.showInformationMessage(
				`siglus-ssu ${latestVersion} is available. Current version: ${currentVersion}.`,
				'Update siglus-ssu',
				'Skip this version',
			);
			if (action === 'Update siglus-ssu') {
				await installSiglusSsuWithProgress();
			} else if (action === 'Skip this version') {
				await context.globalState.update(SKIPPED_SIGLUS_SSU_VERSION_KEY, latestVersion);
			}
		} catch (error) {
			getServerOutputChannel().appendLine(
				`siglus-ssu update check failed: ${toErrorMessage(error)}`,
			);
		} finally {
			hideLanguageServerStatus();
		}
	})().finally(() => {
		siglusSsuUpdateCheckJob = undefined;
	});
	return siglusSsuUpdateCheckJob;
}

function scheduleSiglusSsuUpdateCheck(context: vscode.ExtensionContext): void {
	if (siglusSsuUpdateCheckJob || siglusSsuUpdateCheckScheduled) {
		return;
	}
	siglusSsuUpdateCheckScheduled = true;
	setTimeout(() => {
		siglusSsuUpdateCheckScheduled = false;
		void checkSiglusSsuUpdateWithProgress(context);
	}, 5000);
}

async function promptForSiglusSsuPath(): Promise<void> {
	const current = getSettings().configuredPath;
	const value = await vscode.window.showInputBox({
		title: 'SiglusSS Path',
		prompt: 'Enter the siglus-ssu executable path, or a uv project root directory.',
		value: current,
		ignoreFocusOut: true,
	});
	if (!value) {
		return;
	}
	await vscode.workspace
		.getConfiguration('siglusSS')
		.update('siglusSsuPath', value.trim(), configurationTarget());
}

async function installSiglusSsuWithProgress(): Promise<void> {
	if (installSiglusSsuJob) {
		return installSiglusSsuJob;
	}
	const outputChannel = getServerOutputChannel();
	const statusBarItem = vscode.window.createStatusBarItem(
		'siglusSS.setup',
		vscode.StatusBarAlignment.Left,
		100,
	);
	statusBarItem.name = 'SiglusSS Setup';
	statusBarItem.tooltip = 'Setting up siglus-ssu';
	installSiglusSsuJob = (async () => {
		try {
			isInstallingSiglusSsu = true;
			statusBarItem.text = '$(sync~spin) Setting up siglus-ssu';
			statusBarItem.show();
			await vscode.window.withProgress(
				{
					location: vscode.ProgressLocation.Notification,
					title: 'Setting up siglus-ssu',
					cancellable: true,
				},
				async (progress, token) => {
					const reportProgress: InstallProgressReporter = (message, increment) => {
						statusBarItem.text = `$(sync~spin) ${message}`;
						statusBarItem.tooltip = `SiglusSS setup: ${message}`;
						progress.report({ message, increment });
					};
					reportProgress('Starting setup...', 0);
					await delay(250);
					const pythonCommand = await installSiglusSsuPackage(
						reportProgress,
						token,
						outputChannel,
					);
					if (token.isCancellationRequested) {
						throw new Error('SiglusSS setup was cancelled.');
					}
					await runSiglusSsuInit(pythonCommand, reportProgress, token, outputChannel);
					if (token.isCancellationRequested) {
						throw new Error('SiglusSS setup was cancelled.');
					}
					reportProgress('Restarting language server...', 25);
					await stopLanguageClient();
					await startLanguageClient();
					reportProgress('Ready.', 5);
				},
			);
			void vscode.window.showInformationMessage(
				'siglus-ssu installed, initialized, and the language server was restarted.',
			);
		} catch (error) {
			if (isCancellationError(error)) {
				void vscode.window.showWarningMessage('SiglusSS setup cancelled.');
				return;
			}
			outputChannel.show(true);
			void vscode.window.showErrorMessage(
				`Failed to install and initialize siglus-ssu. ${toErrorMessage(error)}`,
			);
		} finally {
			isInstallingSiglusSsu = false;
			statusBarItem.dispose();
		}
	})().finally(() => {
		installSiglusSsuJob = undefined;
	});
	return installSiglusSsuJob;
}

function scheduleSiglusSsuInstallWithProgress(): void {
	if (installSiglusSsuJob || installSiglusSsuScheduled) {
		return;
	}
	installSiglusSsuScheduled = true;
	setTimeout(() => {
		installSiglusSsuScheduled = false;
		void installSiglusSsuWithProgress();
	}, 0);
}

async function handleLanguageServerStartError(error: unknown): Promise<void> {
	setLanguageServerStatus(
		'$(error) SiglusSS LSP',
		`SiglusSS language server failed to start: ${toErrorMessage(error)}`,
	);
	setTimeout(() => hideLanguageServerStatus(), 8000);
	if (isMissingLanguageClientModuleError(error)) {
		serverOutput?.show(true);
		void vscode.window.showErrorMessage(
			'SiglusSS extension package is missing the vscode-languageclient runtime. Reinstall or update the VSIX.',
		);
		return;
	}
	if (!(error instanceof MissingSiglusSsuError) && !isMissingCommandError(error)) {
		serverOutput?.show(true);
		void vscode.window.showErrorMessage(
			`Failed to start SiglusSS language server. Check siglusSS.siglusSsuPath. ${toErrorMessage(error)}`,
		);
		return;
	}
	const action = await vscode.window.showErrorMessage(
		'siglus-ssu is not installed or is not available from the configured path.',
		'Install siglus-ssu',
		'Set Path',
	);
	if (action === 'Install siglus-ssu') {
		scheduleSiglusSsuInstallWithProgress();
		return;
	}
	if (action === 'Set Path') {
		await promptForSiglusSsuPath();
	}
}

async function restartLanguageClient(): Promise<void> {
	try {
		await stopLanguageClient();
		await startLanguageClient();
		void vscode.window.showInformationMessage('SiglusSS language server restarted.');
	} catch (error) {
		await handleLanguageServerStartError(error);
	}
}

export async function activate(context: vscode.ExtensionContext): Promise<void> {
	context.subscriptions.push(getServerOutputChannel());
	context.subscriptions.push(getLanguageServerStatusItem());
	context.subscriptions.push(
		vscode.workspace.onDidOpenTextDocument((document) => {
			void ensureSiglusEncoding(document);
		}),
	);
	context.subscriptions.push(
		vscode.commands.registerCommand('siglusSS.restartLanguageServer', restartLanguageClient),
	);
	context.subscriptions.push(
		vscode.workspace.onDidChangeConfiguration((event) => {
			if (
				isInstallingSiglusSsu &&
				event.affectsConfiguration('siglusSS.siglusSsuPath')
			) {
				return;
			}
			if (
				event.affectsConfiguration('siglusSS.siglusSsuPath') ||
				event.affectsConfiguration('siglusSS.serverExtraArgs')
			) {
				void restartLanguageClient();
			}
		}),
	);
	for (const document of vscode.workspace.textDocuments) {
		void ensureSiglusEncoding(document);
	}
	try {
		await startLanguageClient();
		scheduleSiglusSsuUpdateCheck(context);
	} catch (error) {
		await handleLanguageServerStartError(error);
	}
}

export async function deactivate(): Promise<void> {
	await stopLanguageClient();
}
