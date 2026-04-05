import { existsSync, statSync } from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as vscode from 'vscode';
import {
	type LanguageClient,
	type LanguageClientOptions,
	type ServerOptions,
} from 'vscode-languageclient/node';

let client: LanguageClient | undefined;
let serverOutput: vscode.OutputChannel | undefined;
const siglusEncodingJobs = new Map<string, Promise<void>>();
const siglusScanJobs = new Map<string, ScanProgressEntry>();
const SIGLUS_ENCODINGS = ['shiftjis', 'utf8bom', 'utf8'] as const;

type ExtensionSettings = {
	configuredPath: string;
	serverExtraArgs: string[];
};

type CommandSpec = {
	command: string;
	args: string[];
	cwd?: string;
};

type DecodedCandidate = {
	encoding: (typeof SIGLUS_ENCODINGS)[number];
	exact: boolean;
	text: string | undefined;
};

type ScanStatusParams = {
	phase: 'begin' | 'report' | 'end';
	kind: string;
	directory: string;
	title: string;
	current: number;
	total: number;
	message?: string;
};

type ScanProgressEntry = {
	report: (value: { message?: string; increment?: number }) => void;
	resolve: () => void;
	lastPercent: number;
	pending: Array<{ message?: string; increment?: number }>;
};

function getServerOutputChannel(): vscode.OutputChannel {
	if (!serverOutput) {
		serverOutput = vscode.window.createOutputChannel('SiglusSS Language Server');
	}
	return serverOutput;
}

function getSettings(): ExtensionSettings {
	const config = vscode.workspace.getConfiguration('siglusSS');
	return {
		configuredPath: (config.get<string>('siglusSsuPath') || 'siglus-ssu').trim() || 'siglus-ssu',
		serverExtraArgs: normalizeStringArray(config.get<unknown>('serverExtraArgs')),
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

function scanProgressKey(params: ScanStatusParams): string {
	return `${params.kind}:${params.directory}`;
}

function beginScanProgress(params: ScanStatusParams): void {
	const key = scanProgressKey(params);
	if (siglusScanJobs.has(key)) {
		return;
	}
	let resolveProgress!: () => void;
	const entry: ScanProgressEntry = {
		report: (value) => {
			entry.pending.push(value);
		},
		resolve: () => {
			resolveProgress();
		},
		lastPercent: 0,
		pending: params.message ? [{ message: params.message }] : [],
	};
	siglusScanJobs.set(key, entry);
	const done = new Promise<void>((resolve) => {
		resolveProgress = resolve;
	});
	void vscode.window.withProgress(
		{
			location: vscode.ProgressLocation.Notification,
			title: params.title,
			cancellable: false,
		},
		async (progress) => {
			entry.report = (value) => {
				progress.report(value);
			};
			for (const value of entry.pending) {
				progress.report(value);
			}
			entry.pending = [];
			try {
				await done;
			} finally {
				siglusScanJobs.delete(key);
			}
		},
	);
}

function reportScanProgress(params: ScanStatusParams): void {
	const entry = siglusScanJobs.get(scanProgressKey(params));
	if (!entry) {
		beginScanProgress(params);
		return;
	}
	const nextPercent =
		params.total > 0 ? Math.min(100, Math.round((params.current / params.total) * 100)) : 100;
	const increment = Math.max(0, nextPercent - entry.lastPercent);
	entry.lastPercent = nextPercent;
	entry.report({
		message: params.message,
		increment,
	});
}

function endScanProgress(params: ScanStatusParams): void {
	const entry = siglusScanJobs.get(scanProgressKey(params));
	if (!entry) {
		return;
	}
	if (params.total > 0) {
		const nextPercent = Math.min(100, Math.round((params.current / params.total) * 100));
		const increment = Math.max(0, nextPercent - entry.lastPercent);
		entry.lastPercent = nextPercent;
		entry.report({
			message: params.message,
			increment,
		});
	}
	entry.resolve();
}

async function startLanguageClient(): Promise<void> {
	const { LanguageClient } = await import('vscode-languageclient/node');
	const outputChannel = getServerOutputChannel();
	const settings = getSettings();
	const commandSpec = resolveCommandSpec(settings.configuredPath);
	const serverOptions: ServerOptions = {
		command: commandSpec.command,
		args: [...commandSpec.args, '-lsp', ...settings.serverExtraArgs],
		options: commandSpec.cwd ? { cwd: commandSpec.cwd } : undefined,
	};
	const clientOptions: LanguageClientOptions = {
		documentSelector: [{ scheme: 'file', language: 'siglusss' }],
		outputChannel,
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
	client.onNotification('siglusSS/scanStatus', (params: ScanStatusParams) => {
		if (params.phase === 'begin') {
			beginScanProgress(params);
			return;
		}
		if (params.phase === 'report') {
			reportScanProgress(params);
			return;
		}
		endScanProgress(params);
	});
	await client.start();
}

async function stopLanguageClient(): Promise<void> {
	const current = client;
	client = undefined;
	for (const entry of siglusScanJobs.values()) {
		entry.resolve();
	}
	siglusScanJobs.clear();
	if (current) {
		await current.stop();
	}
}

function toErrorMessage(error: unknown): string {
	if (error instanceof Error) {
		return error.message;
	}
	return String(error);
}

function isMissingCommandError(error: unknown): boolean {
	const message = toErrorMessage(error);
	return /\bENOENT\b/i.test(message) || /\bnot recognized\b/i.test(message);
}

function isMissingLanguageClientModuleError(error: unknown): boolean {
	const message = toErrorMessage(error);
	return /Cannot find module ['"]vscode-languageclient\/node['"]/i.test(message);
}

function configurationTarget(): vscode.ConfigurationTarget {
	return primaryWorkspaceFolder()
		? vscode.ConfigurationTarget.Workspace
		: vscode.ConfigurationTarget.Global;
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

function openSiglusSsuInstallTerminal(): void {
	const terminal = vscode.window.createTerminal('SiglusSS Setup');
	terminal.show(true);
	terminal.sendText('python -m pip install -U siglus-ssu', true);
}

async function handleLanguageServerStartError(error: unknown): Promise<void> {
	serverOutput?.show(true);
	if (isMissingLanguageClientModuleError(error)) {
		void vscode.window.showErrorMessage(
			'SiglusSS extension package is missing the vscode-languageclient runtime. Reinstall or update the VSIX.',
		);
		return;
	}
	if (!isMissingCommandError(error)) {
		void vscode.window.showErrorMessage(
			`Failed to start SiglusSS language server. Check siglusSS.siglusSsuPath. ${toErrorMessage(error)}`,
		);
		return;
	}
	const action = await vscode.window.showErrorMessage(
		'SiglusSS language server could not start because the configured command was not found.',
		'Set Path',
		'Install With Pip',
	);
	if (action === 'Set Path') {
		await promptForSiglusSsuPath();
		return;
	}
	if (action === 'Install With Pip') {
		openSiglusSsuInstallTerminal();
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
	} catch (error) {
		await handleLanguageServerStartError(error);
	}
}

export async function deactivate(): Promise<void> {
	await stopLanguageClient();
}
