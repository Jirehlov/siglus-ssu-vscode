import { spawn } from 'node:child_process';
import { existsSync, statSync } from 'node:fs';
import * as https from 'node:https';
import * as os from 'node:os';
import * as path from 'node:path';
import * as vscode from 'vscode';
import { parseConstProfileCatalog, resolveConstProfile, type ConstProfileCatalog } from './constProfiles';
import {
	LanguageClient,
	type LanguageClientOptions,
	type ServerOptions,
	State,
	type Range as ProtocolRange,
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
const siglusEncodingJobs = new Map<string, Promise<void>>();
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
let constProfileStatusItem: vscode.StatusBarItem | undefined;
let languageClientOperation: Promise<void> = Promise.resolve();
let languageServerGeneration = 0;
let isDeactivating = false;
let languageServerState: 'stopped' | 'starting' | 'running' | 'error' = 'stopped';
let runningConstProfile: number | undefined;
let runningCommandKey: string | undefined;
let constProfileCatalog: { commandKey: string; value: ConstProfileCatalog } | undefined;
let constProfilePickerJob: Promise<void> | undefined;
let loadingConstProfiles = false;
let readFlagController: ReadFlagController | undefined;

type ExtensionSettings = {
	configuredPath: string;
	serverExtraArgs: string[];
	constProfile: number | undefined;
	readFlagsMode: boolean;
	readSavPath: string;
	autoUpdateSiglusSsu: boolean;
};

type CommandSpec = {
	command: string;
	args: string[];
	cwd?: string;
};

type RunProcessOptions = {
	cwd?: string;
	token?: vscode.CancellationToken;
	stdoutOnly?: boolean;
	timeoutMs?: number;
	acceptedExitCodes?: readonly number[];
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

type SiglusEncoding = 'shiftjis' | 'utf8bom' | 'utf8';

type DecodedCandidate = {
	encoding: SiglusEncoding;
	exact: boolean;
	text: string | undefined;
};

type FlagItem = { index: number; read: boolean; ranges: ProtocolRange[] };

type ReadFlagReport = {
	uri: string;
	version: number | null;
	status: string;
	message?: string;
	flagCount?: number | null;
	savedFlagCount?: number | null;
	readCount?: number | null;
	unreadCount?: number | null;
	mappingId?: string;
	saveRevision?: string;
	states?: string;
	items: FlagItem[];
};

type FlagBoundary = { offset: number; position: vscode.Position; total: number; read: number };
type FlagFragment = { flag: FlagItem; range: vscode.Range; start: FlagBoundary; end: FlagBoundary };
type UnreadNavigation = 'first' | 'previous' | 'next' | 'last';

function partitionPoint<T>(items: readonly T[], before: (item: T) => boolean): number {
	let low = 0;
	let high = items.length;
	while (low < high) {
		const middle = Math.floor((low + high) / 2);
		if (before(items[middle])) {
			low = middle + 1;
		} else {
			high = middle;
		}
	}
	return low;
}

class ReadFlagIndex {
	private readonly fragments: FlagFragment[] = [];
	private readonly byFlag: FlagFragment[][];
	private readonly maxEnds: number[] = [];
	private readonly boundaries: FlagBoundary[];
	private unread: FlagFragment[] = [];
	firstUnread?: FlagItem;
	lastUnread?: FlagItem;
	decorations: vscode.Range[][] = [[], [], []];

	constructor(private readonly items: FlagItem[], document: vscode.TextDocument, languageClient: LanguageClient) {
		const events = new Map<number, FlagBoundary>();
		const boundary = (position: vscode.Position): FlagBoundary => {
			const offset = document.offsetAt(position);
			let event = events.get(offset);
			if (!event) {
				event = { offset, position, total: 0, read: 0 };
				events.set(offset, event);
			}
			return event;
		};
		this.byFlag = items.map(() => []);
		for (const flag of items) {
			for (const location of flag.ranges) {
				const range = languageClient.protocol2CodeConverter.asRange(location);
				if (range.isEmpty) {
					continue;
				}
				const start = boundary(range.start);
				const end = boundary(range.end);
				start.total++;
				end.total--;
				if (flag.read) {
					start.read++;
					end.read--;
				}
				this.fragments.push({ flag, range, start, end });
			}
		}
		this.fragments.sort((a, b) => a.start.offset - b.start.offset || a.flag.index - b.flag.index);
		let maxEnd = 0;
		for (const fragment of this.fragments) {
			this.byFlag[fragment.flag.index].push(fragment);
			maxEnd = Math.max(maxEnd, fragment.end.offset);
			this.maxEnds.push(maxEnd);
		}
		this.boundaries = [...events.values()].sort((a, b) => a.offset - b.offset);
		this.rebuild();
	}

	private rebuild(): void {
		this.firstUnread = undefined;
		this.lastUnread = undefined;
		for (const flag of this.items) {
			if (!flag.read) {
				this.firstUnread ??= flag;
				this.lastUnread = flag;
			}
		}
		this.unread = this.fragments.filter(({ flag }) => !flag.read);
		const ranges: vscode.Range[][] = [[], [], []];
		let total = 0;
		let read = 0;
		let state = -1;
		let start: vscode.Position | undefined;
		for (const boundary of this.boundaries) {
			total += boundary.total;
			read += boundary.read;
			const next = total === 0 ? -1 : read === total ? 0 : read === 0 ? 1 : 2;
			if (next !== state) {
				if (start && state >= 0) {
					ranges[state].push(new vscode.Range(start, boundary.position));
				}
				state = next;
				start = boundary.position;
			}
		}
		this.decorations = ranges;
	}

	private change(index: number, read: boolean): boolean {
		const flag = this.items[index];
		if (flag.read === read) {
			return false;
		}
		flag.read = read;
		const delta = read ? 1 : -1;
		for (const { start, end } of this.byFlag[index]) {
			start.read += delta;
			end.read -= delta;
		}
		return true;
	}

	update(states: Buffer | { indices: readonly number[]; read: boolean }): void {
		let changed = false;
		if (Buffer.isBuffer(states)) {
			if (states.length !== this.items.length) {
				throw new Error('The saved flag count changed.');
			}
			for (let i = 0; i < states.length; i++) {
				if (this.change(i, states[i] !== 0)) {
					changed = true;
				}
			}
		} else {
			for (const index of states.indices) {
				if (this.change(index, states.read)) {
					changed = true;
				}
			}
		}
		if (changed) {
			this.rebuild();
		}
	}

	unreadRange(action: UnreadNavigation, cursor: number): vscode.Range | undefined {
		if (action === 'first' || action === 'last') {
			const first = action === 'first';
			const flag = first ? this.firstUnread : this.lastUnread;
			return flag && this.byFlag[flag.index].at(first ? 0 : -1)?.range;
		}
		const previous = action === 'previous';
		const boundary = partitionPoint(this.unread, ({ start }) =>
			previous ? start.offset < cursor : start.offset <= cursor,
		);
		return this.unread[previous ? boundary - 1 : boundary]?.range;
	}

	flagsAt(document: vscode.TextDocument, selections: readonly vscode.Selection[]): FlagItem[] {
		const flags = new Set<FlagItem>();
		for (const selection of selections) {
			const start = document.offsetAt(selection.start);
			const end = document.offsetAt(selection.end);
			const first = partitionPoint(this.maxEnds, (offset) => offset <= start);
			for (let i = first; i < this.fragments.length; i++) {
				const fragment = this.fragments[i];
				if (selection.isEmpty ? fragment.start.offset > start : fragment.start.offset >= end) {
					break;
				}
				if (fragment.end.offset > start) {
					flags.add(fragment.flag);
				}
			}
		}
		return [...flags];
	}
}

type FlagView = { report: ReadFlagReport; index?: ReadFlagIndex };
type FlagJob = {
	verifySave?: boolean;
	timer?: NodeJS.Timeout;
	cancellation: vscode.CancellationTokenSource;
	promise?: Promise<FlagView | undefined>;
};

class ReadFlagController implements vscode.Disposable {
	private readonly decorations = ['read', 'unread', 'mixed'].map((state) =>
		vscode.window.createTextEditorDecorationType({
			backgroundColor: new vscode.ThemeColor(`siglusSS.${state}FlagBackground`),
			rangeBehavior: vscode.DecorationRangeBehavior.ClosedClosed,
		}),
	);
	private readonly status = vscode.window.createStatusBarItem('siglusSS.readFlags', vscode.StatusBarAlignment.Right, 99);
	private modeEnabled = vscode.workspace.getConfiguration('siglusSS').get<boolean>('readFlagsMode') === true;
	private readonly jobs = new Map<string, FlagJob>();
	private readonly views = new Map<string, FlagView>();
	private readonly painted = new WeakMap<vscode.TextEditor, vscode.Range[][]>();
	private readonly subscriptions: vscode.Disposable[];
	private connection: vscode.Disposable[] = [];
	private languageClient: LanguageClient | undefined;
	private savePath = '';
	private canSetReadFlag?: boolean;

	constructor() {
		this.status.name = 'SiglusSS Read Flags';
		this.status.command = 'siglusSS.readFlags';
		this.subscriptions = [
			vscode.window.onDidChangeActiveTextEditor(() => this.syncVisible()),
			vscode.window.onDidChangeVisibleTextEditors(() => this.syncVisible()),
			vscode.window.onDidChangeWindowState((state) => {
				if (state.focused) {
					this.refresh();
				}
			}),
			vscode.workspace.onDidChangeTextDocument((event) => {
				if (event.contentChanges.length > 0) {
					this.sourceChanged(event.document, 250);
				}
			}),
			vscode.workspace.onDidSaveTextDocument((document) => {
				if (this.modeEnabled && isSceneDocument(document) &&
					vscode.window.visibleTextEditors.some((editor) => editor.document === document)) {
					this.refresh(document);
				}
			}),
			vscode.workspace.onDidCloseTextDocument((document) => {
				this.invalidate(document.uri.toString());
				if (this.modeEnabled && document.uri.fsPath.toLowerCase().endsWith('.inc')) {
					this.includeChanged(document.uri, 0);
				}
				this.updateStatus();
			}),
			vscode.workspace.onDidChangeConfiguration((event) => {
				if (event.affectsConfiguration('siglusSS.readFlagsMode') ||
					(this.modeEnabled && event.affectsConfiguration('siglusSS.readSavPath'))) {
					this.modeEnabled = vscode.workspace.getConfiguration('siglusSS').get<boolean>('readFlagsMode') === true;
					this.disconnect();
				}
			}),
		];
		this.updateStatus();
	}

	connect(languageClient: LanguageClient, savePath: string): void {
		this.disconnect();
		this.languageClient = languageClient;
		this.savePath = this.modeEnabled ? savePath : '';
		this.connection.push(languageClient.onDidChangeState((event) => {
			if (event.newState === State.Running) {
				this.refresh();
			} else {
				for (const uri of new Set([...this.jobs.keys(), ...this.views.keys()])) {
					this.invalidate(uri);
				}
				this.updateStatus();
			}
		}));
		if (this.savePath) {
			const watcher = vscode.workspace.createFileSystemWatcher(
				new vscode.RelativePattern(path.dirname(this.savePath), path.basename(this.savePath)),
			);
			const includes = vscode.workspace.createFileSystemWatcher('**/*.[iI][nN][cC]');
			this.connection.push(
				includes,
				includes.onDidChange((uri) => this.includeChanged(uri, 200)),
				includes.onDidCreate((uri) => this.includeChanged(uri, 200)),
				includes.onDidDelete((uri) => this.includeChanged(uri, 200)),
				watcher,
				watcher.onDidChange(() => this.refresh(undefined, 200)),
				watcher.onDidCreate(() => this.refresh(undefined, 200)),
				watcher.onDidDelete(() => this.refresh(undefined, 200)),
			);
		}
		this.refresh();
	}

	disconnect(): void {
		for (const subscription of this.connection) {
			subscription.dispose();
		}
		this.connection = [];
		this.languageClient = undefined;
		this.savePath = '';
		for (const uri of new Set([...this.jobs.keys(), ...this.views.keys()])) {
			this.invalidate(uri);
		}
		this.updateStatus();
	}

	private syncVisible(): void {
		const documents = new Set(vscode.window.visibleTextEditors.map((editor) => editor.document));
		const visible = new Set([...documents].map((document) => document.uri.toString()));
		for (const uri of new Set([...this.jobs.keys(), ...this.views.keys()])) {
			if (!visible.has(uri)) {
				this.invalidate(uri);
			}
		}
		for (const document of documents) {
			const uri = document.uri.toString();
			const view = this.views.get(uri);
			if (view) {
				this.paint(uri, view.index);
			} else {
				this.paint(uri);
				if (!this.jobs.has(uri)) {
					this.refresh(document);
				}
			}
		}
		this.updateStatus();
	}

	private sourceChanged(document: vscode.TextDocument, delay: number): void {
		if (!this.modeEnabled || !isSiglusDocument(document)) {
			return;
		}
		if (document.uri.fsPath.toLowerCase().endsWith('.inc')) {
			this.includeChanged(document.uri, delay);
		} else if (vscode.window.visibleTextEditors.some((editor) => editor.document === document)) {
			this.refresh(document, delay, true);
		}
	}

	private includeChanged(uri: vscode.Uri, delay: number): void {
		const directory = path.dirname(uri.fsPath);
		for (const document of new Set(vscode.window.visibleTextEditors.map((editor) => editor.document))) {
			if (path.relative(directory, path.dirname(document.uri.fsPath)) === '') {
				this.refresh(document, delay, true);
			}
		}
	}

	refresh(document?: vscode.TextDocument, delay = 0, sourceChanged = false, verifySave = false): void {
		if (!document) {
			for (const visible of new Set(vscode.window.visibleTextEditors.map((editor) => editor.document))) {
				this.refresh(visible, delay, false, true);
			}
			this.updateStatus();
			return;
		}
		const uri = document.uri.toString();
		verifySave ||= this.jobs.get(uri)?.verifySave === true;
		if (sourceChanged) {
			this.invalidate(uri);
		} else {
			this.cancelJob(uri);
		}
		if (
			!this.modeEnabled || !this.savePath || !this.languageClient?.isRunning() ||
			this.languageClient.initializeResult?.capabilities.experimental?.siglusReadFlags?.version !== 1 ||
			!isSceneDocument(document)
		) {
			return;
		}
		const job: FlagJob = { cancellation: new vscode.CancellationTokenSource(), verifySave };
		this.jobs.set(uri, job);
		job.timer = setTimeout(() => { void this.currentReport(document); }, delay);
	}

	private cancelJob(uri: string): void {
		const job = this.jobs.get(uri);
		if (job) {
			clearTimeout(job.timer);
			job.cancellation.cancel();
			job.cancellation.dispose();
			this.jobs.delete(uri);
		}
	}

	private invalidate(uri: string): void {
		this.cancelJob(uri);
		if (this.views.delete(uri)) {
			this.paint(uri);
		}
	}

	async showMenu(): Promise<void> {
		try {
			const selected = await vscode.window.showQuickPick([
				{
					label: this.modeEnabled ? 'Disable Read Flags Mode' : 'Enable Read Flags Mode',
					action: this.modeEnabled ? 'disable' : 'enable',
				},
				{ label: 'Select Read Save...', description: 'Choose or replace read.sav', action: 'select' },
			], {
				title: 'Read Flags',
				placeHolder: this.modeEnabled ? 'Read Flags mode is on' : 'Read Flags mode is off',
			});
			if (!selected) {
				return;
			}
			if (selected.action === 'select') {
				await selectReadSave();
				return;
			}
			const enabled = selected.action === 'enable';
			if (enabled && !getSettings().readSavPath && !(await selectReadSave())) {
				return;
			}
			await vscode.workspace.getConfiguration('siglusSS').update('readFlagsMode', enabled, configurationTarget());
		} catch (error) {
			void vscode.window.showErrorMessage(`Failed to configure read flags. ${toErrorMessage(error)}`);
		}
	}

	async sceneAction(action: UnreadNavigation | 'read' | 'unread', resource?: vscode.Uri): Promise<void> {
		const editor = vscode.window.activeTextEditor;
		if (!editor || !isSceneDocument(editor.document) ||
			(resource && resource.toString() !== editor.document.uri.toString())) {
			return;
		}
		if (!this.modeEnabled || !this.savePath) {
			void vscode.window.showInformationMessage('Enable Read Flags mode and select read.sav in the Read Flags status menu.');
			return;
		}
		const client = this.languageClient;
		if (!client?.isRunning()) {
			void vscode.window.showWarningMessage('The SiglusSS language server is not running.');
			return;
		}
		const capability = client.initializeResult?.capabilities.experimental?.siglusReadFlags;
		const supportsBatch = capability?.setReadFlags === true;
		const writing = action === 'read' || action === 'unread';
		if (capability?.version !== 1 || (writing && !supportsBatch && !capability.setReadFlag)) {
			void vscode.window.showWarningMessage('The configured siglus-ssu build does not support this read-flag action.');
			return;
		}
		const document = editor.document;
		const uri = document.uri.toString();
		const version = document.version;
		const selections = editor.selections;
		const cursor = document.offsetAt(editor.selection.active);
		const view = await this.currentReport(document);
		if (!view || !this.isCurrent(editor, client, version) || this.views.get(uri) !== view ||
			selections.length !== editor.selections.length || selections.some((s, i) =>
				!s.anchor.isEqual(editor.selections[i].anchor) || !s.active.isEqual(editor.selections[i].active))) {
			return;
		}
		const { index, report } = view;
		if (!index) {
			void vscode.window.showWarningMessage(this.mappingMessage(report));
			return;
		}
		if (!writing) {
			const target = index.unreadRange(action, cursor);
			if (target) {
				editor.selection = new vscode.Selection(target.end, target.start);
				editor.revealRange(target, vscode.TextEditorRevealType.InCenterIfOutsideViewport);
			} else if (!index.firstUnread) {
				void vscode.window.showInformationMessage(report.flagCount === 0
					? 'This scene has no read flags.' : 'All flags in this scene are marked as read.');
			} else if (action === 'previous' || action === 'next') {
				const side = action === 'previous' ? 'before' : 'after';
				void vscode.window.showInformationMessage(`There is no unread flag with a source location ${side} the cursor.`);
			} else {
				const flag = action === 'first' ? index.firstUnread : index.lastUnread;
				if (flag) {
					void vscode.window.showWarningMessage(`The ${action} unread flag (${flag.index}) has no precise source location.`);
				}
			}
			return;
		}
		const flags = index.flagsAt(document, selections);
		if (flags.length === 0) {
			void vscode.window.showInformationMessage(selections.some((selection) => !selection.isEmpty)
				? 'There are no read flags in the selection.'
				: 'There is no read flag at this position.');
			return;
		}
		let indices = flags.map((flag) => flag.index);
		if (flags.length > 1 && selections.length === 1 && selections[0].isEmpty) {
			flags.sort((a, b) => a.index - b.index);
			const choice = await vscode.window.showQuickPick(flags.map(({ index, read }) => ({
				label: 'Flag ' + index, description: read ? 'Read' : 'Unread', index,
			})), { title: 'Choose the flag to mark as ' + action });
			if (!choice || !this.isCurrent(editor, client, version) || this.views.get(uri)?.index !== index) {
				return;
			}
			indices = [choice.index];
		}
		if (!supportsBatch && indices.length > 1) {
			void vscode.window.showWarningMessage('Update siglus-ssu to mark multiple flags at once.');
			return;
		}
		const read = action === 'read';
		const method = supportsBatch ? 'siglus/setReadFlags' : 'siglus/setReadFlag';
		const target = supportsBatch ? { indices } : { index: indices[0] };
		try {
			const result = await client.sendRequest<ReadFlagReport & { previousRevision?: string }>(method, {
				textDocument: { uri, version }, mappingId: report.mappingId, ...target, read,
			});
			if (this.languageClient !== client || document.isClosed) {
				return;
			}
			const current = this.views.get(uri);
			if (result.status === 'matched' && document.version === version && result.version === version &&
				result.uri === uri && current?.index === index && result.mappingId === current.report.mappingId &&
				result.previousRevision === current.report.saveRevision) {
				this.cancelJob(uri);
				index.update({ indices, read });
				this.views.set(uri, { index, report: result });
				this.paint(uri, index);
				this.updateStatus();
			} else {
				if (result.status !== 'matched') {
					void vscode.window.showWarningMessage(this.mappingMessage(result));
				}
				this.refresh();
			}
		} catch (error) {
			void vscode.window.showErrorMessage('Failed to update read.sav. ' + toErrorMessage(error));
			this.refresh();
		}
	}

	private isCurrent(editor: vscode.TextEditor, client: LanguageClient, version: number): boolean {
		return vscode.window.activeTextEditor === editor && !editor.document.isClosed &&
			editor.document.version === version && this.languageClient === client && client.isRunning();
	}

	private currentReport(document: vscode.TextDocument): Promise<FlagView | undefined> {
		const uri = document.uri.toString();
		let job = this.jobs.get(uri);
		if (!job) {
			job = { cancellation: new vscode.CancellationTokenSource() };
			this.jobs.set(uri, job);
		}
		clearTimeout(job.timer);
		job.promise ??= this.request(document, job.cancellation, job.verifySave);
		return job.promise;
	}

	private async request(document: vscode.TextDocument, cancellation: vscode.CancellationTokenSource, verifySave = false): Promise<FlagView | undefined> {
		const languageClient = this.languageClient;
		const uri = document.uri.toString();
		const version = document.version;
		try {
			if (!languageClient || cancellation.token.isCancellationRequested) {
				return;
			}
			const previous = this.views.get(uri);
			const report = await languageClient.sendRequest<ReadFlagReport>('siglus/readFlags', {
				textDocument: { uri }, mappingId: previous?.report.mappingId, saveRevision: previous?.report.saveRevision, verifySave,
			}, cancellation.token);
			if (this.jobs.get(uri)?.cancellation !== cancellation || document.isClosed ||
				document.version !== version || report.uri !== uri || report.version !== version) {
				return;
			}
			let index: ReadFlagIndex | undefined;
			if (report.status === 'matched') {
				if (previous?.index && report.mappingId && previous.report.mappingId === report.mappingId) {
					index = previous.index;
					if (report.states !== undefined) {
						index.update(Buffer.from(report.states, 'base64'));
					}
				} else {
					index = new ReadFlagIndex(report.items, document, languageClient);
				}
			}
			const view = { report, index };
			this.views.set(uri, view);
			this.paint(uri, index);
			return view;
		} catch (error) {
			if (!cancellation.token.isCancellationRequested && this.jobs.get(uri)?.cancellation === cancellation) {
				const failure = { report: { uri, version, status: 'requestFailed', message: toErrorMessage(error), items: [] } };
				this.views.set(uri, failure);
				this.paint(uri);
				getServerOutputChannel().warn('Read flags: ' + toErrorMessage(error));
				return failure;
			}
		} finally {
			if (this.jobs.get(uri)?.cancellation === cancellation) {
				this.jobs.delete(uri);
				cancellation.dispose();
				this.updateStatus();
			}
		}
	}

	private paint(uri: string, index?: ReadFlagIndex): void {
		for (const editor of vscode.window.visibleTextEditors) {
			if (editor.document.uri.toString() !== uri || this.painted.get(editor) === index?.decorations) {
				continue;
			}
			this.decorations.forEach((decoration, state) => editor.setDecorations(decoration, index?.decorations[state] ?? []));
			if (index) {
				this.painted.set(editor, index.decorations);
			} else {
				this.painted.delete(editor);
			}
		}
	}

	private mappingMessage(report: ReadFlagReport | undefined): string {
		if (report?.status === 'sourceChanged') {
			return 'The source mapping changed. Try the command again.';
		}
		return report?.status === 'countMismatch'
			? `Flag count mismatch: source ${report.flagCount}, save ${report.savedFlagCount}. Saved states were not applied.`
			: report?.status === 'missingScene'
				? 'This scene has no saved entry. The engine initializes its flags as unread; no saved-state backgrounds are shown.'
				: report?.message ?? report?.status ?? 'No read-flag report is available.';
	}

	private updateStatus(): void {
		const capability = this.languageClient?.initializeResult?.capabilities.experimental?.siglusReadFlags;
		const writable = Boolean(this.modeEnabled && this.savePath && this.languageClient?.isRunning() &&
			capability?.version === 1 && (capability.setReadFlags || capability.setReadFlag));
		if (writable !== this.canSetReadFlag) {
			this.canSetReadFlag = writable;
			void vscode.commands.executeCommand('setContext', 'siglusSS.canSetReadFlag', writable);
		}
		const document = vscode.window.activeTextEditor?.document;
		if (!document || !isSceneDocument(document)) {
			this.status.hide();
			return;
		}
		const uri = document.uri.toString();
		const report = this.views.get(uri)?.report;
		if (!this.modeEnabled) {
			this.status.text = '$(book) Read Flags: Off';
			this.status.tooltip = 'Read Flags mode is off. The selected save path is kept.';
		} else if (!this.languageClient?.isRunning()) {
			this.status.text = '$(warning) Read Flags: Server stopped';
			this.status.tooltip = this.savePath;
		} else if (!this.savePath) {
			this.status.text = '$(book) Read Flags: Select save';
			this.status.tooltip = 'Choose read.sav to view saved flag details.';
		} else if (this.languageClient.initializeResult?.capabilities.experimental?.siglusReadFlags?.version !== 1) {
			this.status.text = '$(warning) Read Flags: Unsupported';
			this.status.tooltip = 'The configured siglus-ssu build does not support read-flag backgrounds.';
		} else if (this.jobs.has(uri)) {
			this.status.text = '$(sync~spin) Read Flags';
			this.status.tooltip = `Loading saved flags from ${this.savePath}`;
		} else if (report?.status === 'matched') {
			this.status.text = `$(book) Read Flags: ${report.readCount}/${report.flagCount}`;
			this.status.tooltip = `${this.savePath}\nRead: ${report.readCount}; unread: ${report.unreadCount}.\nDefault backgrounds: light blue = read; strong red = unread; violet = overlapping read and unread flags.\nHover the highlighted fragment for individual flag states. Right-click to jump to an unread flag or mark the flags in a selection.`;
		} else {
			this.status.text = `$(warning) Read Flags: ${report?.status ?? 'Unavailable'}`;
			this.status.tooltip = `${this.savePath}\n${this.mappingMessage(report)}`;
		}
		this.status.tooltip += '\nClick to enable or disable Read Flags mode, or select read.sav.';
		this.status.show();
	}

	dispose(): void {
		this.disconnect();
		for (const subscription of this.subscriptions) {
			subscription.dispose();
		}
		for (const decoration of this.decorations) {
			decoration.dispose();
		}
		this.status.dispose();
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

function getSettings(): ExtensionSettings {
	const config = vscode.workspace.getConfiguration('siglusSS');
	const profileSetting = config.inspect<number | null>('constProfile');
	const { profile, serverExtraArgs } = resolveConstProfile(
		profileSetting?.workspaceValue !== undefined ? profileSetting.workspaceValue : profileSetting?.globalValue,
		normalizeStringArray(config.get<unknown>('serverExtraArgs')),
	);
	const readFlagsMode = config.get<boolean>('readFlagsMode') === true;
	let readSavPath = config.get<string>('readSavPath')?.trim() ?? '';
	const explicitReadSav = Boolean(readSavPath);
	const args: string[] = [];
	for (let index = 0; index < serverExtraArgs.length; index += 1) {
		const arg = serverExtraArgs[index];
		if (arg === '--') {
			args.push(...serverExtraArgs.slice(index));
			break;
		}
		if (arg === '--read-sav') {
			const value = serverExtraArgs[index + 1];
			if (!value || value.startsWith('--')) {
				throw new Error('--read-sav requires a file path. Select read.sav from the Read Flags status menu or set siglusSS.readSavPath.');
			}
			if (!explicitReadSav) {
				if (readSavPath) {
					throw new Error('--read-sav must be specified only once.');
				}
				readSavPath = value;
			}
			index += 1;
		} else {
			args.push(arg);
		}
	}
	if (readFlagsMode && readSavPath) {
		readSavPath = path.resolve(primaryWorkspaceFolder()?.uri.fsPath ?? process.cwd(), expandConfiguredPath(readSavPath));
	}
	return {
		configuredPath: getConfiguredPath(),
		serverExtraArgs: args,
		constProfile: profile,
		readFlagsMode,
		readSavPath,
		autoUpdateSiglusSsu: config.get<boolean>('autoUpdateSiglusSsu') !== false,
	};
}

function getConfiguredPath(): string {
	return (vscode.workspace.getConfiguration('siglusSS').get<string>('siglusSsuPath') || 'siglus-ssu').trim() || 'siglus-ssu';
}

function currentConstProfile(): number | undefined {
	const settings = getSettings();
	const key = JSON.stringify(resolveCommandSpec(settings.configuredPath));
	return settings.constProfile ?? (runningCommandKey === key ? runningConstProfile : undefined) ??
		(constProfileCatalog?.commandKey === key ? constProfileCatalog.value.default : undefined);
}

async function queryConstProfiles(commandSpec: CommandSpec): Promise<ConstProfileCatalog> {
	const commandKey = JSON.stringify(commandSpec);
	constProfileCatalog = undefined;
	// --version exits without starting an LSP even if a future CLI accepts the probe value.
	const [validationOutput, helpOutput] = await Promise.all([
		runProcess(commandSpec.command, [...commandSpec.args, '--const-profile', '-1', '--version'], {
			cwd: commandSpec.cwd, acceptedExitCodes: [2], timeoutMs: 10000,
		}),
		runProcess(commandSpec.command, [...commandSpec.args, '--help'], {
			cwd: commandSpec.cwd, stdoutOnly: true, timeoutMs: 10000,
		}),
	]);
	const value = parseConstProfileCatalog(validationOutput, helpOutput);
	if (JSON.stringify(resolveCommandSpec(getConfiguredPath())) === commandKey) {
		constProfileCatalog = { commandKey, value };
		updateConstProfileStatus();
	}
	return value;
}

function getConstProfileStatusItem(): vscode.StatusBarItem {
	if (!constProfileStatusItem) {
		constProfileStatusItem = vscode.window.createStatusBarItem(
			'siglusSS.constProfile', vscode.StatusBarAlignment.Right, 100,
		);
		constProfileStatusItem.name = 'SiglusSS Const Profile';
		constProfileStatusItem.command = 'siglusSS.selectConstProfile';
	}
	return constProfileStatusItem;
}

function updateConstProfileStatus(): void {
	const item = getConstProfileStatusItem();
	if (vscode.window.activeTextEditor?.document.languageId !== 'siglusss') {
		item.hide();
		return;
	}
	try {
		const constProfile = currentConstProfile();
		const pending = languageServerState === 'starting' ||
			(languageServerState === 'running' && runningConstProfile !== constProfile);
		const icon = loadingConstProfiles ? 'sync~spin' : languageServerState === 'error' ? 'error' : pending ? 'sync~spin' : 'list-selection';
		item.text = `$(${icon}) SiglusSS: Profile ${constProfile ?? '?'}`;
		const status = loadingConstProfiles ? 'Loading available profile numbers...' : languageServerState === 'error'
			? 'Language server failed to start. Click to choose a profile; see the SiglusSS output for details.'
			: pending ? 'Applying profile...' : 'Click to select a const profile.';
		item.tooltip = constProfile === undefined
			? `Using the server's default profile. ${status}`
			: `Profile ${constProfile}\n${status}`;
	} catch (error) {
		item.text = '$(error) SiglusSS: Profile ?';
		item.tooltip = toErrorMessage(error);
	}
	item.show();
}

function selectConstProfile(): Promise<void> {
	if (!constProfilePickerJob) {
		constProfilePickerJob = showConstProfilePicker().finally(() => {
			constProfilePickerJob = undefined;
		});
	}
	return constProfilePickerJob;
}

async function showConstProfilePicker(): Promise<void> {
	const commandSpec = resolveCommandSpec(getConfiguredPath());
	let catalog: ConstProfileCatalog;
	loadingConstProfiles = true;
	updateConstProfileStatus();
	try {
		catalog = await queryConstProfiles(commandSpec);
	} catch (error) {
		void vscode.window.showErrorMessage(
			`Cannot read const profiles from siglus-ssu. Check the configured path, or enter a profile number in SiglusSS > Const Profile in Settings. ${toErrorMessage(error)}`,
		);
		return;
	} finally {
		loadingConstProfiles = false;
		updateConstProfileStatus();
	}
	let current: number | undefined;
	try {
		current = currentConstProfile();
	} catch {
		// Keep the picker available to repair an invalid setting or legacy argument.
	}
	const target = configurationTarget();
	const scope = target === vscode.ConfigurationTarget.Workspace ? 'workspace' : 'user settings';
	const profiles = [...catalog.profiles].sort((left, right) =>
		Number(right === current) - Number(left === current),
	);
	const selection = await vscode.window.showQuickPick<vscode.QuickPickItem & { profile: number }>(
		profiles.map((profile) => ({
			label: String(profile),
			description: profile === current ? 'Current' : undefined,
			profile,
		})),
		{
			title: 'SiglusSS: Select Const Profile',
			placeHolder: `Choose a profile number. Saves to ${scope} and restarts the language server.`,
		},
	);
	if (!selection || selection.profile === current) {
		return;
	}
	if (JSON.stringify(resolveCommandSpec(getConfiguredPath())) !== JSON.stringify(commandSpec)) {
		void vscode.window.showErrorMessage('The siglus-ssu path changed. Open the profile selector again.');
		return;
	}
	try {
		await vscode.workspace.getConfiguration('siglusSS').update('constProfile', selection.profile, target);
	} catch (error) {
		void vscode.window.showErrorMessage(`Failed to save SiglusSS const profile. ${toErrorMessage(error)}`);
	}
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

function isSceneDocument(document: vscode.TextDocument): boolean {
	return document.languageId === 'siglusss' && isSiglusDocument(document) &&
		document.uri.fsPath.toLowerCase().endsWith('.ss');
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
	encoding: SiglusEncoding,
): Promise<DecodedCandidate> {
	try {
		const text = await vscode.workspace.decode(bytes, { encoding });
		const encoded = await vscode.workspace.encode(text, { encoding });
		return {
			encoding,
			exact: Buffer.compare(bytes, encoded) === 0,
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

async function detectSiglusEncoding(uri: vscode.Uri): Promise<SiglusEncoding> {
	const bytes = await vscode.workspace.fs.readFile(uri);
	const hadBom =
		bytes.byteLength >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf;
	const bom = hadBom ? await decodeCandidate(bytes, 'utf8bom') : undefined;
	if (bom?.text !== undefined) {
		return bom.encoding;
	}
	const shiftJis = await decodeCandidate(bytes, 'shiftjis');
	if (shiftJis.exact) {
		return shiftJis.encoding;
	}
	const utf8 = bom ?? await decodeCandidate(bytes, 'utf8');
	if (utf8.exact) {
		return utf8.encoding;
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
	const outputChannel = getServerOutputChannel();
	const settings = getSettings();
	languageServerState = 'starting';
	updateConstProfileStatus();
	setLanguageServerStatus(
		'$(sync~spin) SiglusSS LSP',
		'Starting SiglusSS language server...',
	);
	const commandSpec = resolveCommandSpec(settings.configuredPath);
	setLanguageServerStatus(
		'$(sync~spin) SiglusSS LSP',
		`Checking ${[commandSpec.command, ...commandSpec.args, '-lsp'].join(' ')}`,
	);
	await runProcess(commandSpec.command, [...commandSpec.args, '--version'], {
		cwd: commandSpec.cwd,
		timeoutMs: 10000,
	});
	let catalog: ConstProfileCatalog | undefined;
	try {
		catalog = await queryConstProfiles(commandSpec);
	} catch (error) {
		// A CLI with different help/validation text can still start with its configured profile.
		outputChannel.appendLine(`Const profile discovery unavailable: ${toErrorMessage(error)}`);
	}
	if (catalog && settings.constProfile !== undefined && !catalog.profiles.includes(settings.constProfile)) {
		throw new Error(`Const profile ${settings.constProfile} is no longer available. Use SiglusSS: Select Const Profile to choose an available number.`);
	}
	const profileArgs = settings.constProfile === undefined ? [] : ['--const-profile', String(settings.constProfile)];
	const readSavPath = settings.readFlagsMode ? settings.readSavPath : '';
	const serverOptions: ServerOptions = {
		command: commandSpec.command,
		args: [...commandSpec.args, ...profileArgs, '-lsp', ...settings.serverExtraArgs,
			...(readSavPath ? ['--read-sav', readSavPath] : [])],
		options: commandSpec.cwd ? { cwd: commandSpec.cwd } : undefined,
	};
	const clientOptions: LanguageClientOptions = {
		// Settings take effect through CLI arguments and a restart. Configuration
		// synchronization would send notifications while the old client is stopping.
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
	readFlagController?.connect(client, readSavPath);
	runningConstProfile = settings.constProfile ?? catalog?.default;
	runningCommandKey = JSON.stringify(commandSpec);
	languageServerState = 'running';
	updateConstProfileStatus();
	setLanguageServerStatus(
		'$(check) SiglusSS LSP',
		'SiglusSS language server is running. Click to restart.',
	);
	setTimeout(() => languageServerStatusItem?.hide(), 4000);
}

async function stopLanguageClient(): Promise<void> {
	const current = client;
	readFlagController?.disconnect();
	clearLspNotificationProgress();
	setLanguageServerStatus(
		'$(sync~spin) SiglusSS LSP',
		'Stopping SiglusSS language server...',
	);
	if (current) {
		await current.stop();
	}
	client = undefined;
	runningConstProfile = undefined;
	runningCommandKey = undefined;
	languageServerState = 'stopped';
	updateConstProfileStatus();
	languageServerStatusItem?.hide();
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
		/\bnot found\b/i.test(message) ||
		/\bno such file or directory\b/i.test(message) ||
		/\bfailed to spawn\b/i.test(message)
	);
}

function configurationTarget(): vscode.ConfigurationTarget {
	return vscode.workspace.workspaceFile || vscode.workspace.workspaceFolders?.length
		? vscode.ConfigurationTarget.Workspace
		: vscode.ConfigurationTarget.Global;
}

async function selectReadSave(): Promise<boolean> {
	const selected = await vscode.window.showOpenDialog({
		canSelectFiles: true,
		canSelectFolders: false,
		canSelectMany: false,
		openLabel: 'Select Read Save',
		title: 'Select the game\'s read.sav',
		filters: { 'Siglus save files': ['sav'] },
	});
	if (selected?.[0]) {
		try {
			await vscode.workspace.getConfiguration('siglusSS').update('readSavPath', selected[0].fsPath, configurationTarget());
			return true;
		} catch (error) {
			void vscode.window.showErrorMessage(`Failed to save the read.sav path. ${toErrorMessage(error)}`);
		}
	}
	return false;
}

function nextLspProgressToken(method: string): string {
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
		!Object.hasOwn(params, 'workDoneToken')
	);
}

function createLspNotificationProgress(token: string, params: WorkDoneProgressBegin): void {
	const state: LspNotificationProgressState = {
		closed: false,
		reportedPercentage: 0,
		pending: [params],
	};
	lspProgressStates.set(token, state);
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
				});
			},
		),
	)
		.finally(() => {
			lspProgressStates.delete(token);
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
	token: string,
	params: LspWorkDoneProgress,
): void {
	if (params.kind === 'begin') {
		createLspNotificationProgress(token, params);
		return;
	}
	const state = lspProgressStates.get(token);
	if (!state) {
		return;
	}
	reportLspNotificationProgress(state, params);
	if (params.kind === 'end') {
		finishLspNotificationProgress(token);
	}
}

function finishLspNotificationProgress(token: string): void {
	const state = lspProgressStates.get(token);
	if (state && !state.closed) {
		state.closed = true;
		state.resolve?.();
	}
	lspProgressDisposables.get(token)?.dispose();
	lspProgressDisposables.delete(token);
}

function registerLspNotificationProgress(token: string): void {
	if (!client) {
		return;
	}
	lspProgressDisposables.set(
		token,
		client.onProgress(WorkDoneProgress.type, token, (params) => {
			handleLspNotificationProgress(token, params);
		}),
	);
}

function clearLspNotificationProgress(): void {
	for (const token of [...lspProgressDisposables.keys()]) {
		finishLspNotificationProgress(token);
	}
}

async function runProcess(
	command: string,
	args: string[],
	options: RunProcessOptions = {},
): Promise<string> {
	const outputChannel = getServerOutputChannel();
	const label = [command, ...args].join(' ');
	outputChannel.appendLine('');
	outputChannel.appendLine(`> ${label}`);
	return new Promise<string>((resolve, reject) => {
		if (options.token?.isCancellationRequested) {
			reject(new Error(`${label} was cancelled.`));
			return;
		}
		let output = '';
		let stdout = '';
		let finished = false;
		let timeout: ReturnType<typeof setTimeout> | undefined;
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
			if (timeout !== undefined) {
				clearTimeout(timeout);
			}
			cancellationDisposable?.dispose();
			callback();
		};
		const cancel = () => {
			finish(() => {
				child.kill();
				reject(new Error(`${label} was cancelled.`));
			});
		};
		cancellationDisposable = options.token?.onCancellationRequested(cancel);
		if (options.timeoutMs !== undefined) {
			timeout = setTimeout(() => finish(() => {
				child.kill();
				reject(new Error(`Timed out while running ${label}.`));
			}), options.timeoutMs);
		}
		child.stdout.setEncoding('utf8').on('data', (text: string) => {
			stdout += text;
			output += text;
			outputChannel.append(text);
		});
		child.stderr.setEncoding('utf8').on('data', (text: string) => {
			output += text;
			outputChannel.append(text);
		});
		child.on('error', (error) => {
			finish(() => reject(error));
		});
		child.on('close', (code) => {
			finish(() => {
				if (code === 0 || (code !== null && options.acceptedExitCodes?.includes(code))) {
					resolve(options.stdoutOnly ? stdout : output);
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
): Promise<string> {
	const args = ['-m', 'pip', 'install', '-U', 'siglus-ssu'];
	reportProgress('Installing package...', 5);
	try {
		await runProcess('python', args, { token });
		return 'python';
	} catch (error) {
		if (!isMissingCommandError(error)) {
			throw error;
		}
		reportProgress('python was not found, trying python3...');
		await runProcess('python3', args, { token });
		return 'python3';
	}
}

async function resolveSiglusSsuConsoleScript(
	pythonCommand: string,
	token: vscode.CancellationToken,
): Promise<string | undefined> {
	const code = [
		'import os, sys, sysconfig',
		'name = "siglus-ssu"',
		'if sys.platform == "win32":',
		'    name += ".exe"',
		'print(os.path.join(sysconfig.get_path("scripts"), name))',
	].join('\n');
	const output = await runProcess(pythonCommand, ['-c', code], { token });
	const scriptPath = output.trim().split(/\r?\n/).pop()?.trim();
	return scriptPath || undefined;
}

async function configureInstalledSiglusSsuPath(
	pythonCommand: string,
	reportProgress: InstallProgressReporter,
	token: vscode.CancellationToken,
): Promise<void> {
	reportProgress('Locating siglus-ssu...', 55);
	const installedScriptPath = await resolveSiglusSsuConsoleScript(
		pythonCommand,
		token,
	);
	if (
		installedScriptPath &&
		existsSync(installedScriptPath) &&
		getSettings().configuredPath === 'siglus-ssu'
	) {
		await vscode.workspace
			.getConfiguration('siglusSS')
			.update('siglusSsuPath', installedScriptPath, configurationTarget());
	}
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
		languageServerStatusItem?.hide();
	}
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
					await new Promise<void>((resolve) => setTimeout(resolve, 250));
					const pythonCommand = await installSiglusSsuPackage(
						reportProgress,
						token,
					);
					if (token.isCancellationRequested) {
						throw new Error('SiglusSS setup was cancelled.');
					}
					await configureInstalledSiglusSsuPath(
						pythonCommand,
						reportProgress,
						token,
					);
					if (token.isCancellationRequested) {
						throw new Error('SiglusSS setup was cancelled.');
					}
					reportProgress('Restarting language server...', 35);
					await restartLanguageClientProcess();
					reportProgress('Ready.', 5);
				},
			);
			void vscode.window.showInformationMessage(
				'siglus-ssu installed and the language server was restarted.',
			);
		} catch (error) {
			if (/\bcancelled\b/i.test(toErrorMessage(error))) {
				void vscode.window.showWarningMessage('SiglusSS setup cancelled.');
				return;
			}
			outputChannel.show(true);
			void vscode.window.showErrorMessage(
				`Failed to install siglus-ssu. ${toErrorMessage(error)}`,
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
	languageServerState = 'error';
	updateConstProfileStatus();
	setLanguageServerStatus(
		'$(error) SiglusSS LSP',
		`SiglusSS language server failed to start: ${toErrorMessage(error)}`,
	);
	setTimeout(() => languageServerStatusItem?.hide(), 8000);
	if (!isMissingCommandError(error)) {
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

function queueLanguageClientOperation<T>(operation: () => Promise<T>): Promise<T> {
	const job = languageClientOperation.then(operation);
	languageClientOperation = job.then(() => undefined, () => undefined);
	return job;
}

function restartLanguageClientProcess(): Promise<boolean> {
	const generation = ++languageServerGeneration;
	return queueLanguageClientOperation(async () => {
		if (isDeactivating || generation !== languageServerGeneration) {
			return false;
		}
		try {
			await stopLanguageClient();
			if (isDeactivating || generation !== languageServerGeneration) {
				return false;
			}
			await startLanguageClient();
			return generation === languageServerGeneration;
		} catch (error) {
			if (isDeactivating || generation !== languageServerGeneration) {
				return false;
			}
			throw error;
		}
	});
}

async function restartLanguageClient(showNotification = true): Promise<void> {
	try {
		if (await restartLanguageClientProcess() && showNotification) {
			void vscode.window.showInformationMessage('SiglusSS language server restarted.');
		}
	} catch (error) {
		await handleLanguageServerStartError(error);
	}
}

export async function activate(context: vscode.ExtensionContext): Promise<void> {
	readFlagController = new ReadFlagController();
	context.subscriptions.push(readFlagController);
	context.subscriptions.push(getServerOutputChannel());
	context.subscriptions.push(getLanguageServerStatusItem());
	context.subscriptions.push(getConstProfileStatusItem());
	context.subscriptions.push(vscode.window.onDidChangeActiveTextEditor(updateConstProfileStatus));
	updateConstProfileStatus();
	context.subscriptions.push(
		vscode.workspace.onDidOpenTextDocument((document) => {
			void ensureSiglusEncoding(document);
		}),
	);
	context.subscriptions.push(
		vscode.commands.registerCommand('siglusSS.restartLanguageServer', () => restartLanguageClient()),
		vscode.commands.registerCommand('siglusSS.selectConstProfile', selectConstProfile),
		vscode.commands.registerCommand('siglusSS.readFlags', () => readFlagController?.showMenu()),
		vscode.commands.registerCommand('siglusSS.refreshReadFlags', () => readFlagController?.refresh()),
		vscode.commands.registerCommand('siglusSS.goToFirstUnreadFlag', (uri?: vscode.Uri) => readFlagController?.sceneAction('first', uri)),
		vscode.commands.registerCommand('siglusSS.goToPreviousUnreadFlag', (uri?: vscode.Uri) => readFlagController?.sceneAction('previous', uri)),
		vscode.commands.registerCommand('siglusSS.goToNextUnreadFlag', (uri?: vscode.Uri) => readFlagController?.sceneAction('next', uri)),
		vscode.commands.registerCommand('siglusSS.goToLastUnreadFlag', (uri?: vscode.Uri) => readFlagController?.sceneAction('last', uri)),
		vscode.commands.registerCommand('siglusSS.markFlagRead', (uri?: vscode.Uri) => readFlagController?.sceneAction('read', uri)),
		vscode.commands.registerCommand('siglusSS.markFlagUnread', (uri?: vscode.Uri) => readFlagController?.sceneAction('unread', uri)),
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
				event.affectsConfiguration('siglusSS.serverExtraArgs') ||
				event.affectsConfiguration('siglusSS.constProfile') ||
				event.affectsConfiguration('siglusSS.readFlagsMode') ||
				(event.affectsConfiguration('siglusSS.readSavPath') &&
					vscode.workspace.getConfiguration('siglusSS').get<boolean>('readFlagsMode') === true)
			) {
				updateConstProfileStatus();
				void restartLanguageClient(false);
			}
		}),
	);
	for (const document of vscode.workspace.textDocuments) {
		void ensureSiglusEncoding(document);
	}
	try {
		if (await restartLanguageClientProcess()) {
			setTimeout(() => { void checkSiglusSsuUpdateWithProgress(context); }, 5000);
		}
	} catch (error) {
		await handleLanguageServerStartError(error);
	}
}

export async function deactivate(): Promise<void> {
	isDeactivating = true;
	languageServerGeneration += 1;
	await queueLanguageClientOperation(stopLanguageClient);
}
