import {
  acknowledgeManualAction,
  buildPlan,
  cancelRun,
  createPackage,
  getInventory,
  getRun,
  inspectPackage,
  isDesktopRuntime,
  normalizeBridgeError,
  resumeRestore,
  saveReport,
  selectedSelectionId,
  selectPackageDestination,
  selectPackageFile,
  selectReportDestination,
  startRestore,
  startScan,
  subscribeToEvents,
  verify,
} from './api';
import {
  ArtifactPolicy,
  LargeDataSelectionPolicy,
  ReforgeErrorCode,
  RestoreMode,
  RunStatus,
  SecretSelectionPolicy,
  UnknownBinarySelectionPolicy,
  type ArtifactSelection,
  type Component,
  type DependencyEdge,
  type ErrorEnvelope,
  type Conflict,
  type Inventory,
  type ManualAction,
  type OperationState,
  type ProgressEvent,
  type RestorePlan,
  type RestoreReport,
  type SelectionInput,
  type TrustState,
} from './generated';
import type {
  ActivityEvent,
  AppNotice,
  BridgeEventHandlers,
  ComponentSelectionSummary,
  EventEnvelope,
  OperationView,
  PackageInspection,
  PackageResponse,
  ReportDelta,
  RestoreProgressDelta,
  RunView,
} from './api';

export type Screen =
  | 'home'
  | 'scan_progress'
  | 'scan_results'
  | 'selection'
  | 'package_review'
  | 'target_analysis'
  | 'restore_plan'
  | 'restore_progress'
  | 'verification'
  | 'report';

export interface StateError extends ErrorEnvelope {
  source?: 'bridge' | 'validation' | 'local';
}

const SCAN_TIMEOUT_MS = 180_000;
const RESTORE_TIMEOUT_MS = 1_800_000;
const POLL_INTERVAL_MS = 800;
const MAX_EVENT_ROWS = 250;

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const exponent = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / 1024 ** exponent;
  return `${value >= 10 || exponent === 0 ? value.toFixed(0) : value.toFixed(1)} ${units[exponent]}`;
}

export function progressPercent(completed: number, total?: number): number {
  if (!total || total <= 0) return completed > 0 ? 100 : 0;
  return Math.min(100, Math.max(0, Math.round((completed / total) * 100)));
}

export function reportTotal(counts: RestoreReport['counts']): number {
  return Object.values(counts).reduce((total, count) => total + count, 0);
}

export function isActivationKey(key: string): boolean {
  return key === 'Enter' || key === ' ';
}

export interface ConflictDisplay {
  title: string;
  resolution: string;
  requires_confirmation: boolean;
}

export function conflictDisplay(conflict: Conflict): ConflictDisplay {
  return {
    title: conflict.kind.replaceAll('_', ' '),
    resolution: conflict.resolution.replaceAll('_', ' '),
    requires_confirmation: conflict.requires_confirmation,
  };
}

function requiredEdges(graph: { components: Component[]; edges: DependencyEdge[] }, id: string): string[] {
  const component = graph.components.find((item) => item.id === id);
  const embedded = component?.dependencies ?? [];
  const graphEdges = graph.edges.filter((edge) => edge.from === id && edge.required);
  return [...embedded, ...graphEdges]
    .filter((edge) => edge.required)
    .map((edge) => edge.to);
}

export function selectionClosure(
  graph: { components: Component[]; edges: DependencyEdge[] },
  selected: string[],
): ComponentSelectionSummary {
  const initial = new Set(selected);
  const closure = new Set(selected);
  const queue = [...selected];

  while (queue.length > 0) {
    const current = queue.shift();
    if (!current) continue;
    for (const dependency of requiredEdges(graph, current)) {
      if (!closure.has(dependency)) {
        closure.add(dependency);
        queue.push(dependency);
      }
    }
  }

  const totalBytes = graph.components
    .filter((component) => closure.has(component.id))
    .flatMap((component) => component.artifacts)
    .filter((artifact) => artifact.policy !== ArtifactPolicy.SecretReference)
    .reduce((total, artifact) => total + artifact.size_bytes, 0);

  return {
    selected: [...closure],
    auto_added: [...closure].filter((id) => !initial.has(id)),
    total_bytes: totalBytes,
  };
}

export function selectionForInventory(inventory: Inventory): SelectionInput {
  const defaults = inventory.graph.components
    .filter((component) => component.selection.selected_by_default && !component.selection.sensitive)
    .map((component) => component.id);
  const closure = selectionClosure(inventory.graph, defaults);
  const artifacts: ArtifactSelection[] = inventory.graph.components
    .filter((component) => closure.selected.includes(component.id))
    .flatMap((component) => component.artifacts)
    .filter((artifact) => artifact.policy !== ArtifactPolicy.SecretReference)
    .map((artifact) => ({ artifact: artifact.id, include: true }));

  return {
    components: closure.selected,
    artifacts,
    policy: {
      secrets: SecretSelectionPolicy.Exclude,
      large_data: LargeDataSelectionPolicy.RequireConfirmation,
      unknown_binaries: UnknownBinarySelectionPolicy.Exclude,
    },
  };
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, milliseconds));
}

function readLastRunId(): string | null {
  if (typeof localStorage === 'undefined') return null;
  return localStorage.getItem('reforge:last-run-id');
}

function writeLastRunId(runId: string): void {
  if (typeof localStorage !== 'undefined') localStorage.setItem('reforge:last-run-id', runId);
}

function localError(message: string): StateError {
  return {
    code: ReforgeErrorCode.OperationFailed,
    message,
    retryability: 'NEVER',
    source: 'local',
  } as StateError;
}

export class ReforgeState {
  screen = $state<Screen>('home');
  inventory = $state<Inventory | null>(null);
  selection = $state<SelectionInput | null>(null);
  packageInspection = $state<PackageInspection | null>(null);
  packageReceipt = $state<PackageResponse['receipt'] | null>(null);
  packageSelectionId = $state<string | null>(null);
  outputSelectionId = $state<string | null>(null);
  plan = $state<RestorePlan | null>(null);
  run = $state<RunView | null>(null);
  report = $state<RestoreReport | null>(null);
  progress = $state<ProgressEvent | RestoreProgressDelta | null>(null);
  runId = $state<string | null>(null);
  lastRunId = $state<string | null>(readLastRunId());
  mode = $state<RestoreMode>(RestoreMode.Rebuild);
  packageApproved = $state(false);
  busy = $state(false);
  error = $state<StateError | null>(null);
  notice = $state<AppNotice | null>(null);
  autoAddedComponents = $state<string[]>([]);
  eventRows = $state<ActivityEvent[]>([]);
  desktopRuntime = isDesktopRuntime();

  private scanGeneration = 0;
  private restoreGeneration = 0;
  private unlisten: (() => void) | null = null;

  get selectedCount(): number {
    return this.selection?.components.length ?? 0;
  }

  get selectedBytes(): number {
    if (!this.inventory || !this.selection) return 0;
    return this.inventory.graph.components
      .filter((component) => this.selection?.components.includes(component.id))
      .flatMap((component) => component.artifacts)
      .filter((artifact) => this.selection?.artifacts.some((item) => item.artifact === artifact.id && item.include))
      .reduce((total, artifact) => total + artifact.size_bytes, 0);
  }

  get hasPendingManualActions(): boolean {
    return this.run?.manual_actions.some((action) => action.state === 'PENDING') ?? false;
  }

  get reportItemCount(): number {
    return this.report ? reportTotal(this.report.counts) : 0;
  }

  async connectEvents(): Promise<void> {
    if (this.unlisten) return;
    const handlers: BridgeEventHandlers = {
      onProgress: (event) => this.handleProgress(event),
      onRestoreProgress: (event) => this.handleRestoreProgress(event),
      onReport: (event) => this.handleReport(event.payload),
      onError: (event) => this.handleBackendError(event),
    };
    try {
      this.unlisten = await subscribeToEvents(handlers);
    } catch (error) {
      this.setError(error);
    }
  }

  disconnectEvents(): void {
    this.unlisten?.();
    this.unlisten = null;
  }

  clearError(): void {
    this.error = null;
  }

  dismissNotice(): void {
    this.notice = null;
  }

  go(screen: Screen): void {
    this.clearError();
    this.screen = screen;
  }

  async startScan(): Promise<void> {
    this.clearError();
    this.notice = null;
    this.progress = null;
    this.eventRows = [];
    this.busy = true;
    this.screen = 'scan_progress';
    const generation = ++this.scanGeneration;
    try {
      const handle = await startScan();
      this.runId = handle.run_id;
      this.lastRunId = handle.run_id;
      writeLastRunId(handle.run_id);
      this.pollInventory(handle.run_id, generation);
    } catch (error) {
      this.setError(error);
    }
  }

  async refreshInventory(): Promise<void> {
    this.clearError();
    this.busy = true;
    try {
      const inventory = await getInventory();
      this.setInventory(inventory);
      this.screen = 'scan_results';
    } catch (error) {
      this.setError(error);
    }
  }

  async openPackage(): Promise<void> {
    this.clearError();
    this.notice = null;
    this.busy = true;
    try {
      const result = await selectPackageFile();
      const selectionId = selectedSelectionId(result);
      if (!selectionId) {
        this.busy = false;
        return;
      }
      const inspection = await inspectPackage(selectionId);
      this.packageSelectionId = selectionId;
      this.packageInspection = inspection;
      this.packageApproved = inspection.trust === 'USER_APPROVED';
      this.screen = 'package_review';
      this.busy = false;
    } catch (error) {
      this.setError(error);
    }
  }

  async createPackageFromSelection(): Promise<void> {
    if (!this.selection || this.selection.components.length === 0) {
      this.setError(localError('Select at least one component before creating a package'));
      return;
    }
    this.clearError();
    this.busy = true;
    try {
      const result = await selectPackageDestination();
      const selectionId = selectedSelectionId(result);
      if (!selectionId) {
        this.busy = false;
        return;
      }
      const response = await createPackage({
        output_selection_id: selectionId,
        selection: this.selection,
      });
      this.outputSelectionId = selectionId;
      this.packageReceipt = response.receipt;
      this.notice = { tone: 'success', message: 'Package written atomically and ready for review' };
      this.screen = 'package_review';
      this.busy = false;
    } catch (error) {
      this.setError(error);
    }
  }

  setComponentSelected(componentId: string, selected: boolean): void {
    if (!this.inventory) return;
    const current = new Set(this.selection?.components ?? []);
    if (selected) current.add(componentId);
    else current.delete(componentId);
    const closure = selectionClosure(this.inventory.graph, [...current]);
    const artifacts = this.inventory.graph.components
      .filter((component) => closure.selected.includes(component.id))
      .flatMap((component) => component.artifacts)
      .filter((artifact) => artifact.policy !== ArtifactPolicy.SecretReference)
      .map((artifact) => ({ artifact: artifact.id, include: true }));
    this.selection = {
      ...(this.selection ?? selectionForInventory(this.inventory)),
      components: closure.selected,
      artifacts,
    };
    this.autoAddedComponents = closure.auto_added;
  }

  approvePackage(approved: boolean): void {
    this.packageApproved = approved;
    if (approved && this.packageInspection?.trust !== 'USER_APPROVED') {
      this.notice = { tone: 'warning', message: 'Approval is recorded for this run; package integrity remains backend-verified' };
    }
  }

  async buildRestorePlan(): Promise<void> {
    if (!this.packageSelectionId) {
      this.setError(localError('Open a package before building a restore plan'));
      return;
    }
    this.clearError();
    this.busy = true;
    this.screen = 'target_analysis';
    try {
      const response = await buildPlan({
        package_selection_id: this.packageSelectionId,
        mode: this.mode,
        package_approved: this.packageApproved,
      });
      this.plan = response.plan;
      this.screen = 'target_analysis';
      this.busy = false;
    } catch (error) {
      this.setError(error);
    }
  }

  showRestorePlan(): void {
    if (!this.plan) return;
    this.screen = 'restore_plan';
  }

  async beginRestore(): Promise<void> {
    if (!this.packageSelectionId || !this.plan) {
      this.setError(localError('Build a restore plan before starting restore'));
      return;
    }
    this.clearError();
    this.notice = null;
    this.eventRows = [];
    this.busy = true;
    this.screen = 'restore_progress';
    const generation = ++this.restoreGeneration;
    try {
      const handle = await startRestore({
        package_selection_id: this.packageSelectionId,
        mode: this.mode,
        package_approved: this.packageApproved,
      });
      this.runId = handle.run_id;
      this.lastRunId = handle.run_id;
      writeLastRunId(handle.run_id);
      this.pollRun(handle.run_id, generation);
    } catch (error) {
      this.setError(error);
    }
  }

  async resumeLatestRun(): Promise<void> {
    if (!this.lastRunId) {
      this.setError(localError('No resumable run is recorded on this device'));
      return;
    }
    this.clearError();
    this.eventRows = [];
    this.busy = true;
    this.screen = 'restore_progress';
    const generation = ++this.restoreGeneration;
    try {
      const handle = await resumeRestore(this.lastRunId);
      this.runId = handle.run_id;
      this.pollRun(handle.run_id, generation);
    } catch (error) {
      this.setError(error);
    }
  }

  async cancelCurrentRun(): Promise<void> {
    const activeRunId = this.runId;
    if (!activeRunId) return;
    this.scanGeneration += 1;
    this.restoreGeneration += 1;
    try {
      const result = await cancelRun(activeRunId);
      this.notice = {
        tone: result.accepted ? 'info' : 'warning',
        message: result.accepted ? 'Cancellation requested; safe operations will stop at the next checkpoint' : 'The run could not accept cancellation',
      };
      this.busy = false;
    } catch (error) {
      this.setError(error);
    }
  }

  async verifyCurrentRun(): Promise<void> {
    if (!this.runId) return;
    this.clearError();
    this.busy = true;
    try {
      const response = await verify(this.runId);
      this.report = response.report;
      this.busy = false;
      this.screen = 'verification';
    } catch (error) {
      this.setError(error);
    }
  }

  async acknowledgeAction(action: ManualAction): Promise<void> {
    if (!this.runId) return;
    this.clearError();
    try {
      const response = await acknowledgeManualAction(this.runId, action.id);
      if (this.run) {
        this.run = {
          ...this.run,
          manual_actions: this.run.manual_actions.map((candidate) =>
            candidate.id === response.action.id ? response.action : candidate,
          ),
        };
      }
      this.notice = { tone: 'success', message: 'Manual action acknowledged; the journal remains the source of truth' };
    } catch (error) {
      this.setError(error);
    }
  }

  async saveCurrentReport(): Promise<void> {
    if (!this.runId || !this.report) return;
    this.clearError();
    this.busy = true;
    try {
      const result = await selectReportDestination();
      const selectionId = selectedSelectionId(result);
      if (!selectionId) {
        this.busy = false;
        return;
      }
      await saveReport(this.runId, selectionId);
      this.notice = { tone: 'success', message: 'Redacted report saved' };
      this.busy = false;
    } catch (error) {
      this.setError(error);
    }
  }

  private setInventory(inventory: Inventory): void {
    this.inventory = inventory;
    this.selection = selectionForInventory(inventory);
    this.autoAddedComponents = [];
    this.busy = false;
  }

  private handleProgress(event: EventEnvelope<ProgressEvent>): void {
    if (!this.runId || event.run_id !== this.runId) return;
    this.progress = event.payload;
    this.appendEvent({
      seq: (this.eventRows.at(-1)?.seq ?? 0) + 1,
      run_id: event.run_id,
      time: new Date().toISOString(),
      level: event.payload.status,
      message: event.payload.message,
    });
  }

  private handleRestoreProgress(event: EventEnvelope<RestoreProgressDelta>): void {
    if (!this.runId || event.run_id !== this.runId) return;
    this.progress = event.payload;
    this.appendEvent({
      seq: (this.eventRows.at(-1)?.seq ?? 0) + 1,
      run_id: event.run_id,
      time: new Date().toISOString(),
      level: event.payload.status,
      message: event.payload.message,
    });
  }

  private handleReport(delta: ReportDelta): void {
    if (!this.runId || delta.report.run_id !== this.runId) return;
    this.report = delta.report;
    this.busy = false;
    this.screen = 'verification';
  }

  private handleBackendError(event: EventEnvelope<ErrorEnvelope>): void {
    if (this.runId && event.run_id !== this.runId) return;
    this.setError(event.payload);
  }

  private appendEvent(event: ActivityEvent): void {
    this.eventRows = [...this.eventRows, event].slice(-MAX_EVENT_ROWS);
  }

  private async pollInventory(runId: string, generation: number): Promise<void> {
    const deadline = Date.now() + SCAN_TIMEOUT_MS;
    while (generation === this.scanGeneration && Date.now() < deadline) {
      try {
        const inventory = await getInventory();
        if (inventory.scan_id === runId) {
          this.setInventory(inventory);
          this.screen = 'scan_results';
          return;
        }
      } catch (error) {
        if (this.error) return;
      }
      await delay(POLL_INTERVAL_MS);
    }
    if (generation === this.scanGeneration) {
      this.setError(localError('Scan did not produce an inventory before the timeout'));
    }
  }

  private async pollRun(runId: string, generation: number): Promise<void> {
    const deadline = Date.now() + RESTORE_TIMEOUT_MS;
    while (generation === this.restoreGeneration && Date.now() < deadline) {
      try {
        const response = await getRun(runId);
        if (response.run) {
          this.run = response.run;
          this.plan = this.plan ?? null;
        }
        if (response.report) {
          this.report = response.report;
          this.busy = false;
          this.screen = 'verification';
          return;
        }
        if (response.lifecycle?.status === 'FAILED' || response.lifecycle?.status === 'CANCELLED') {
          this.busy = false;
          if (response.lifecycle.error) this.setError(response.lifecycle.error);
          return;
        }
      } catch (error) {
        this.setError(error);
        return;
      }
      await delay(POLL_INTERVAL_MS);
    }
    if (generation === this.restoreGeneration) {
      this.setError(localError('Restore status polling timed out; use Resume run to continue safely'));
    }
  }

  private setError(error: unknown): void {
    const envelope = normalizeBridgeError(error);
    this.error = { ...envelope, source: 'bridge' };
    this.busy = false;
  }
}

export function createReforgeState(): ReforgeState {
  return new ReforgeState();
}

export type { TrustState, OperationState, RunStatus };
