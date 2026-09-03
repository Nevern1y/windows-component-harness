import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import {
  ReforgeErrorCode,
  Retryability,
} from './generated';
import type {
  ApprovalState,
  ErrorEnvelope,
  Inventory,
  ManualAction,
  Operation,
  OperationState,
  PackageGraph,
  PackageManifest,
  ProgressEvent,
  RestoreMode,
  RestorePlan,
  RestoreReport,
  RunId,
  RunStatus,
  SelectionInput,
  TrustState,
} from './generated';
export type EmptyRequest = Record<string, never>;

export type StartScanRequest = EmptyRequest;

export interface CancelRunRequest { run_id: RunId; }
export interface InspectPackageRequest { selection_id: string; }
export interface CreatePackageRequest { output_selection_id: string; selection: SelectionInput; }
export interface BuildPlanRequest { package_selection_id: string; mode: RestoreMode; package_approved: boolean; }
export interface StartRestoreRequest { package_selection_id: string; mode: RestoreMode; package_approved: boolean; }
export interface ResumeRestoreRequest { run_id: RunId; }
export interface GetRunRequest { run_id: RunId; }
export interface AckManualActionRequest { run_id: RunId; action_id: string; }
export interface SaveReportRequest { run_id: RunId; output_selection_id: string; }

export interface WireEnvelope<T> {
  schema_version: number;
  request_id: string;
  payload: T;
}

export interface RunHandle { run_id: RunId; }
export interface CancelResponse { run_id: RunId; accepted: boolean; }
export interface InventoryResponse { inventory: Inventory; }

export interface PackageInspection {
  package_id: string;
  format_version: number;
  manifest: PackageManifest;
  graph: PackageGraph;
  selection: SelectionInput;
  object_index: { objects: Array<Record<string, unknown>> };
  trust: TrustState;
  has_vault: boolean;
  archive_bytes: number;
  warnings: string[];
  sources: Record<string, unknown>;
  signature?: Record<string, unknown>;
}

export interface PackageResponse {
  receipt: { package_id: string; object_count: number; index_digest: string };
}

export interface PlanResponse { plan: RestorePlan; }
export interface ReportResponse { report: RestoreReport; }
export type NativeDialogResult =
  | { status: 'cancelled' }
  | { status: 'selected'; selection_id: string };

export type RunLifecycle = 'STARTING' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED';
export interface RunLifecycleView { status: RunLifecycle; error?: ErrorEnvelope; }

export interface OperationView {
  id: string;
  operation: Operation;
  state: OperationState;
  attempt: number;
  started_at?: string;
  ended_at?: string;
  result?: unknown;
  error?: ErrorEnvelope;
  backup?: unknown;
}

export interface EventView {
  seq: number;
  run_id: RunId;
  time: string;
  level: string;
  event: unknown;
}

export interface ActivityEvent {
  seq: number;
  run_id: RunId;
  time: string;
  level: string;
  message: string;
}

export interface RunView {
  run_id: RunId;
  package_id: string;
  mode: RestoreMode;
  target_fingerprint: string;
  status: RunStatus;
  approval_state: ApprovalState;
  created_at: string;
  updated_at: string;
  operations: OperationView[];
  events: EventView[];
  manual_actions: ManualAction[];
}

export interface RunResponse {
  run?: RunView;
  lifecycle?: RunLifecycleView;
  report?: RestoreReport;
}

export interface ManualActionResponse { action: ManualAction; }
export interface RestoreProgressDelta {
  status: RunStatus;
  operation_id?: string;
  operation_state?: OperationState;
  completed: number;
  total?: number;
  message: string;
}
export interface ReportDelta { status: RestoreReport['status']; report: RestoreReport; }

export interface EventEnvelope<T> {
  schema_version: number;
  event_id: string;
  run_id: RunId;
  payload: T;
}

export interface BridgeEventHandlers {
  onProgress?: (event: EventEnvelope<ProgressEvent>) => void;
  onRestoreProgress?: (event: EventEnvelope<RestoreProgressDelta>) => void;
  onReport?: (event: EventEnvelope<ReportDelta>) => void;
  onError?: (event: EventEnvelope<ErrorEnvelope>) => void;
}

export interface ComponentSelectionSummary {
  selected: string[];
  auto_added: string[];
  total_bytes: number;
}

export interface AppNotice { tone: 'success' | 'info' | 'warning'; message: string; }


export const BRIDGE_SCHEMA_VERSION = 1;
export const EVENTS = {
  progress: 'reforge://progress',
  restoreProgress: 'reforge://restore-progress',
  report: 'reforge://report',
  error: 'reforge://error',
} as const;

type CommandRequest = object;

export function isDesktopRuntime(): boolean {
  return typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;
}

function requestId(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  return `request-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

function protocolError(message: string): ErrorEnvelope {
  return {
    code: ReforgeErrorCode.SchemaInvalid,
    message,
    technical_detail: undefined,
    component: undefined,
    operation: undefined,
    retryability: Retryability.Never,
  };
}

export function normalizeBridgeError(value: unknown): ErrorEnvelope {
  if (typeof value === 'object' && value !== null) {
    const candidate = value as Partial<ErrorEnvelope>;
    if (typeof candidate.code === 'string' && typeof candidate.message === 'string') {
      return {
        code: candidate.code as ReforgeErrorCode,
        message: candidate.message,
        technical_detail: typeof candidate.technical_detail === 'string' ? candidate.technical_detail : undefined,
        component: typeof candidate.component === 'string' ? candidate.component : undefined,
        operation: typeof candidate.operation === 'string' ? candidate.operation : undefined,
        retryability: (candidate.retryability as Retryability | undefined) ?? Retryability.Never,
      };
    }
  }

  return {
    code: ReforgeErrorCode.OperationFailed,
    message: typeof value === 'string' ? value : 'The desktop command failed',
    technical_detail: undefined,
    component: undefined,
    operation: undefined,
    retryability: Retryability.Never,
  };
}

async function command<TRequest extends CommandRequest, TResponse>(
  name: string,
  payload: TRequest,
): Promise<TResponse> {
  const id = requestId();
  const request: WireEnvelope<TRequest> = {
    schema_version: BRIDGE_SCHEMA_VERSION,
    request_id: id,
    payload,
  };

  try {
    const response = await invoke<WireEnvelope<TResponse>>(name, { request });
    if (
      !response ||
      response.schema_version !== BRIDGE_SCHEMA_VERSION ||
      response.request_id !== id ||
      !('payload' in response)
    ) {
      throw protocolError('The desktop returned an invalid response envelope');
    }
    return response.payload;
  } catch (error) {
    throw normalizeBridgeError(error);
  }
}

export function startScan(): Promise<RunHandle> {
  return command<StartScanRequest, RunHandle>('start_scan', {});
}

export function cancelRun(run_id: string): Promise<CancelResponse> {
  const payload: CancelRunRequest = { run_id };
  return command<CancelRunRequest, CancelResponse>('cancel_run', payload);
}

export async function getInventory(): Promise<Inventory> {
  const response = await command<EmptyRequest, InventoryResponse>('get_inventory', {});
  return response.inventory;
}

export function inspectPackage(selection_id: string): Promise<PackageInspection> {
  const payload: InspectPackageRequest = { selection_id };
  return command<InspectPackageRequest, PackageInspection>('inspect_package', payload);
}

export function createPackage(payload: CreatePackageRequest): Promise<PackageResponse> {
  return command<CreatePackageRequest, PackageResponse>('create_package', payload);
}

export function buildPlan(payload: BuildPlanRequest): Promise<PlanResponse> {
  return command<BuildPlanRequest, PlanResponse>('build_plan', payload);
}

export function startRestore(payload: StartRestoreRequest): Promise<RunHandle> {
  return command<StartRestoreRequest, RunHandle>('start_restore', payload);
}

export function resumeRestore(run_id: string): Promise<RunHandle> {
  const payload: ResumeRestoreRequest = { run_id };
  return command<ResumeRestoreRequest, RunHandle>('resume_restore', payload);
}

export function getRun(run_id: string): Promise<RunResponse> {
  const payload: GetRunRequest = { run_id };
  return command<GetRunRequest, RunResponse>('get_run', payload);
}

export function verify(run_id: string): Promise<ReportResponse> {
  const payload: GetRunRequest = { run_id };
  return command<GetRunRequest, ReportResponse>('verify', payload);
}

export function acknowledgeManualAction(run_id: string, action_id: string): Promise<ManualActionResponse> {
  const payload: AckManualActionRequest = { run_id, action_id };
  return command<AckManualActionRequest, ManualActionResponse>('ack_manual_action', payload);
}

export function saveReport(run_id: string, output_selection_id: string): Promise<ReportResponse> {
  const payload: SaveReportRequest = { run_id, output_selection_id };
  return command<SaveReportRequest, ReportResponse>('save_report', payload);
}

async function selectNative(name: string): Promise<NativeDialogResult> {
  return command<EmptyRequest, NativeDialogResult>(name, {});
}

export function selectPackageFile(): Promise<NativeDialogResult> {
  return selectNative('select_package_file');
}

export function selectPackageDestination(): Promise<NativeDialogResult> {
  return selectNative('select_package_destination');
}

export function selectReportDestination(): Promise<NativeDialogResult> {
  return selectNative('select_report_destination');
}

export function selectedSelectionId(result: NativeDialogResult): string | null {
  return result.status === 'selected' ? result.selection_id : null;
}

export async function subscribeToEvents(handlers: BridgeEventHandlers): Promise<() => void> {
  if (!isDesktopRuntime()) {
    return () => undefined;
  }

  const unlisteners: UnlistenFn[] = [];
  try {
    if (handlers.onProgress) {
      unlisteners.push(
        await listen<EventEnvelope<ProgressEvent>>(EVENTS.progress, (event) => {
          handlers.onProgress?.(event.payload);
        }),
      );
    }
    if (handlers.onRestoreProgress) {
      unlisteners.push(
        await listen<EventEnvelope<RestoreProgressDelta>>(EVENTS.restoreProgress, (event) => {
          handlers.onRestoreProgress?.(event.payload);
        }),
      );
    }
    if (handlers.onReport) {
      unlisteners.push(
        await listen<EventEnvelope<ReportDelta>>(EVENTS.report, (event) => {
          handlers.onReport?.(event.payload);
        }),
      );
    }
    if (handlers.onError) {
      unlisteners.push(
        await listen<EventEnvelope<ErrorEnvelope>>(EVENTS.error, (event) => {
          handlers.onError?.(event.payload);
        }),
      );
    }
  } catch (error) {
    for (const unlisten of unlisteners) {
      unlisten();
    }
    throw normalizeBridgeError(error);
  }

  return () => {
    for (const unlisten of unlisteners) {
      unlisten();
    }
  };
}

export type { RestoreMode } from './generated';
