import '@testing-library/jest-dom/vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import ComponentTree from '../src/lib/components/ComponentTree.svelte';
import ErrorAlert from '../src/lib/components/ErrorAlert.svelte';
import ConflictList from '../src/lib/components/ConflictList.svelte';
import ManualActionList from '../src/lib/components/ManualActionList.svelte';
import ProgressSummary from '../src/lib/components/ProgressSummary.svelte';
import TrustNotice from '../src/lib/components/TrustNotice.svelte';
import {
  ComponentKind,
  Confidence,
  ConflictKind,
  ConflictResolution,
  IdentityQuality,
  ManualActionState,
  Portability,
  ReforgeErrorCode,
  Retryability,
  RiskLevel,
  RestoreStrategy,
  TrustState,
} from '../src/lib/generated';
import type { Component, Conflict, ManualAction } from '../src/lib/generated';
import type { ActivityEvent } from '../src/lib/api';

function component(id: string): Component {
  return {
    id,
    kind: ComponentKind.Tool,
    identity: { identity_quality: IdentityQuality.Local },
    display_name: id,
    evidence: [],
    confidence: Confidence.Confirmed,
    dependencies: [],
    artifacts: [],
    restore: {
      primary: RestoreStrategy.ConfigPortable,
      alternatives: [],
      portability: Portability.Portable,
      requires_elevation: false,
      requires_user_action: false,
      rationale: [],
    },
    compatibility: {
      requires_elevation: false,
      requires_wsl: false,
      requires_docker: false,
    },
    verification: [],
    selection: {
      recommended: true,
      score: 1,
      selected_by_default: false,
      sensitive: false,
      size_bytes: 0,
    },
  };
}

function manualAction(id = 'manual-1'): ManualAction {
  return {
    id,
    title: 'Sign in to the provider',
    reason: 'The provider requires an interactive account session.',
    risk: RiskLevel.High,
    instructions: ['Complete sign-in in the provider window.', 'Return here after the account is ready.'],
    state: ManualActionState.Pending,
    independent_operations_may_continue: true,
  };
}

const conflict: Conflict = {
  id: 'conflict-1',
  kind: ConflictKind.DataCollision,
  source_summary: 'Package settings',
  target_summary: 'Existing settings',
  resolution: ConflictResolution.Merge,
  requires_confirmation: true,
};

const activityEvents: ActivityEvent[] = [
  {
    seq: 1,
    run_id: '00000000-0000-7000-8000-000000000001',
    time: '2026-08-31T12:00:00.000Z',
    level: 'PROGRESS',
    message: 'Runtime probes started.',
  },
];

describe('T050 accessibility and honest-progress contracts', () => {
  it('announces paused progress, exposes a determinate bar, and moves focus', async () => {
    const { rerender } = render(ProgressSummary, {
      props: {
        label: 'Restore',
        completed: 2,
        total: 4,
        phase: 'Runtime probes',
        status: 'RUNNING',
        message: 'Applying the next operation',
        events: activityEvents,
      },
    });

    expect(screen.getByRole('progressbar', { name: 'Restore progress' })).toHaveAttribute('value', '50');
    expect(screen.getByText(/RUNNING/)).toBeInTheDocument();

    await rerender({
      label: 'Restore',
      completed: 2,
      total: 4,
      phase: 'Runtime probes',
      status: 'WAITING_FOR_REBOOT',
      message: 'Restart Windows before continuing',
      events: activityEvents,
    });

    await waitFor(() => expect(screen.getByRole('region')).toHaveFocus());
    expect(screen.getByRole('region')).toHaveAttribute('aria-live', 'assertive');
    expect(screen.getByText(/WAITING FOR REBOOT/)).toBeInTheDocument();
    expect(screen.getByText('Restart Windows before continuing')).toBeInTheDocument();
    expect(screen.getByRole('list', { name: 'Restore activity log' })).toHaveTextContent('Runtime probes started.');
  });

  it('moves focus to a global error and keeps technical detail out of the UI', async () => {
    const user = userEvent.setup();
    const onDismiss = vi.fn();
    render(ErrorAlert, {
      error: {
        code: ReforgeErrorCode.OperationFailed,
        message: 'The installer did not complete.',
        technical_detail: 'C:\\private\\secret.log',
        retryability: Retryability.SafeRetry,
      },
      onDismiss,
    });

    const alert = screen.getByRole('alert');
    await waitFor(() => expect(alert).toHaveFocus());
    expect(alert).toHaveTextContent('OPERATION FAILED');
    expect(alert).not.toHaveTextContent('C:\\private\\secret.log');
    await user.tab();
    expect(screen.getByRole('button', { name: 'Dismiss error' })).toHaveFocus();
    await user.keyboard('{Enter}');
    expect(onDismiss).toHaveBeenCalledOnce();
  });

  it('keeps unknown totals indeterminate instead of reporting false completion', () => {
    render(ProgressSummary, {
      label: 'Scan',
      completed: 3,
      phase: 'Discovery',
      status: 'PROGRESS',
      message: 'Adapter is still enumerating',
    });

    const progress = screen.getByRole('progressbar', { name: 'Scan progress' });
    expect(progress).not.toHaveAttribute('value');
    expect(screen.getByText('—')).toBeInTheDocument();
  });

  it('renders every trust state as text and keeps approval explicit', async () => {
    const user = userEvent.setup();
    const onApprove = vi.fn();
    render(TrustNotice, { trust: TrustState.SignatureInvalid, approved: false, onApprove });

    expect(screen.getByRole('heading', { name: 'Invalid signature' })).toBeInTheDocument();
    expect(screen.getByText(/blocked by its trust state/i)).toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole('region')).toHaveFocus());
    const approval = screen.getByRole('checkbox', { name: /reviewed the package/i });
    expect(approval).toBeVisible();
    await user.click(approval);
    expect(onApprove).toHaveBeenCalledWith(true);
  });

  it('focuses the first manual checkpoint and supports keyboard acknowledgement', async () => {
    const user = userEvent.setup();
    const action = manualAction();
    const onAcknowledge = vi.fn();
    render(ManualActionList, { actions: [action], onAcknowledge });

    const acknowledge = screen.getByRole('button', { name: 'Acknowledge Sign in to the provider' });
    await waitFor(() => expect(acknowledge).toHaveFocus());
    expect(screen.getByRole('status')).toHaveAccessibleName('1 pending manual actions, 1 total');
    await user.keyboard('{Enter}');
    expect(onAcknowledge).toHaveBeenCalledWith(action);
  });

  it('announces conflict confirmation requirements and hands off focus on arrival', async () => {
    const { rerender } = render(ConflictList, { conflicts: [] });
    await rerender({ conflicts: [conflict] });

    await waitFor(() => expect(screen.getByRole('region')).toHaveFocus());
    expect(screen.getByRole('status')).toHaveAccessibleName('1 conflicts, 1 require confirmation');
    expect(screen.getByText('Confirmation required')).toBeInTheDocument();
    expect(screen.getByRole('listitem')).toHaveTextContent('DATA COLLISION');
  });

  it('virtualizes large component inventories without losing keyboard selection', async () => {
    const user = userEvent.setup();
    const onToggle = vi.fn();
    const components = Array.from({ length: 1500 }, (_, index) => component(`component-${index}`));
    render(ComponentTree, { components, selected: [], onToggle });

    const tree = screen.getByRole('list', { name: 'Inventory components' });
    expect(screen.getAllByRole('checkbox').length).toBeLessThanOrEqual(48);
    const first = screen.getByRole('checkbox', { name: 'Select component-0' });
    const firstItem = first.closest('[role="listitem"]');
    if (!firstItem) throw new Error('Expected the first component to retain list semantics');
    expect(firstItem).toHaveAttribute('aria-posinset', '1');

    await user.tab();
    expect(first).toHaveFocus();
    await user.keyboard(' ');
    expect(onToggle).toHaveBeenCalledWith('component-0', true);

    tree.scrollTop = 1499 * 64;
    await fireEvent.scroll(tree);
    const last = await screen.findByRole('checkbox', { name: 'Select component-1499' });
    const lastItem = last.closest('[role="listitem"]');
    if (!lastItem) throw new Error('Expected the last component to retain list semantics');
    expect(lastItem).toHaveAttribute('aria-posinset', '1500');
    last.focus();
    await user.keyboard(' ');
    expect(onToggle).toHaveBeenCalledWith('component-1499', true);
  });
});
