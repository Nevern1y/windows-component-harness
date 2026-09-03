import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import {
  conflictDisplay,
  formatBytes,
  isActivationKey,
  progressPercent,
  reportTotal,
  selectionClosure,
} from './state.svelte';
import {
  ArtifactPolicy,
  ComponentKind,
  ConfigScope,
  Confidence,
  ContentType,
  DependencyKind,
  IdentityQuality,
  Portability,
  RestoreStrategy,
  TrustState,
} from './generated';
import type { Component, Conflict, DependencyEdge, RestoreReport } from './generated';
import TrustNotice from './components/TrustNotice.svelte';

function component(id: string, dependencies: DependencyEdge[] = []): Component {
  return {
    id,
    kind: ComponentKind.Tool,
    identity: { identity_quality: IdentityQuality.Local },
    display_name: id,
    evidence: [],
    confidence: Confidence.Confirmed,
    dependencies,
    artifacts: [
      {
        id: `artifact-${id}`,
        source_path: { root: { type: 'USER_PROFILE' }, relative: `${id}.json` },
        scope: ConfigScope.User,
        size_bytes: id === 'cmp_app' ? 1024 : 2048,
        content_type: ContentType.Json,
        policy: ArtifactPolicy.Config,
      },
    ],
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
      selected_by_default: true,
      sensitive: false,
      size_bytes: id === 'cmp_app' ? 1024 : 2048,
    },
  };
}

const counts: RestoreReport['counts'] = {
  verified: 2,
  partial: 1,
  already_present: 0,
  waiting_for_user: 1,
  reauth_required: 0,
  reboot_required: 0,
  unsupported: 0,
  failed: 1,
};

describe('Reforge UI behavior contracts', () => {
  it('closes required dependencies without including optional edges', () => {
    const required: DependencyEdge = { from: 'cmp_app', to: 'cmp_runtime', kind: DependencyKind.RequiredRuntime, required: true, evidence: [], confidence: Confidence.Confirmed };
    const optional: DependencyEdge = { from: 'cmp_app', to: 'cmp_docs', kind: DependencyKind.RelatedOnly, required: false, evidence: [], confidence: Confidence.Low };
    const graph = {
      components: [component('cmp_app', [required, optional]), component('cmp_runtime'), component('cmp_docs')],
      edges: [required, optional],
    };

    expect(selectionClosure(graph, ['cmp_app'])).toEqual({
      selected: ['cmp_app', 'cmp_runtime'],
      auto_added: ['cmp_runtime'],
      total_bytes: 3072,
    });
  });

  it('clamps progress to a stable accessible percentage', () => {
    expect(progressPercent(0, 10)).toBe(0);
    expect(progressPercent(4, 10)).toBe(40);
    expect(progressPercent(11, 10)).toBe(100);
    expect(progressPercent(1)).toBe(100);
  });

  it('renders conflict semantics without losing confirmation state', () => {
    const conflict = {
      id: 'conflict-1',
      kind: 'DATA_COLLISION',
      source_summary: 'Package settings',
      target_summary: 'Existing settings',
      resolution: 'MERGE',
      requires_confirmation: true,
    } as Conflict;

    expect(conflictDisplay(conflict)).toEqual({
      title: 'DATA COLLISION',
      resolution: 'MERGE',
      requires_confirmation: true,
    });
  });

  it('totals report categories for the verification summary', () => {
    expect(reportTotal(counts)).toBe(5);
  });

  it('accepts keyboard activation keys used by accessible controls', () => {
    expect(isActivationKey('Enter')).toBe(true);
    expect(isActivationKey(' ')).toBe(true);
    expect(isActivationKey('Escape')).toBe(false);
  });

  it('blocks an unsupported trust DTO instead of rendering a permissive state', () => {
    render(TrustNotice, {
      trust: 'FUTURE_TRUST_STATE' as TrustState,
      approved: false,
      onApprove: () => undefined,
    });

    expect(screen.getByRole('alert')).toHaveTextContent('Unsupported trust state');
    expect(screen.getByText(/unsupported trust data/i)).toBeInTheDocument();
    expect(screen.getByRole('checkbox', { name: /reviewed the package/i })).toBeDisabled();
  });

  it('formats artifact sizes for compact metric labels', () => {
    expect(formatBytes(0)).toBe('0 B');
    expect(formatBytes(1024)).toBe('1.0 KB');
    expect(formatBytes(1024 * 1024 * 2)).toBe('2.0 MB');
  });
});
