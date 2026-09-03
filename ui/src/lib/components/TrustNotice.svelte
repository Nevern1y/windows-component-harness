<script lang="ts">
  import { TrustState } from '../generated';
  import type { TrustState as TrustStateType } from '../generated';

  let { trust, approved, onApprove, disabled = false } = $props<{
    trust: TrustStateType;
    approved: boolean;
    onApprove: (approved: boolean) => void;
    disabled?: boolean;
  }>();

  type TrustKind = 'verified' | 'review' | 'blocked';
  type TrustCopy = { label: string; detail: string; kind: TrustKind };
  const TRUST_COPY: Record<TrustStateType, TrustCopy> = {
    [TrustState.Unchecked]: { label: 'Not checked', detail: 'Integrity has not been evaluated yet.', kind: 'review' },
    [TrustState.IntegrityVerified]: { label: 'Integrity verified', detail: 'The archive integrity check passed. Provenance may still require review.', kind: 'verified' },
    [TrustState.Unsigned]: { label: 'Unsigned package', detail: 'No signature was provided. Review the source before approving.', kind: 'review' },
    [TrustState.SignatureInvalid]: { label: 'Invalid signature', detail: 'The signature did not verify. Treat this package as untrusted.', kind: 'blocked' },
    [TrustState.SignatureValidUntrusted]: { label: 'Valid signature · untrusted signer', detail: 'The signature is valid, but the signer is not in the trusted set.', kind: 'review' },
    [TrustState.SignatureValidTrusted]: { label: 'Trusted signature', detail: 'The signature and trusted signer checks passed.', kind: 'verified' },
    [TrustState.UserApproved]: { label: 'User approved', detail: 'This package has an explicit approval decision for the current restore.', kind: 'verified' },
    [TrustState.Rejected]: { label: 'Rejected package', detail: 'This package was rejected and must not be restored.', kind: 'blocked' },
  };
  const UNKNOWN_TRUST_COPY: TrustCopy = {
    label: 'Unsupported trust state',
    detail: 'The desktop received a trust value it does not understand. This package remains blocked.',
    kind: 'blocked',
  };

  let trustRegion: HTMLElement;
  let knownTrust = $derived(Object.hasOwn(TRUST_COPY, trust));
  let trustCopy = $derived(knownTrust ? TRUST_COPY[trust as TrustStateType] : UNKNOWN_TRUST_COPY);
  let isUnsafe = $derived(trustCopy.kind === 'blocked');

  $effect(() => {
    if (!isUnsafe) return;
    queueMicrotask(() => trustRegion?.focus());
  });
</script>

<section
  class="trust-notice"
  class:unsafe={isUnsafe}
  aria-live={isUnsafe ? 'assertive' : 'polite'}
  aria-atomic="true"
  aria-labelledby="trust-title"
  aria-describedby="trust-detail"
  role={knownTrust ? undefined : 'alert'}
  tabindex="-1"
  bind:this={trustRegion}
>
  <div class="trust-mark" aria-hidden="true">{isUnsafe ? '!' : '✓'}</div>
  <div class="trust-copy">
    <p class="eyebrow">Trust boundary</p>
    <h2 id="trust-title">{trustCopy.label}</h2>
    <p id="trust-detail">{trustCopy.detail}</p>
    <p>Integrity and provenance are checked by the Rust engine. User approval is a separate decision and never grants the package filesystem or shell access.</p>
    {#if !knownTrust}<p class="warning-text">This package is blocked because the desktop received unsupported trust data. Update the desktop and engine together before continuing.</p>
    {:else if isUnsafe}<p class="warning-text">This package is blocked by its trust state. Approval will not bypass backend policy.</p>{/if}
    <div class="trust-state-line"><span class="trust-state state-{trustCopy.kind}">{trustCopy.kind.replaceAll('_', ' ')}</span><span>backend policy remains authoritative</span></div>
    <label class="approval-row" for="package-approval">
      <input id="package-approval" type="checkbox" checked={approved} disabled={disabled || !knownTrust} aria-describedby="trust-detail" onchange={(event) => onApprove(event.currentTarget.checked)} />
      <span>I have reviewed the package and approve this restore plan.</span>
    </label>
  </div>
</section>
