<script lang="ts">
  import type { ManualAction } from '../generated';

  let { actions = [], onAcknowledge, disabled = false } = $props<{
    actions?: ManualAction[];
    onAcknowledge?: (action: ManualAction) => void;
    disabled?: boolean;
  }>();

  let manualRegion: HTMLElement;
  let pendingCount = $derived(actions.filter((action: ManualAction) => action.state === 'PENDING').length);
  let firstPendingActionId = $derived(actions.find((action: ManualAction) => action.state === 'PENDING')?.id);
  let previousPendingCount = 0;

  $effect(() => {
    const pending = pendingCount;
    if (pending > 0 && pending !== previousPendingCount) {
      queueMicrotask(() => manualRegion?.querySelector<HTMLButtonElement>('[data-first-pending="true"]')?.focus());
    }
    previousPendingCount = pending;
  });
</script>

<section
  class="stack-section"
  aria-labelledby="manual-actions-title"
  aria-describedby="manual-actions-summary"
  aria-live={pendingCount > 0 ? 'assertive' : 'polite'}
  aria-atomic="true"
  tabindex="-1"
  bind:this={manualRegion}
>
  <div class="section-heading">
    <div>
      <p class="eyebrow">Human checkpoints</p>
      <h2 id="manual-actions-title">Manual actions</h2>
    </div>
    <span class="count-badge" id="manual-actions-summary" role="status" aria-label={`${pendingCount} pending manual actions, ${actions.length} total`}>{pendingCount} pending</span>
  </div>
  {#if actions.length === 0}
    <div class="empty-state compact"><strong>No manual actions.</strong><span>Independent operations can continue without user intervention.</span></div>
  {:else}
    <div class="manual-list" role="list">
      {#each actions as action (action.id)}
        <article class="manual-row" class:acknowledged={action.state !== 'PENDING'} role="listitem">
          <div class="manual-copy">
            <div class="inline-labels">
              <strong>{action.title}</strong>
              <span class="risk risk-{action.risk.toLowerCase()}">{action.risk}</span>
            </div>
            <p>{action.reason}</p>
            <ol>
              {#each action.instructions as instruction}<li>{instruction}</li>{/each}
            </ol>
            {#if action.docs_url}<a class="manual-link" href={action.docs_url} target="_blank" rel="noreferrer">Open supporting documentation</a>{/if}
            {#if action.independent_operations_may_continue}<span class="field-note">Independent operations may continue.</span>{/if}
          </div>
          {#if action.state === 'PENDING'}
            <button class="button secondary" type="button" data-first-pending={action.id === firstPendingActionId ? 'true' : undefined} disabled={disabled} aria-label={`Acknowledge ${action.title}`} onclick={() => onAcknowledge?.(action)}>Acknowledge</button>
          {:else}
            <span class="tag success-tag">{action.state.replaceAll('_', ' ')}</span>
          {/if}
        </article>
      {/each}
    </div>
  {/if}
</section>
