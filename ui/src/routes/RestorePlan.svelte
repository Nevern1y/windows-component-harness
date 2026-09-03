<script lang="ts">
  import ConflictList from '../lib/components/ConflictList.svelte';
  import ManualActionList from '../lib/components/ManualActionList.svelte';
  import type { Conflict } from '../lib/generated';
  import type { ReforgeState } from '../lib/state.svelte';
  let { state } = $props<{ state: ReforgeState }>();
  let plan = $derived(state.plan);
</script>

<section class="route wide-route">
  {#if plan}
    <div class="route-header split-header">
      <div>
        <p class="eyebrow">03 / Approve</p>
        <h1>Review the restore plan</h1>
        <p class="lede">Every operation has an idempotency key, prerequisites, and a verification rule. Approving starts the journaled run; it does not bypass blockers.</p>
      </div>
      <div class="approval-stamp" class:approved={state.packageApproved}><span>{state.packageApproved ? 'APPROVED' : 'PENDING'}</span><small>package decision</small></div>
    </div>

    <div class="operation-table" aria-labelledby="operation-table-title">
      <div class="section-heading"><div><p class="eyebrow">Execution graph</p><h2 id="operation-table-title">Operations</h2></div><span class="count-badge">{plan.operations.length}</span></div>
      {#if plan.operations.length === 0}<div class="empty-state compact">No operations are required; verification can confirm the target as already satisfied.</div>{:else}
        {#each plan.operations as operation (operation.id)}
          <div class="operation-row"><code>{operation.id}</code><strong>{operation.kind.type.replaceAll('_', ' ')}</strong><span>{operation.requires_elevation ? 'Elevation' : 'User scope'}</span><span>{operation.non_idempotent ? 'Non-idempotent' : 'Idempotent'}</span></div>
        {/each}
      {/if}
    </div>

    <ConflictList conflicts={plan.conflicts} />
    <ManualActionList actions={plan.manual_actions} onAcknowledge={(action) => state.acknowledgeAction(action)} disabled={state.busy} />

    <div class="approval-footer">
      <div><strong>Ready to start?</strong><span>{plan.operations.length} operations · {plan.conflicts.filter((conflict: Conflict) => conflict.requires_confirmation).length} confirmations · {plan.manual_actions.length} manual checkpoints</span></div>
      <div class="route-actions"><button class="button primary" type="button" disabled={!state.packageApproved || state.busy} onclick={() => state.beginRestore()}>Start restore <span aria-hidden="true">→</span></button><button class="button secondary" type="button" onclick={() => state.go('target_analysis')}>Back</button></div>
    </div>
  {:else}
    <div class="empty-state">Build a target plan before approving restore.</div>
  {/if}
</section>
