<script lang="ts">
  import ProgressSummary from '../lib/components/ProgressSummary.svelte';
  import ManualActionList from '../lib/components/ManualActionList.svelte';
  import type { OperationView } from '../lib/api';
  import type { ReforgeState } from '../lib/state.svelte';
  let { state } = $props<{ state: ReforgeState }>();
  let restoreProgress = $derived(state.progress && 'completed' in state.progress && !('phase' in state.progress) ? state.progress : null);
  let currentOperation = $derived(state.run?.operations.find((operation: OperationView) => operation.state === 'RUNNING') ?? null);
</script>

<section class="route wide-route">
  <div class="route-header split-header"><div><p class="eyebrow">03 / Execute</p><h1>Restore is journaled</h1><p class="lede">Completed operations are not replayed after interruption. Keep this window open for manual checkpoints and reboot requests.</p></div>{#if state.runId}<code class="run-id">{state.runId}</code>{/if}</div>

  {#if restoreProgress}
    <ProgressSummary label="Environment restore" completed={restoreProgress.completed} total={restoreProgress.total} status={restoreProgress.status} message={restoreProgress.message} events={state.eventRows} />
  {:else}
    <ProgressSummary
      label="Environment restore"
      completed={0}
      phase="Journal replay"
      status="STARTING"
      message="Waiting for the first restore progress event."
      events={state.eventRows}
    />
  {/if}

  {#if currentOperation}
    <article class="current-operation"><p class="eyebrow">Current operation</p><strong>{currentOperation.operation.kind.type.replaceAll('_', ' ')}</strong><span>{currentOperation.state.replaceAll('_', ' ')} · attempt {currentOperation.attempt}</span></article>
  {/if}

  {#if state.run?.manual_actions.length}
    <ManualActionList actions={state.run.manual_actions} onAcknowledge={(action) => state.acknowledgeAction(action)} disabled={state.busy} />
  {/if}

  <div class="route-actions"><button class="button danger-quiet" type="button" onclick={() => state.cancelCurrentRun()}>Cancel at checkpoint</button><button class="button secondary" type="button" onclick={() => state.verifyCurrentRun()} disabled={!state.runId || state.busy}>Verify current state</button></div>
</section>
