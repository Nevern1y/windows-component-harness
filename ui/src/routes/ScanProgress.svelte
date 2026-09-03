<script lang="ts">
  import ProgressSummary from '../lib/components/ProgressSummary.svelte';
  import type { ReforgeState } from '../lib/state.svelte';

  let { state } = $props<{ state: ReforgeState }>();
  let scanProgress = $derived(state.progress && 'phase' in state.progress ? state.progress : null);
</script>

<section class="route narrow-route">
  <div class="route-header">
    <p class="eyebrow">01 / Discover</p>
    <h1>Scanning the current user environment</h1>
    <p class="lede">The engine reads supported Windows sources and records provenance. It does not copy files until you choose a package selection.</p>
  </div>

  {#if scanProgress}
    <ProgressSummary
      label="Environment scan"
      completed={scanProgress.completed}
      total={scanProgress.total}
      phase={scanProgress.phase.replaceAll('_', ' ')}
      status={scanProgress.status}
      message={scanProgress.message}
      bytes={scanProgress.bytes}
      events={state.eventRows}
    />
  {:else}
    <ProgressSummary
      label="Environment scan"
      completed={0}
      phase="Discovery"
      status="STARTING"
      message="Waiting for the first typed progress event from the desktop engine."
      events={state.eventRows}
    />
  {/if}

  <div class="route-actions">
    <button class="button secondary" type="button" disabled={state.busy} onclick={() => state.refreshInventory()}>Refresh inventory</button>
    <button class="button danger-quiet" type="button" onclick={() => state.cancelCurrentRun()}>Cancel safely</button>
  </div>
  <p class="field-note">Cancellation is journaled and will not replay completed destructive operations.</p>
</section>
