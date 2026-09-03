<script lang="ts">
  import ConflictList from '../lib/components/ConflictList.svelte';
  import type { ReforgeState } from '../lib/state.svelte';

  let { state } = $props<{ state: ReforgeState }>();
  let plan = $derived(state.plan);
</script>

<section class="route wide-route">
  {#if plan}
    <div class="route-header split-header">
      <div>
        <p class="eyebrow">03 / Target analysis</p>
        <h1>Target is understood</h1>
        <p class="lede">The engine compared package requirements with this machine and produced an explicit operation graph. Nothing has been changed.</p>
      </div>
      <div class="target-fingerprint"><span>Target fingerprint</span><code>{plan.target_fingerprint}</code></div>
    </div>

    <div class="metric-band">
      <div><strong>{plan.selected_components.length}</strong><span>selected components</span></div>
      <div><strong>{plan.operations.length}</strong><span>planned operations</span></div>
      <div><strong>{plan.conflicts.length}</strong><span>conflicts</span></div>
      <div><strong>{plan.manual_actions.length}</strong><span>manual actions</span></div>
    </div>

    <ConflictList conflicts={plan.conflicts} />
    {#if plan.warnings.length > 0}<aside class="notice warning"><strong>Plan warnings</strong><ul>{#each plan.warnings as warning}<li>{warning}</li>{/each}</ul></aside>{/if}

    <div class="route-actions">
      <button class="button primary" type="button" onclick={() => state.showRestorePlan()}>Review restore plan <span aria-hidden="true">→</span></button>
      <button class="button secondary" type="button" onclick={() => state.go('package_review')}>Back to package</button>
    </div>
  {:else}
    <div class="empty-state">Run target analysis from package review first.</div>
  {/if}
</section>
