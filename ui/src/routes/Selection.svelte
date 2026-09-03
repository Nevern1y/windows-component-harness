<script lang="ts">
  import ComponentTree from '../lib/components/ComponentTree.svelte';
  import { formatBytes } from '../lib/state.svelte';
  import type { ReforgeState } from '../lib/state.svelte';

  let { state } = $props<{ state: ReforgeState }>();
  let inventory = $derived(state.inventory);
</script>

<section class="route wide-route">
  {#if inventory}
    <div class="route-header split-header">
      <div>
        <p class="eyebrow">02 / Select</p>
        <h1>Choose the portable slice</h1>
        <p class="lede">Required dependencies are closed automatically. Sensitive values are represented as references or excluded; they never enter package bytes.</p>
      </div>
      <div class="selection-total">
        <strong>{state.selectedCount}</strong>
        <span>components selected</span>
        <span class="accent-text">{formatBytes(state.selectedBytes)} estimated</span>
      </div>
    </div>

    <ComponentTree
      components={inventory.graph.components}
      selected={state.selection?.components ?? []}
      autoAdded={state.autoAddedComponents}
      onToggle={(id, selected) => state.setComponentSelected(id, selected)}
    />

    <div class="policy-strip">
      <span class="policy-label">Selection policy</span>
      <span>Secrets: exclude</span>
      <span>Large data: confirm</span>
      <span>Unknown binaries: exclude</span>
    </div>

    <div class="route-actions">
      <button class="button primary" type="button" disabled={state.selectedCount === 0 || state.busy} onclick={() => state.createPackageFromSelection()}>Create package <span aria-hidden="true">→</span></button>
      <button class="button secondary" type="button" onclick={() => state.go('scan_results')}>Back to inventory</button>
    </div>
  {:else}
    <div class="empty-state">Scan an environment before selecting components.</div>
  {/if}
</section>
