<script lang="ts">
  import ComponentTree from '../lib/components/ComponentTree.svelte';
  import { formatBytes } from '../lib/state.svelte';
  import type { Component } from '../lib/generated';
  import type { ReforgeState } from '../lib/state.svelte';
  let { state } = $props<{ state: ReforgeState }>();
  let inventory = $derived(state.inventory);
</script>

<section class="route wide-route">
  {#if inventory}
    <div class="route-header split-header">
      <div>
        <p class="eyebrow">01 / Discover · complete</p>
        <h1>Inventory captured</h1>
        <p class="lede">Review what Reforge found before selecting the portable slice. Evidence and warnings stay attached to this scan.</p>
      </div>
      <div class="metric-cluster" aria-label="Inventory summary">
        <div><strong>{inventory.graph.components.length}</strong><span>components</span></div>
        <div><strong>{inventory.evidence.length}</strong><span>evidence records</span></div>
        <div><strong>{formatBytes(inventory.graph.components.reduce((sum: number, item: Component) => sum + item.selection.size_bytes, 0))}</strong><span>estimated artifacts</span></div>
      </div>
    </div>

    {#if inventory.warnings.length > 0}
      <aside class="notice warning" aria-label="Scan warnings">
        <strong>{inventory.warnings.length} scan warning{inventory.warnings.length === 1 ? '' : 's'}</strong>
        <ul>{#each inventory.warnings as warning}<li>{warning}</li>{/each}</ul>
      </aside>
    {/if}

    <ComponentTree
      components={inventory.graph.components}
      selected={state.selection?.components ?? []}
      autoAdded={state.autoAddedComponents}
      onToggle={(id, selected) => state.setComponentSelected(id, selected)}
    />

    <div class="route-actions">
      <button class="button primary" type="button" onclick={() => state.go('selection')}>Review selection <span aria-hidden="true">→</span></button>
      <button class="button secondary" type="button" onclick={() => state.refreshInventory()}>Refresh scan</button>
    </div>
  {:else}
    <div class="empty-state">No inventory is loaded. Start a scan first.</div>
  {/if}
</section>
