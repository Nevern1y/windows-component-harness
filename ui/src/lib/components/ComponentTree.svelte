<script lang="ts">
  import type { Component } from '../generated';
  import { formatBytes } from '../state.svelte';

  const VIRTUALIZE_AFTER = 120;
  const ROW_HEIGHT = 64;
  const WINDOW_ROWS = 18;
  const OVERSCAN_ROWS = 6;

  let {
    components,
    selected,
    autoAdded = [],
    onToggle,
    disabled = false,
  } = $props<{
    components: Component[];
    selected: string[];
    autoAdded?: string[];
    onToggle: (componentId: string, selected: boolean) => void;
    disabled?: boolean;
  }>();

  let virtualStart = $state(0);
  let selectedSet = $derived(new Set(selected));
  let autoAddedSet = $derived(new Set(autoAdded));
  let virtualized = $derived(components.length > VIRTUALIZE_AFTER);
  let visibleStart = $derived(
    virtualized ? Math.min(virtualStart, Math.max(0, components.length - WINDOW_ROWS)) : 0,
  );
  let visibleEnd = $derived(
    virtualized
      ? Math.min(components.length, visibleStart + WINDOW_ROWS + OVERSCAN_ROWS * 2)
      : components.length,
  );
  let visibleComponents = $derived(components.slice(visibleStart, visibleEnd));
  let topSpacer = $derived(virtualized ? visibleStart * ROW_HEIGHT : 0);
  let bottomSpacer = $derived(virtualized ? Math.max(0, components.length - visibleEnd) * ROW_HEIGHT : 0);

  function updateVirtualStart(nextStart: number): void {
    const maximumStart = Math.max(0, components.length - WINDOW_ROWS);
    virtualStart = Math.min(maximumStart, Math.max(0, nextStart));
  }

  function handleScroll(event: Event): void {
    if (!virtualized) return;
    const viewport = event.currentTarget as HTMLDivElement;
    updateVirtualStart(Math.floor(viewport.scrollTop / ROW_HEIGHT) - OVERSCAN_ROWS);
  }

  function ensureKeyboardRange(index: number): void {
    if (!virtualized) return;
    const bufferedStart = visibleStart + OVERSCAN_ROWS;
    const bufferedEnd = Math.max(bufferedStart, visibleEnd - OVERSCAN_ROWS - 1);
    if (index < bufferedStart || index > bufferedEnd) {
      updateVirtualStart(index - Math.floor(WINDOW_ROWS / 2));
    }
  }
</script>

<section class="component-tree" aria-labelledby="component-tree-title">
  <div class="section-heading">
    <div>
      <p class="eyebrow">Inventory graph</p>
      <h2 id="component-tree-title">Components and dependencies</h2>
    </div>
    <span class="muted">{selected.length} selected</span>
  </div>

  <div class="tree-list" class:virtualized role="list" aria-label="Inventory components" onscroll={handleScroll}>
    {#if components.length === 0}
      <p class="empty-state">No components were returned by the scan.</p>
    {:else}
      {#if virtualized}<div class="tree-spacer" style:height={`${topSpacer}px`} aria-hidden="true"></div>{/if}
      {#each visibleComponents as component, index (component.id)}
        {@const absoluteIndex = visibleStart + index}
        <label
          class:selected={selectedSet.has(component.id)}
          class:auto-added={autoAddedSet.has(component.id)}
          class="tree-row"
          role="listitem"
          aria-setsize={components.length}
          aria-posinset={absoluteIndex + 1}
        >
          <input
            type="checkbox"
            checked={selectedSet.has(component.id)}
            disabled={disabled}
            aria-label={`Select ${component.display_name}`}
            onfocus={() => ensureKeyboardRange(absoluteIndex)}
            onchange={(event) => onToggle(component.id, event.currentTarget.checked)}
          />
          <span class="tree-copy">
            <strong>{component.display_name}</strong>
            <span class="tree-meta">
              {component.kind.replaceAll('_', ' ')}
              {#if component.version?.raw} · {component.version.raw}{/if}
              · {component.artifacts.length} artifact{component.artifacts.length === 1 ? '' : 's'}
            </span>
          </span>
          <span class="tree-side">
            {#if autoAddedSet.has(component.id)}<span class="tag">required dependency</span>{/if}
            <span class="confidence">{component.confidence.replaceAll('_', ' ')}</span>
            <span class="size">{formatBytes(component.selection.size_bytes)}</span>
          </span>
        </label>
      {/each}
      {#if virtualized}<div class="tree-spacer" style:height={`${bottomSpacer}px`} aria-hidden="true"></div>{/if}
    {/if}
  </div>
  <p class="field-note">Selecting a component includes required dependencies. Secret references stay excluded.</p>
</section>
