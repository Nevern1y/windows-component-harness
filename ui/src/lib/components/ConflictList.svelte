<script lang="ts">
  import { conflictDisplay } from '../state.svelte';
  import type { Conflict } from '../generated';

  let { conflicts = [] } = $props<{ conflicts?: Conflict[] }>();
  let conflictRegion: HTMLElement;
  let confirmationCount = $derived(conflicts.filter((conflict: Conflict) => conflict.requires_confirmation).length);
  let previousConflictCount = $state(0);

  $effect(() => {
    const count = conflicts.length;
    if (count > 0 && previousConflictCount === 0) queueMicrotask(() => conflictRegion?.focus());
    previousConflictCount = count;
  });
</script>

<section
  class="stack-section"
  aria-labelledby="conflict-title"
  aria-describedby="conflict-summary"
  aria-live="polite"
  tabindex="-1"
  bind:this={conflictRegion}
>
  <div class="section-heading">
    <div>
      <p class="eyebrow">Target review</p>
      <h2 id="conflict-title">Conflicts and resolutions</h2>
    </div>
    <span class:warning={confirmationCount > 0} class="count-badge" id="conflict-summary" role="status" aria-label={`${conflicts.length} conflicts, ${confirmationCount} require confirmation`}>{conflicts.length}</span>
  </div>
  {#if conflicts.length === 0}
    <div class="empty-state compact"><strong>No conflicts detected.</strong><span>The plan can proceed with its declared idempotent operations.</span></div>
  {:else}
    <div class="conflict-list" role="list">
      {#each conflicts as conflict (conflict.id)}
        {@const display = conflictDisplay(conflict)}
        <article class="conflict-row" class:needs-confirmation={display.requires_confirmation} role="listitem">
          <div class="conflict-main">
            <strong>{display.title}</strong>
            <span>{conflict.source_summary}</span>
            <span class="muted">Target: {conflict.target_summary}</span>
          </div>
          <div class="conflict-resolution">
            <span class="tag">{display.resolution}</span>
            {#if display.requires_confirmation}<span class="warning-text">Confirmation required</span>{/if}
          </div>
        </article>
      {/each}
    </div>
  {/if}
</section>
