<script lang="ts">
  import type { ActivityEvent } from '../api';
  import { progressPercent } from '../state.svelte';

  const timeFormatter = new Intl.DateTimeFormat(undefined, {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });

  let {
    label,
    completed,
    total,
    phase,
    status,
    message,
    bytes,
    events = [],
  } = $props<{
    label: string;
    completed: number;
    total?: number;
    phase?: string;
    status: string;
    message: string;
    bytes?: number;
    events?: ActivityEvent[];
  }>();

  let progressRegion: HTMLElement;
  let percent = $derived(progressPercent(completed, total));
  let isDeterminate = $derived(total !== undefined && total > 0);
  let needsAttention = $derived(status === 'FAILED' || status === 'WAITING_FOR_USER' || status === 'WAITING_FOR_REBOOT' || status === 'CANCELLED');
  let statusLabel = $derived(status.replaceAll('_', ' '));
  let progressText = $derived(isDeterminate ? `${percent}% complete` : `${completed} completed; total pending`);

  function formatEventTime(time: string): string {
    const timestamp = Date.parse(time);
    return Number.isNaN(timestamp) ? 'Unknown time' : timeFormatter.format(timestamp);
  }

  $effect(() => {
    if (!needsAttention) return;
    queueMicrotask(() => progressRegion?.focus());
  });
</script>

<section
  class="progress-card"
  class:needs-attention={needsAttention}
  aria-live={needsAttention ? 'assertive' : 'polite'}
  aria-atomic="true"
  aria-labelledby="progress-title"
  aria-describedby="progress-message"
  tabindex="-1"
  bind:this={progressRegion}
>
  <div class="section-heading">
    <div>
      <p class="eyebrow">{phase ?? 'Operation'}</p>
      <h2 id="progress-title">{label}</h2>
    </div>
    <strong class="progress-percent" aria-label={progressText}>{isDeterminate ? `${percent}%` : '—'}</strong>
  </div>
  {#if isDeterminate}
    <progress max="100" value={percent} aria-label={`${label} progress`}>{percent}%</progress>
  {:else}
    <progress max="100" aria-label={`${label} progress`} aria-valuetext={progressText}></progress>
  {/if}
  <div class="progress-foot">
    <span>{completed}{total ? ` of ${total}` : ''} completed{#if bytes !== undefined} · {bytes.toLocaleString()} bytes{/if}</span>
    <span class="status-text status-{status.toLowerCase()}"><span class="status-symbol" aria-hidden="true">{needsAttention ? '!' : '·'}</span>{statusLabel}</span>
  </div>
  <p id="progress-message" class="progress-message">{message}</p>

  <details class="activity-log" open={needsAttention}>
    <summary><span>Activity log</span><span class="activity-log-count">{events.length} latest update{events.length === 1 ? '' : 's'}</span></summary>
    {#if events.length === 0}
      <p class="activity-log-empty">No events have been recorded yet.</p>
    {:else}
      <ol class="activity-log-list" aria-label={`${label} activity log`}>
        {#each events as event (event.seq)}
          <li class="activity-log-row">
            <time class="activity-log-time" datetime={event.time}>{formatEventTime(event.time)}</time>
            <span class="activity-log-level">{event.level.replaceAll('_', ' ')}</span>
            <span class="activity-log-message">{event.message}</span>
          </li>
        {/each}
      </ol>
    {/if}
  </details>
</section>
