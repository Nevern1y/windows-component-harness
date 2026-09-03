<script lang="ts">
  import type { ErrorEnvelope } from '../generated';

  let {
    error,
    onDismiss,
  } = $props<{
    error: ErrorEnvelope;
    onDismiss: () => void;
  }>();

  let errorRegion: HTMLElement;

  $effect(() => {
    void error;
    queueMicrotask(() => errorRegion?.focus());
  });
</script>

<aside class="app-alert error" role="alert" tabindex="-1" bind:this={errorRegion}>
  <div>
    <strong>{error.code.replaceAll('_', ' ')}</strong>
    <p>{error.message}</p>
  </div>
  <div class="alert-actions">
    <span>{error.retryability.replaceAll('_', ' ')}</span>
    <button class="toolbar-icon" type="button" aria-label="Dismiss error" onclick={onDismiss}>×</button>
  </div>
</aside>
