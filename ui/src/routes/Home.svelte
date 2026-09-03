<script lang="ts">
  import HistoryIcon from '@lucide/svelte/icons/history';
  import PackageOpenIcon from '@lucide/svelte/icons/package-open';
  import ScanLineIcon from '@lucide/svelte/icons/scan-line';
  import ShieldCheckIcon from '@lucide/svelte/icons/shield-check';
  import type { ReforgeState } from '../lib/state.svelte';

  let { state } = $props<{ state: ReforgeState }>();
</script>

<section class="route route-home">
  <div class="home-header">
    <div>
      <p class="eyebrow">Workspace overview</p>
      <h1>Rebuild your Windows environment</h1>
      <p class="lede">A reviewable, resumable path from a working machine to a portable environment package. The Rust engine owns discovery, policy, and filesystem changes.</p>
    </div>
    <div class="home-status" role="status">
      <span class:connected={state.desktopRuntime} class="status-indicator" aria-hidden="true"></span>
      <span>{state.desktopRuntime ? 'Desktop engine ready' : 'Preview mode'}</span>
    </div>
  </div>

  <div class="home-action-grid">
    <button class="home-card home-card-primary" type="button" disabled={state.busy} onclick={() => state.startScan()}>
      <span class="home-card-icon" aria-hidden="true"><ScanLineIcon size={19} strokeWidth={1.9} /></span>
      <span class="home-card-copy"><strong>Scan this machine</strong><small>Discover applications, runtimes, tools, data, and safe configuration references.</small></span>
      <span class="home-card-arrow" aria-hidden="true">→</span>
    </button>
    <button class="home-card" type="button" disabled={state.busy} onclick={() => state.openPackage()}>
      <span class="home-card-icon" aria-hidden="true"><PackageOpenIcon size={19} strokeWidth={1.9} /></span>
      <span class="home-card-copy"><strong>Open a package</strong><small>Inspect a <code>.reforge</code> archive before building a restore plan.</small></span>
      <span class="home-card-arrow" aria-hidden="true">→</span>
    </button>
    {#if state.lastRunId}
      <button class="home-card" type="button" disabled={state.busy} onclick={() => state.resumeLatestRun()}>
        <span class="home-card-icon" aria-hidden="true"><HistoryIcon size={19} strokeWidth={1.9} /></span>
        <span class="home-card-copy"><strong>Resume latest run</strong><small>Continue from the journal checkpoint without replaying completed actions.</small></span>
        <span class="home-card-arrow" aria-hidden="true">→</span>
      </button>
    {:else}
      <div class="home-card home-card-muted">
        <span class="home-card-icon" aria-hidden="true"><HistoryIcon size={19} strokeWidth={1.9} /></span>
        <span class="home-card-copy"><strong>No paused run</strong><small>After a restore starts, this space will offer a safe resume action.</small></span>
      </div>
    {/if}
  </div>

  <section class="home-summary" aria-labelledby="guarantees-title">
    <div class="section-heading"><div><p class="eyebrow">Operating guarantees</p><h2 id="guarantees-title">Built for recovery, not snapshots</h2></div><ShieldCheckIcon size={18} aria-hidden="true" /></div>
    <div class="home-summary-grid">
      <div><strong>Rust-owned policy</strong><span>The webview receives typed metadata, never unrestricted filesystem access.</span></div>
      <div><strong>Versioned archives</strong><span>Package contents and trust metadata remain inspectable before restore.</span></div>
      <div><strong>Journaled operations</strong><span>Completed work is not replayed after interruption or reboot.</span></div>
      <div><strong>Reference-only secrets</strong><span>Credentials stay outside archive bytes and require explicit re-authentication.</span></div>
    </div>
  </section>
</section>
