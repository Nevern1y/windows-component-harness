<script lang="ts">
  import { formatBytes } from '../lib/state.svelte';
  import type { ReforgeState } from '../lib/state.svelte';

  let { state } = $props<{ state: ReforgeState }>();
  let report = $derived(state.report);
</script>

<section class="route wide-route">
  {#if report}
    <div class="route-header split-header"><div><p class="eyebrow">04 / Verify · report</p><h1>Restore evidence</h1><p class="lede">This view contains bounded summaries and verification outcomes. Raw secrets and absolute user paths are not rendered.</p></div><div class="report-status status-{report.status.toLowerCase()}">{report.status.replaceAll('_', ' ')}</div></div>
    <div class="data-grid three-columns"><div><span>Run</span><strong>{report.run_id}</strong></div><div><span>Package</span><strong>{report.package_id}</strong></div><div><span>Elapsed</span><strong>{(report.elapsed_ms / 1000).toFixed(1)} s</strong></div><div><span>Bytes written</span><strong>{formatBytes(report.bytes_written)}</strong></div><div><span>Components</span><strong>{report.components.length}</strong></div><div><span>Manual actions</span><strong>{report.manual_actions.length}</strong></div></div>
    <div class="report-list" aria-labelledby="report-components-title"><div class="section-heading"><div><p class="eyebrow">Component outcomes</p><h2 id="report-components-title">Verification by component</h2></div></div>{#each report.components as component (component.component)}<article class="report-row"><div><code>{component.component}</code><strong>{component.status.replaceAll('_', ' ')}</strong></div><div><span>{component.evidence.length} evidence record{component.evidence.length === 1 ? '' : 's'}</span><span>{component.warnings.length} warning{component.warnings.length === 1 ? '' : 's'}</span></div></article>{/each}</div>
    <div class="route-actions"><button class="button primary" type="button" onclick={() => state.saveCurrentReport()} disabled={state.busy}>Save redacted report</button><button class="button secondary" type="button" onclick={() => state.go('verification')}>Back to summary</button><button class="button ghost" type="button" onclick={() => state.go('home')}>Return home</button></div>
  {:else}
    <div class="empty-state">No report is loaded.</div>
  {/if}
</section>
