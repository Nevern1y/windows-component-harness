<script lang="ts">
  import { reportTotal } from '../lib/state.svelte';
  import type { ReforgeState } from '../lib/state.svelte';

  let { state } = $props<{ state: ReforgeState }>();
  let report = $derived(state.report);
</script>

<section class="route wide-route">
  {#if report}
    <div class="route-header split-header"><div><p class="eyebrow">04 / Verify</p><h1>What survived the rebuild?</h1><p class="lede">Verification is evidence-based and component-specific. A partial result is reported as partial, never silently promoted to success.</p></div><div class="report-status status-{report.status.toLowerCase()}">{report.status.replaceAll('_', ' ')}</div></div>
    <div class="metric-band report-metrics"><div><strong>{reportTotal(report.counts)}</strong><span>checks</span></div><div><strong>{report.counts.verified}</strong><span>verified</span></div><div><strong>{report.counts.failed}</strong><span>failed</span></div><div><strong>{report.counts.waiting_for_user}</strong><span>waiting for user</span></div><div><strong>{report.counts.reboot_required}</strong><span>reboot required</span></div></div>
    {#if report.warnings.length > 0}<aside class="notice warning"><strong>Verification warnings</strong><ul>{#each report.warnings as warning}<li>{warning}</li>{/each}</ul></aside>{/if}
    <div class="route-actions"><button class="button primary" type="button" onclick={() => state.go('report')}>Open detailed report <span aria-hidden="true">→</span></button><button class="button secondary" type="button" onclick={() => state.verifyCurrentRun()} disabled={state.busy}>Run verification again</button></div>
  {:else}
    <div class="empty-state"><strong>Verification has not completed.</strong><span>The report will appear after the journal reaches a terminal state.</span><button class="button secondary" type="button" onclick={() => state.go('restore_progress')}>Back to restore</button></div>
  {/if}
</section>
