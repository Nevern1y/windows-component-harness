<script lang="ts">
  import TrustNotice from '../lib/components/TrustNotice.svelte';
  import { formatBytes } from '../lib/state.svelte';
  import { RestoreMode } from '../lib/generated';
  import type { ReforgeState } from '../lib/state.svelte';

  let { state } = $props<{ state: ReforgeState }>();
  let inspection = $derived(state.packageInspection);
  let receipt = $derived(state.packageReceipt);
</script>

<section class="route wide-route">
  {#if inspection}
    <div class="route-header split-header">
      <div>
        <p class="eyebrow">02 / Review · package</p>
        <h1>Inspect before restore</h1>
        <p class="lede">This package is read-only until you approve a plan. The archive remains behind the Rust boundary; the webview receives metadata only.</p>
      </div>
      <div class="package-stamp"><span>PACKAGE</span><strong>{inspection.format_version}</strong><small>format version</small></div>
    </div>

    <TrustNotice trust={inspection.trust} approved={state.packageApproved} onApprove={(approved) => state.approvePackage(approved)} />

    <div class="data-grid three-columns">
      <div><span>Package identity</span><strong>{inspection.manifest.package_id}</strong></div>
      <div><span>Source host</span><strong>{inspection.manifest.source_host.os_version} · {inspection.manifest.source_host.architecture}</strong></div>
      <div><span>Archive size</span><strong>{formatBytes(inspection.archive_bytes)}</strong></div>
      <div><span>Components</span><strong>{inspection.graph.components.length}</strong></div>
      <div><span>Objects</span><strong>{inspection.object_index.objects.length}</strong></div>
      <div><span>Vault</span><strong>{inspection.has_vault ? 'Present · explicit use only' : 'Not present'}</strong></div>
    </div>

    {#if inspection.warnings.length > 0}
      <aside class="notice warning"><strong>Package warnings</strong><ul>{#each inspection.warnings as warning}<li>{warning}</li>{/each}</ul></aside>
    {/if}

    <div class="mode-panel">
      <div><p class="eyebrow">Restore mode</p><h2>Choose the target operation</h2><p>Rebuild expects a clean target. Migration preserves unknown target state and surfaces collisions for review.</p></div>
      <label class="select-field"><span>Mode</span><select value={state.mode} onchange={(event) => state.mode = event.currentTarget.value as RestoreMode}><option value={RestoreMode.Rebuild}>Rebuild</option><option value={RestoreMode.Migration}>Migration</option></select></label>
    </div>

    <div class="route-actions">
      <button class="button primary" type="button" disabled={!state.packageApproved || state.busy} onclick={() => state.buildRestorePlan()}>Analyze target <span aria-hidden="true">→</span></button>
      <button class="button secondary" type="button" onclick={() => state.openPackage()}>Open another package</button>
    </div>
  {:else if receipt}
    <div class="success-panel">
      <p class="eyebrow">02 / Review · package created</p>
      <h1>Package is ready</h1>
      <p class="lede">The package writer committed the archive atomically. Re-open it to inspect trust metadata and build a restore plan.</p>
      <dl class="receipt-list"><div><dt>Package identity</dt><dd>{receipt.package_id}</dd></div><div><dt>Objects</dt><dd>{receipt.object_count}</dd></div><div><dt>Index digest</dt><dd>{receipt.index_digest}</dd></div></dl>
      <div class="route-actions"><button class="button primary" type="button" onclick={() => state.openPackage()}>Inspect package</button><button class="button secondary" type="button" onclick={() => state.go('home')}>Return home</button></div>
    </div>
  {:else}
    <div class="empty-state">No package is loaded. Open a <code>.reforge</code> file to continue.</div>
  {/if}
</section>
