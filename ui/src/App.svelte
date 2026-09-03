<script lang="ts">
  import { onMount } from 'svelte';
  import MenuIcon from '@lucide/svelte/icons/menu';
  import XIcon from '@lucide/svelte/icons/x';
  import AppSidebar from './lib/components/AppSidebar.svelte';
  import ErrorAlert from './lib/components/ErrorAlert.svelte';
  import CommandPalette from './lib/components/CommandPalette.svelte';
  import ThemeToggle from './lib/components/ThemeToggle.svelte';
  import CliOnlyNotice from './routes/CliOnlyNotice.svelte';
  import Home from './routes/Home.svelte';
  import PackageReview from './routes/PackageReview.svelte';
  import Report from './routes/Report.svelte';
  import RestorePlan from './routes/RestorePlan.svelte';
  import RestoreProgress from './routes/RestoreProgress.svelte';
  import ScanProgress from './routes/ScanProgress.svelte';
  import ScanResults from './routes/ScanResults.svelte';
  import Selection from './routes/Selection.svelte';
  import TargetAnalysis from './routes/TargetAnalysis.svelte';
  import Verification from './routes/Verification.svelte';
  import { createReforgeState, type ReforgeState, type Screen } from './lib/state.svelte';

  const reforge: ReforgeState = createReforgeState();

  // Deliberately hard-coded: this desktop binary is informational only.
  const CLI_ONLY_MODE = true;
  let sidebarOpen = $state(false);
  let sidebarCollapsed = $state(false);

  const screenLabels: Record<Screen, string> = {
    home: 'Dashboard',
    scan_progress: 'Scan progress',
    scan_results: 'Inventory',
    selection: 'Selection',
    package_review: 'Package review',
    target_analysis: 'Target analysis',
    restore_plan: 'Restore plan',
    restore_progress: 'Restore progress',
    verification: 'Verification',
    report: 'Report',
  };

  let currentLabel = $derived(CLI_ONLY_MODE ? 'CLI-only mode' : screenLabels[reforge.screen]);
  function handleViewportChange(): void {
    if (window.matchMedia('(min-width: 768px)').matches) sidebarOpen = false;
  }

  onMount(() => {
    if (CLI_ONLY_MODE) return;
    void reforge.connectEvents();
    window.addEventListener('resize', handleViewportChange);
    return () => {
      window.removeEventListener('resize', handleViewportChange);
      reforge.disconnectEvents();
    };
  });
  function toggleNavigation(): void {
    if (typeof window !== 'undefined' && window.matchMedia('(max-width: 767px)').matches) {
      sidebarOpen = !sidebarOpen;
    } else {
      sidebarCollapsed = !sidebarCollapsed;
    }
  }
</script>


<svelte:head>
  <title>{currentLabel} · Reforge</title>
  <meta name="description" content="Reviewable, resumable Windows environment reconstruction" />
</svelte:head>
{#if CLI_ONLY_MODE}
  <main id="main-content" class="workspace">
    <CliOnlyNotice />
  </main>
{:else}
<div class="app-shell">
  <AppSidebar state={reforge} open={sidebarOpen} collapsed={sidebarCollapsed} onClose={() => (sidebarOpen = false)} />

  <div class="app-main" class:sidebar-collapsed={sidebarCollapsed}>
    <header class="topbar">
      <div class="topbar-leading">
        <button class="toolbar-icon menu-trigger" type="button" aria-label={sidebarOpen || sidebarCollapsed ? 'Expand navigation' : 'Collapse navigation'} aria-expanded={sidebarOpen || !sidebarCollapsed} onclick={() => toggleNavigation()}>
          {#if sidebarOpen}<XIcon size={18} strokeWidth={1.8} aria-hidden="true" />{:else}<MenuIcon size={18} strokeWidth={1.8} aria-hidden="true" />{/if}
        </button>
        <span class="topbar-divider" aria-hidden="true"></span>
        <nav class="breadcrumb" aria-label="Breadcrumb">
          {#if reforge.screen === 'home'}
            <span class="breadcrumb-current">Dashboard</span>
          {:else}
            <button type="button" class="breadcrumb-link" onclick={() => reforge.go('home')}>Reforge</button>
            <span class="breadcrumb-separator" aria-hidden="true">/</span>
            <span class="breadcrumb-current">{currentLabel}</span>
          {/if}
        </nav>
      </div>

      <div class="topbar-actions">
        <CommandPalette state={reforge} />
        <div class="runtime-status" role="status" aria-live="polite">
          <span class:connected={reforge.desktopRuntime} class="status-indicator" aria-hidden="true"></span>
          <span class="runtime-label">{reforge.busy ? 'Working' : reforge.desktopRuntime ? 'Connected' : 'Preview'}</span>
        </div>
        <ThemeToggle />
      </div>
    </header>

    <main id="main-content" class="workspace">
      {#if reforge.error}
        <ErrorAlert error={reforge.error} onDismiss={() => reforge.clearError()} />
      {/if}
      {#if reforge.notice}
        <aside class="app-alert {reforge.notice.tone}" role="status"><span>{reforge.notice.message}</span><button class="toolbar-icon" type="button" aria-label="Dismiss notice" onclick={() => reforge.dismissNotice()}>×</button></aside>
      {/if}

      {#if reforge.screen === 'home'}<Home state={reforge} />
      {:else if reforge.screen === 'scan_progress'}<ScanProgress state={reforge} />
      {:else if reforge.screen === 'scan_results'}<ScanResults state={reforge} />
      {:else if reforge.screen === 'selection'}<Selection state={reforge} />
      {:else if reforge.screen === 'package_review'}<PackageReview state={reforge} />
      {:else if reforge.screen === 'target_analysis'}<TargetAnalysis state={reforge} />
      {:else if reforge.screen === 'restore_plan'}<RestorePlan state={reforge} />
      {:else if reforge.screen === 'restore_progress'}<RestoreProgress state={reforge} />
      {:else if reforge.screen === 'verification'}<Verification state={reforge} />
      {:else if reforge.screen === 'report'}<Report state={reforge} />
      {/if}
    </main>
  </div>
</div>
{/if}
