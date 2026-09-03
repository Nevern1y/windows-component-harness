<script lang="ts">
  import ActivityIcon from '@lucide/svelte/icons/activity';
  import ArchiveIcon from '@lucide/svelte/icons/archive';
  import ClipboardCheckIcon from '@lucide/svelte/icons/clipboard-check';
  import FileCheck2Icon from '@lucide/svelte/icons/file-check-2';
  import FolderKanbanIcon from '@lucide/svelte/icons/folder-kanban';
  import LayoutDashboardIcon from '@lucide/svelte/icons/layout-dashboard';
  import ListChecksIcon from '@lucide/svelte/icons/list-checks';
  import PackageOpenIcon from '@lucide/svelte/icons/package-open';
  import ScanLineIcon from '@lucide/svelte/icons/scan-line';
  import ShieldCheckIcon from '@lucide/svelte/icons/shield-check';
  import TerminalSquareIcon from '@lucide/svelte/icons/terminal-square';
  import WrenchIcon from '@lucide/svelte/icons/wrench';
  import type { ReforgeState, Screen } from '../state.svelte';

  type Icon = typeof LayoutDashboardIcon;
  type NavItem = { label: string; screen: Screen; icon: Icon; description?: string };
  type NavGroup = { label: string; items: NavItem[] };

  let { state, open = false, collapsed = false, onClose }: { state: ReforgeState; open?: boolean; collapsed?: boolean; onClose?: () => void } = $props();

  const navigation: NavGroup[] = [
    {
      label: 'Overview',
      items: [{ label: 'Dashboard', screen: 'home', icon: LayoutDashboardIcon, description: 'Start or resume a workflow' }],
    },
    {
      label: 'Discovery',
      items: [
        { label: 'Scan progress', screen: 'scan_progress', icon: ScanLineIcon, description: 'Read current machine sources' },
        { label: 'Inventory', screen: 'scan_results', icon: FolderKanbanIcon, description: 'Review discovered components' },
        { label: 'Selection', screen: 'selection', icon: ListChecksIcon, description: 'Choose a portable slice' },
      ],
    },
    {
      label: 'Reconstruction',
      items: [
        { label: 'Package review', screen: 'package_review', icon: PackageOpenIcon, description: 'Inspect package trust' },
        { label: 'Target analysis', screen: 'target_analysis', icon: ActivityIcon, description: 'Compare target state' },
        { label: 'Restore plan', screen: 'restore_plan', icon: ClipboardCheckIcon, description: 'Approve journaled actions' },
        { label: 'Restore progress', screen: 'restore_progress', icon: TerminalSquareIcon, description: 'Follow the journal' },
      ],
    },
    {
      label: 'Verification',
      items: [
        { label: 'Verification', screen: 'verification', icon: ShieldCheckIcon, description: 'Review evidence summary' },
        { label: 'Report', screen: 'report', icon: FileCheck2Icon, description: 'Save the redacted report' },
      ],
    },
  ];

  function canNavigate(screen: Screen): boolean {
    if (screen === 'home') return true;
    if (screen === 'scan_progress') return state.busy && state.progress !== null;
    if (screen === 'scan_results' || screen === 'selection') return state.inventory !== null;
    if (screen === 'package_review') return state.packageInspection !== null || state.packageReceipt !== null;
    if (screen === 'target_analysis' || screen === 'restore_plan') return state.plan !== null;
    if (screen === 'restore_progress') return state.runId !== null;
    if (screen === 'verification' || screen === 'report') return state.report !== null;
    return false;
  }

  function navigate(item: NavItem): void {
    if (!canNavigate(item.screen)) return;
    state.go(item.screen);
    onClose?.();
  }
</script>

{#if open}
  <button class="sidebar-backdrop" type="button" aria-label="Close navigation" onclick={() => onClose?.()}></button>
{/if}

<aside class="app-sidebar" class:open class:collapsed aria-label="Reforge navigation">
  <div class="sidebar-brand">
    <button class="brand-button" type="button" aria-label="Return to Reforge dashboard" onclick={() => navigate({ label: 'Dashboard', screen: 'home', icon: LayoutDashboardIcon })}>
      <span class="brand-icon" aria-hidden="true"><WrenchIcon size={17} strokeWidth={2.4} /></span>
      <span class="brand-copy"><strong>Reforge</strong><small>Environment recovery</small></span>
    </button>
  </div>

  <nav class="sidebar-nav">
    {#each navigation as group (group.label)}
      <section class="nav-group" aria-labelledby={`nav-${group.label.toLowerCase()}`}>
        <h2 id={`nav-${group.label.toLowerCase()}`}>{group.label}</h2>
        <div class="nav-items">
          {#each group.items as item (item.screen)}
            {@const available = canNavigate(item.screen)}
            <button
              class="nav-item"
              class:active={state.screen === item.screen}
              class:available
              type="button"
              disabled={!available}
              aria-current={state.screen === item.screen ? 'page' : undefined}
              aria-label={available ? item.label : `${item.label}, unavailable until an earlier step completes`}
              title={item.description}
              onclick={() => navigate(item)}
            >
              <item.icon size={16} strokeWidth={2} aria-hidden="true" />
              <span>{item.label}</span>
              {#if item.screen === 'selection' && state.selectedCount > 0}<span class="nav-count">{state.selectedCount}</span>{/if}
              {#if item.screen === 'restore_progress' && state.hasPendingManualActions}<span class="nav-alert" aria-label="Manual action pending">!</span>{/if}
            </button>
          {/each}
        </div>
      </section>
    {/each}
  </nav>

  <div class="sidebar-footer">
    <div class="sidebar-status" role="status">
      <span class:connected={state.desktopRuntime} class="status-indicator" aria-hidden="true"></span>
      <div><strong>{state.desktopRuntime ? 'Desktop bridge' : 'Preview mode'}</strong><small>{state.desktopRuntime ? 'Rust engine connected' : 'Read-only UI preview'}</small></div>
    </div>
    <div class="sidebar-policy"><ShieldCheckIcon size={14} aria-hidden="true" /><span>Policy and filesystem access stay in Rust.</span></div>
    <button class="sidebar-home" type="button" onclick={() => navigate({ label: 'Dashboard', screen: 'home', icon: LayoutDashboardIcon })}><ArchiveIcon size={14} aria-hidden="true" />About this workspace</button>
  </div>
</aside>
