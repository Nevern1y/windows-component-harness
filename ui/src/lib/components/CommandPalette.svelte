<script lang="ts">
  import { onMount } from 'svelte';
  import ActivityIcon from '@lucide/svelte/icons/activity';
  import ClipboardCheckIcon from '@lucide/svelte/icons/clipboard-check';
  import FileCheck2Icon from '@lucide/svelte/icons/file-check-2';
  import FolderKanbanIcon from '@lucide/svelte/icons/folder-kanban';
  import LayoutDashboardIcon from '@lucide/svelte/icons/layout-dashboard';
  import ListChecksIcon from '@lucide/svelte/icons/list-checks';
  import PackageOpenIcon from '@lucide/svelte/icons/package-open';
  import ScanLineIcon from '@lucide/svelte/icons/scan-line';
  import SearchIcon from '@lucide/svelte/icons/search';
  import ShieldCheckIcon from '@lucide/svelte/icons/shield-check';
  import TerminalSquareIcon from '@lucide/svelte/icons/terminal-square';
  import type { ReforgeState, Screen } from '../state.svelte';

  type Icon = typeof LayoutDashboardIcon;
  type Command = { label: string; description: string; screen: Screen; icon: Icon };

  let { state: reforge }: { state: ReforgeState } = $props();
  let dialog = $state<HTMLDialogElement | undefined>(undefined);
  let input = $state<HTMLInputElement | undefined>(undefined);
  let open = $state(false);
  let query = $state('');

  const commands: Command[] = [
    { label: 'Dashboard', description: 'Start or resume a workflow', screen: 'home', icon: LayoutDashboardIcon },
    { label: 'Scan progress', description: 'Read current Windows sources', screen: 'scan_progress', icon: ScanLineIcon },
    { label: 'Inventory', description: 'Review discovered components', screen: 'scan_results', icon: FolderKanbanIcon },
    { label: 'Selection', description: 'Choose a portable slice', screen: 'selection', icon: ListChecksIcon },
    { label: 'Package review', description: 'Inspect package trust metadata', screen: 'package_review', icon: PackageOpenIcon },
    { label: 'Target analysis', description: 'Compare package and target state', screen: 'target_analysis', icon: ActivityIcon },
    { label: 'Restore plan', description: 'Review journaled operations', screen: 'restore_plan', icon: ClipboardCheckIcon },
    { label: 'Restore progress', description: 'Follow the active journal', screen: 'restore_progress', icon: TerminalSquareIcon },
    { label: 'Verification', description: 'Review evidence summary', screen: 'verification', icon: ShieldCheckIcon },
    { label: 'Report', description: 'Save the redacted report', screen: 'report', icon: FileCheck2Icon },
  ];

  let filteredCommands = $derived(
    commands.filter((command) => `${command.label} ${command.description}`.toLowerCase().includes(query.trim().toLowerCase())),
  );

  onMount(() => {
    function handleKeydown(event: KeyboardEvent): void {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        openPalette();
      }
    }
    window.addEventListener('keydown', handleKeydown);
    return () => window.removeEventListener('keydown', handleKeydown);
  });

  $effect(() => {
    if (!open) return;
    queueMicrotask(() => {
      if (dialog && !dialog.open) dialog.showModal();
      input?.focus();
    });
  });

  function openPalette(): void {
    open = true;
    query = '';
  }

  function closePalette(): void {
    open = false;
    dialog?.close();
  }

  function canNavigate(screen: Screen): boolean {
    if (screen === 'home') return true;
    if (screen === 'scan_progress') return reforge.busy && reforge.progress !== null;
    if (screen === 'scan_results' || screen === 'selection') return reforge.inventory !== null;
    if (screen === 'package_review') return reforge.packageInspection !== null || reforge.packageReceipt !== null;
    if (screen === 'target_analysis' || screen === 'restore_plan') return reforge.plan !== null;
    if (screen === 'restore_progress') return reforge.runId !== null;
    return reforge.report !== null;
  }

  function execute(command: Command): void {
    if (!canNavigate(command.screen)) return;
    reforge.go(command.screen);
    closePalette();
  }
</script>

<button class="toolbar-search" type="button" aria-label="Open command palette" onclick={openPalette}>
  <SearchIcon size={16} strokeWidth={1.8} aria-hidden="true" />
  <span>Search workflows...</span>
  <kbd>Ctrl K</kbd>
</button>

{#if open}
  <dialog bind:this={dialog} class="command-dialog" aria-labelledby="command-title" onclick={(event) => event.target === dialog && closePalette()} onclose={() => (open = false)}>
    <div class="command-panel">
      <div class="command-header">
        <div><p class="command-kicker">Reforge command palette</p><h2 id="command-title">Go to a workflow step</h2></div>
        <button class="toolbar-icon" type="button" aria-label="Close command palette" onclick={closePalette}>×</button>
      </div>
      <label class="command-input-wrap">
        <SearchIcon size={17} aria-hidden="true" />
        <input bind:this={input} bind:value={query} type="search" placeholder="Search workflow steps" aria-label="Search workflow steps" onkeydown={(event) => event.key === 'Escape' && closePalette()} />
        <kbd>Esc</kbd>
      </label>
      <div class="command-results" role="listbox" aria-label="Workflow steps">
        {#if filteredCommands.length === 0}
          <p class="command-empty">No matching workflow step.</p>
        {:else}
          {#each filteredCommands as command (command.screen)}
            {@const available = canNavigate(command.screen)}
            <button class="command-item" class:active={reforge.screen === command.screen} type="button" role="option" aria-selected={reforge.screen === command.screen} disabled={!available} onclick={() => execute(command)}>
              <span class="command-icon"><command.icon size={16} aria-hidden="true" /></span>
              <span><strong>{command.label}</strong><small>{command.description}</small></span>
              {#if !available}<em>Unavailable</em>{/if}
            </button>
          {/each}
        {/if}
      </div>
    </div>
  </dialog>
{/if}
