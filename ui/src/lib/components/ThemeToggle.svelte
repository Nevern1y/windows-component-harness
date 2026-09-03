<script lang="ts">
  import { onMount } from 'svelte';
  import MoonIcon from '@lucide/svelte/icons/moon';
  import SunIcon from '@lucide/svelte/icons/sun';

  let dark = $state(true);

  onMount(() => {
    const stored = localStorage.getItem('reforge:theme');
    dark = stored ? stored === 'dark' : document.documentElement.classList.contains('dark');
    applyTheme();
  });

  function applyTheme(): void {
    document.documentElement.classList.toggle('dark', dark);
    document.documentElement.classList.toggle('light', !dark);
  }

  function toggleTheme(): void {
    dark = !dark;
    localStorage.setItem('reforge:theme', dark ? 'dark' : 'light');
    applyTheme();
  }
</script>

<button class="toolbar-icon" type="button" aria-label={dark ? 'Switch to light theme' : 'Switch to dark theme'} title={dark ? 'Switch to light theme' : 'Switch to dark theme'} onclick={toggleTheme}>
  {#if dark}<SunIcon size={17} strokeWidth={1.8} aria-hidden="true" />{:else}<MoonIcon size={17} strokeWidth={1.8} aria-hidden="true" />{/if}
</button>
