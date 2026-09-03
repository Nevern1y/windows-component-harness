import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/svelte';
import { describe, expect, it } from 'vitest';
import CliOnlyNotice from '../src/routes/CliOnlyNotice.svelte';
import App from '../src/App.svelte';

describe('CLI-only desktop mode', () => {
  it('shows the CLI workflow without exposing control buttons', () => {
    render(CliOnlyNotice);
    expect(screen.getByText(/reforge scan/)).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Use Reforge from the command line' })).toBeInTheDocument();
    expect(screen.getByText(/exposes no Tauri commands/i)).toBeInTheDocument();
    expect(screen.queryAllByRole('button')).toHaveLength(0);
  });

  it('keeps the future workflow unreachable in the current desktop profile', () => {
    render(App);

    expect(screen.getByRole('heading', { name: 'Use Reforge from the command line' })).toBeInTheDocument();
    expect(screen.queryAllByRole('button')).toHaveLength(0);
  });
});
