/**
 * Stable UI import boundary for the canonical Rust-generated DTOs.
 *
 * `generated.ts` is regenerated from `reforge-domain`; this facade keeps UI
 * consumers independent of the generator's output path without introducing
 * a second model.
 */
export * from './generated';
