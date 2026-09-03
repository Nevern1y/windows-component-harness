<section class="route narrow-route cli-only-route" aria-labelledby="cli-only-title">
  <div class="route-header">
    <p class="eyebrow">CLI-only release mode</p>
    <h1 id="cli-only-title">Use Reforge from the command line</h1>
    <p class="lede">Desktop controls are disabled in this build. The reconstruction engine remains available through the local CLI, with the same package, journal, restore, and verification behavior.</p>
  </div>

  <div class="progress-card cli-only-card">
    <div class="section-heading">
      <div>
        <p class="eyebrow">Available workflow</p>
        <h2>Discover, package, restore, verify</h2>
      </div>
      <span class="count-badge">CLI</span>
    </div>
    <pre class="cli-command-list"><code>reforge scan
reforge package create --output PATH
reforge package inspect PATH
reforge plan --package PATH --mode rebuild|migrate
reforge restore --package PATH --mode rebuild|migrate --yes-safe
reforge resume RUN_ID
reforge verify RUN_ID
reforge report RUN_ID</code></pre>
  </div>

  <p class="field-note">This desktop shell intentionally exposes no Tauri commands, native file dialogs, or runtime switch for re-enabling control. Use <code>reforge --help</code> for the complete CLI contract.</p>
</section>
