use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{self, BufRead, IsTerminal, Write},
    path::{Path, PathBuf},
    time::Duration,
};

use chrono::{DateTime, Utc};
use crossterm::{
    cursor::{Hide, MoveTo, Show},
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute,
    terminal::{self, Clear, ClearType},
};
use reforge_domain::{
    ApprovalState, Component, ComponentId, ComponentKind, Confidence, Inventory, ManualActionState,
    Operation, OperationState, Portability, ProgressEvent, ReportStatus, RestoreMode, RestorePlan,
    RestoreReport, RestoreStrategy,
};
use reforge_platform_windows::CancellationToken;
use serde_json::json;

use super::interactive::{
    BackupPreset, CategoryKind, UiPreferences, backup_history_records, categories,
    category_components, category_label, component_category, component_has_large_data,
    component_has_secret_artifact, component_is_catalog_only, component_is_safe_for_default,
    component_is_unknown_binary, preset_selection, remember_backup, selection_from_ids,
};
#[cfg(test)]
use super::interactive::{LARGE_ARTIFACT_THRESHOLD, component_is_safely_portable};
use super::{
    ApplicationService, CommandResult, ErrorEnvelope, SecretFinding, SelectionReview, boxed_error,
    doctor_command,
};
const STALE_AFTER: chrono::Duration = chrono::Duration::hours(24);

pub(super) async fn run() -> Result<CommandResult, Box<ErrorEnvelope>> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return run_line_mode().await;
    }

    let mut session = TerminalSession::enter()?;
    let mut ui = Ui::new(&mut session.stdout)?;
    match ui.run().await {
        Ok(()) => {}
        Err(error) if error.code == reforge_domain::ReforgeErrorCode::Cancelled => {}
        Err(error) => return Err(error),
    }
    Ok(interactive_result())
}

pub(super) async fn run_quick_backup() -> Result<CommandResult, Box<ErrorEnvelope>> {
    require_interactive_terminal()?;
    let mut session = TerminalSession::enter()?;
    let mut ui = Ui::new(&mut session.stdout)?;
    if !ui.preferences.welcomed {
        match ui.welcome() {
            Ok(true) => {}
            Ok(false) => return Ok(interactive_result()),
            Err(error) if error.code == reforge_domain::ReforgeErrorCode::Cancelled => {
                return Ok(interactive_result());
            }
            Err(error) => return Err(error),
        }
    }
    match ui.quick_backup().await {
        Ok(()) => Ok(interactive_result()),
        Err(error) if error.code == reforge_domain::ReforgeErrorCode::Cancelled => {
            Ok(interactive_result())
        }
        Err(error) => Err(error),
    }
}

pub(super) async fn run_restore() -> Result<CommandResult, Box<ErrorEnvelope>> {
    require_interactive_terminal()?;
    let mut session = TerminalSession::enter()?;
    let mut ui = Ui::new(&mut session.stdout)?;
    match ui.restore_backup().await {
        Ok(()) => Ok(interactive_result()),
        Err(error) if error.code == reforge_domain::ReforgeErrorCode::Cancelled => {
            Ok(interactive_result())
        }
        Err(error) => Err(error),
    }
}

fn require_interactive_terminal() -> Result<(), Box<ErrorEnvelope>> {
    if io::stdin().is_terminal() && io::stdout().is_terminal() {
        Ok(())
    } else {
        Err(boxed_error(
            reforge_domain::ReforgeErrorCode::SchemaInvalid,
            "This guided workflow requires Windows Terminal or another interactive terminal",
        ))
    }
}

fn interactive_result() -> CommandResult {
    CommandResult {
        payload: json!({"status": "exited", "interface": "terminal"}),
        human: String::new(),
        exit_code: 0,
    }
}

struct TerminalSession {
    stdout: io::Stdout,
}

impl TerminalSession {
    fn enter() -> Result<Self, Box<ErrorEnvelope>> {
        terminal::enable_raw_mode().map_err(|error| io_error(error, "Enable terminal input"))?;
        let mut stdout = io::stdout();
        if let Err(error) = execute!(stdout, Hide) {
            let _ = terminal::disable_raw_mode();
            return Err(io_error(error, "Initialize terminal display"));
        }
        Ok(Self { stdout })
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        let _ = execute!(self.stdout, Show);
        let _ = terminal::disable_raw_mode();
    }
}

struct Ui<'a> {
    out: &'a mut io::Stdout,
    service: ApplicationService,
    inventory: Option<Inventory>,
    selected: BTreeSet<ComponentId>,
    preferences: UiPreferences,
    selection_initialized: bool,
}

impl<'a> Ui<'a> {
    fn new(out: &'a mut io::Stdout) -> Result<Self, Box<ErrorEnvelope>> {
        Ok(Self {
            out,
            service: ApplicationService::new()?,
            inventory: None,
            selected: BTreeSet::new(),
            preferences: UiPreferences::load()?,
            selection_initialized: false,
        })
    }

    async fn run(&mut self) -> Result<(), Box<ErrorEnvelope>> {
        if !self.preferences.welcomed && !self.welcome()? {
            return Ok(());
        }
        loop {
            let result = match self.select_home_menu()? {
                MenuChoice::Selected(0) => self.quick_backup().await,
                MenuChoice::Selected(1) => self.custom_backup().await,
                MenuChoice::Selected(2) => self.restore_backup().await,
                MenuChoice::Selected(3) => self.browse_components().await,
                MenuChoice::Selected(4) => self.scan_screen().await,
                MenuChoice::Selected(5) => self.backup_history().await,
                MenuChoice::Selected(6) => self.advanced().await,
                MenuChoice::Selected(7) => self.settings(),
                MenuChoice::Back | MenuChoice::Exit => break,
                MenuChoice::Selected(_) => continue,
            };
            if let Err(error) = result {
                if error.code == reforge_domain::ReforgeErrorCode::Cancelled {
                    break;
                }
                self.clear()?;
                self.show_error(&error)?;
            }
        }
        Ok(())
    }

    fn welcome(&mut self) -> Result<bool, Box<ErrorEnvelope>> {
        self.clear()?;
        self.line("Welcome to Reforge")?;
        self.line("")?;
        self.line("Back up your Windows development environment and restore it later.")?;
        self.line("Passwords and login sessions are not copied.")?;
        self.line("[Enter] Continue    [Esc] Exit")?;
        loop {
            match read_key()? {
                KeyCode::Enter => break,
                KeyCode::Esc | KeyCode::Backspace => return Ok(false),
                _ => {}
            }
        }
        self.clear()?;
        self.line("Checking system...")?;
        let result = doctor_command()?;
        let mut context = vec![
            format!(
                "[OK] Windows (version {}, build {})",
                result.payload["os_version"].as_str().unwrap_or("unknown"),
                result.payload["os_build"].as_str().unwrap_or("unknown")
            ),
            "[OK] Local state directory available".to_owned(),
            format!("System observations: {}", result.payload["warning_count"]),
            "Secrets, large data and unknown binaries stay excluded.".to_owned(),
        ];
        if result.payload["elevated"].as_bool() == Some(false) {
            context.push("[WARN] Administrator access not active.".to_owned());
            context.push("Some Windows components may not be discovered.".to_owned());
            loop {
                match self.select_menu_with_context(
                    "Welcome to Reforge",
                    &context,
                    &[
                        "Continue normally - recommended",
                        "Restart Reforge as Administrator",
                        "Learn more",
                    ],
                )? {
                    MenuChoice::Selected(0) => break,
                    MenuChoice::Selected(1) => {
                        self.preferences.welcomed = true;
                        self.preferences.save()?;
                        match reforge_platform_windows::relaunch_current_process_elevated() {
                            Ok(()) => return Ok(false),
                            Err(error)
                                if error.code == reforge_domain::ReforgeErrorCode::Cancelled =>
                            {
                                context.push(
                                    "Administrator restart cancelled; continue normally below."
                                        .to_owned(),
                                );
                            }
                            Err(error) => self.show_error(&error)?,
                        }
                    }
                    MenuChoice::Selected(2) => {
                        self.show_lines("Administrator access", &[
                            "Safe backup and inspection do not require administrator access.".to_owned(),
                            "Restart opens a separate Reforge terminal after a Windows UAC prompt.".to_owned(),
                            "This does not approve any restore or bypass operation-level security.".to_owned(),
                        ])?;
                    }
                    MenuChoice::Back | MenuChoice::Exit => return Ok(false),
                    _ => {}
                }
            }
        } else {
            match self.select_menu_with_context("Welcome to Reforge", &context, &["Continue"])? {
                MenuChoice::Selected(0) => {}
                _ => return Ok(false),
            }
        }
        self.preferences.welcomed = true;
        self.preferences.save()?;
        Ok(true)
    }

    fn select_home_menu(&mut self) -> Result<MenuChoice, Box<ErrorEnvelope>> {
        let items = [
            "Quick Backup",
            "Custom Backup",
            "Restore Backup",
            "Browse Detected Components",
            "Scan This PC",
            "Backup History",
            "Advanced",
            "Settings",
        ];
        let mut cursor = 0usize;
        loop {
            let inventory = self
                .inventory
                .clone()
                .or_else(|| self.service.inventory().ok());
            self.clear()?;
            self.line("REFORGE")?;
            self.line("Backup & Restore your Windows setup")?;
            self.line("================================")?;
            if let Some(inventory) = &inventory {
                let os = clean_text(&inventory.host.os_version, 48);
                let captured = format_date(inventory.captured_at);
                self.line(&format!(
                    "System: Windows {os} (build {})",
                    clean_text(&inventory.host.os_build, 16)
                ))?;
                self.line(&format!("Last scan: {captured}"))?;
                self.line(&format!(
                    "Detected: {} components",
                    inventory.graph.components.len()
                ))?;
            } else {
                self.line("System: Windows (not scanned yet)")?;
                self.line("Last scan: none")?;
                self.line("Detected: 0 components")?;
            }
            self.line("")?;
            for (index, item) in items.iter().enumerate() {
                let marker = if index == cursor { ">" } else { " " };
                self.line(&format!("{marker} [{}] {item}", index + 1))?;
            }
            self.line("  [0] Exit")?;
            self.line("")?;
            self.line("Use Up/Down and Enter, or press a number. Ctrl+C exits safely.")?;

            match menu_input(read_key()?, cursor, items.len()) {
                MenuInput::Cursor(next) => cursor = next,
                MenuInput::Choice(choice) => return Ok(choice),
                MenuInput::Unhandled => {}
            }
        }
    }

    fn select_menu(&mut self, items: &[&str]) -> Result<MenuChoice, Box<ErrorEnvelope>> {
        self.select_menu_with_context("REFORGE", &[], items)
    }

    fn select_menu_with_context(
        &mut self,
        title: &str,
        context: &[String],
        items: &[&str],
    ) -> Result<MenuChoice, Box<ErrorEnvelope>> {
        self.select_menu_at(title, context, items, 0)
    }

    fn select_menu_at(
        &mut self,
        title: &str,
        context: &[String],
        items: &[&str],
        mut cursor: usize,
    ) -> Result<MenuChoice, Box<ErrorEnvelope>> {
        cursor = cursor.min(items.len().saturating_sub(1));
        loop {
            self.clear()?;
            self.line(title)?;
            self.line("")?;
            for line in context {
                self.line(line)?;
            }
            if !context.is_empty() {
                self.line("")?;
            }
            let (start, end) = visible_range(cursor, items.len(), context.len() + 6);
            for (index, item) in items.iter().enumerate().take(end).skip(start) {
                let marker = if index == cursor { ">" } else { " " };
                self.line(&format!("{marker} [{}] {item}", index + 1))?;
            }
            self.line("")?;
            self.line("Up/Down  Enter  1-9 Select  Esc/Backspace")?;
            match menu_input(read_key()?, cursor, items.len()) {
                MenuInput::Cursor(next) => cursor = next,
                MenuInput::Choice(choice) => return Ok(choice),
                MenuInput::Unhandled => {}
            }
        }
    }

    async fn quick_backup(&mut self) -> Result<(), Box<ErrorEnvelope>> {
        if let Err(error) = doctor_command() {
            self.clear()?;
            self.show_error(&error)?;
            return Ok(());
        }
        let Some(inventory) = self.ensure_inventory().await? else {
            return Ok(());
        };
        let Some(preset) = self.choose_preset()? else {
            return Ok(());
        };
        self.selected = preset_selection(&inventory.graph, preset)
            .components
            .into_iter()
            .collect();
        self.selection_initialized = true;
        if preset == BackupPreset::Custom {
            self.custom_backup().await?;
            return Ok(());
        }
        let selection = selection_from_ids(&self.selected);
        let review = self.service.review_selection(selection)?;
        self.render_quick_summary(&inventory, &review)?;
        loop {
            match read_key()? {
                KeyCode::Enter => {
                    self.create_reviewed_backup(&review).await?;
                    return Ok(());
                }
                KeyCode::Char('c') | KeyCode::Char('C') => {
                    self.custom_backup().await?;
                    return Ok(());
                }
                KeyCode::Char('d') | KeyCode::Char('D') if !review.secret_findings.is_empty() => {
                    self.show_secret_findings(&review.secret_findings)?;
                    self.render_quick_summary(&inventory, &review)?;
                }
                KeyCode::Esc | KeyCode::Backspace => return Ok(()),
                _ => {}
            }
        }
    }

    fn show_secret_findings(
        &mut self,
        findings: &[SecretFinding],
    ) -> Result<(), Box<ErrorEnvelope>> {
        let mut lines = vec!["Values are never shown here or included automatically.".to_owned()];
        for finding in findings {
            lines.push(format!(
                "{} / {}",
                finding.component_name, finding.artifact_path
            ));
            lines.push(finding.reason.clone());
        }
        self.show_lines("Potential secrets excluded", &lines)
    }

    fn choose_preset(&mut self) -> Result<Option<BackupPreset>, Box<ErrorEnvelope>> {
        let cursor = BackupPreset::ALL
            .iter()
            .position(|preset| *preset == self.preferences.last_preset)
            .unwrap_or(0);
        let choice = self.select_menu_at(
            "Choose Backup Type",
            &["Recommended is the safe default for most users.".to_owned()],
            &[
                "Recommended - best option for most users",
                "Developer PC - apps, runtimes, tools, Git, package managers",
                "AI Development - harnesses, MCP, skills, instructions, runtimes",
                "AI Workstation - safe AI configuration plus portable developer dependencies",
                "Full Safe Backup - everything considered safely portable",
                "Minimal - core applications and configurations",
                "Custom - choose components manually",
            ],
            cursor,
        )?;
        let MenuChoice::Selected(index) = choice else {
            return Ok(None);
        };
        let preset = BackupPreset::ALL[index];
        self.preferences.last_preset = preset;
        self.preferences.save()?;
        Ok(Some(preset))
    }

    fn render_quick_summary(
        &mut self,
        inventory: &Inventory,
        review: &SelectionReview,
    ) -> Result<(), Box<ErrorEnvelope>> {
        self.clear()?;
        self.line(&format!(
            "Quick Backup / {}",
            self.preferences.last_preset.label()
        ))?;
        self.line("[OK] Environment checked; existing inventory reused when fresh")?;
        let counts = category_counts(&inventory.graph.components, &review.selected_components);
        for (label, count) in counts {
            self.line(&format!("{label}: {count}"))?;
        }
        self.line("Excluded: passwords, auth/sessions, secrets, unknown binaries, large data")?;
        self.line(&format!(
            "Potential secrets excluded: {}",
            review.secret_findings.len()
        ))?;
        self.line(&format!(
            "{} components / {} files / estimated {}",
            review.selected_components.len(),
            review.selected_artifacts.len(),
            format_bytes(review.total_bytes)
        ))?;
        self.line("[Enter] Create safely  [C] Customize  [D] Secret details  [Esc] Cancel")
    }

    async fn create_reviewed_backup(
        &mut self,
        review: &SelectionReview,
    ) -> Result<(), Box<ErrorEnvelope>> {
        if review.selected_components.is_empty() {
            return self.show_lines(
                "Nothing to back up",
                &[
                    "No safe components match this preset. Choose Custom or another preset."
                        .to_owned(),
                ],
            );
        }
        let output = unique_backup_path(self.preferences.backup_path()?)?;
        self.clear()?;
        self.line("Creating backup...")?;
        self.line("Ctrl+C requests a safe stop before the completed archive is published.")?;
        let cancellation = CancellationToken::new();
        let worker_cancellation = cancellation.clone();
        let worker_output = output.clone();
        let selection = review.selection.clone();
        let service = self.service.clone();
        let mut worker = tokio::task::spawn_blocking(move || {
            service.create_package_with_cancel(&worker_output, selection, &worker_cancellation)
        });
        let result = tokio::select! {
            result = &mut worker => result,
            cancelled = wait_for_cancel_request() => {
                cancellation.cancel();
                let completed = worker.await;
                cancelled?;
                completed
            }
        };
        let receipt = result.map_err(|error| io_error(error, "Complete backup creation"))??;
        let package = self.service.inspect_package(&output)?;
        let history_error = remember_backup(
            &output,
            package.selection.components.len(),
            self.preferences.last_preset,
        )
        .err();
        loop {
            self.clear()?;
            self.line("[OK] Backup created successfully")?;
            self.line(&format!("Location: {}", output.display()))?;
            self.line(&format!(
                "Components: {}",
                package.selection.components.len()
            ))?;
            self.line(&format!(
                "Excluded secrets: {}",
                self.secret_component_count(self.inventory.as_ref())
            ))?;
            self.line(&format!(
                "Warnings: {}",
                package.warnings.len() + review.secret_findings.len()
            ))?;
            self.line(&format!("Package objects: {}", receipt.object_count))?;
            if let Some(error) = &history_error {
                self.line(&format!(
                    "[WARN] Backup is complete, but history metadata was not saved: {}",
                    error.message
                ))?;
            }
            self.line("")?;
            self.line("[Enter] Done   [I] Inspect   [R] Backup report")?;
            match read_key()? {
                KeyCode::Enter | KeyCode::Esc | KeyCode::Backspace => return Ok(()),
                KeyCode::Char('i') | KeyCode::Char('I') => {
                    self.show_package_details(&package)?;
                }
                KeyCode::Char('r') | KeyCode::Char('R') => {
                    let mut lines = vec![
                        format!("Location: {}", output.display()),
                        format!(
                            "{} components, {} objects",
                            package.selection.components.len(),
                            receipt.object_count
                        ),
                        "Secrets, large data, unknown binaries and executable hooks excluded."
                            .to_owned(),
                    ];
                    for finding in &review.secret_findings {
                        lines.push(format!(
                            "[EXCLUDED] {} / {}: {}",
                            finding.component_name, finding.artifact_path, finding.reason
                        ));
                    }
                    lines.extend(package.warnings.iter().cloned());
                    self.show_lines("Backup Report", &lines)?;
                }
                _ => {}
            }
        }
    }

    async fn custom_backup(&mut self) -> Result<(), Box<ErrorEnvelope>> {
        let Some(inventory) = self.ensure_inventory().await? else {
            return Ok(());
        };
        self.preferences.last_preset = BackupPreset::Custom;
        self.preferences.save()?;
        if !self.selection_initialized {
            self.selected = preset_selection(&inventory.graph, BackupPreset::Recommended)
                .components
                .into_iter()
                .collect();
            self.selection_initialized = true;
        }
        let categories = categories();
        let mut cursor = 0usize;
        loop {
            self.clear()?;
            self.line("Custom Backup")?;
            self.line("")?;
            for (index, category) in categories.iter().enumerate() {
                let mut count = 0;
                let mut selected = 0;
                for component in inventory
                    .graph
                    .components
                    .iter()
                    .filter(|component| component_category(component) == category.kind)
                {
                    count += 1;
                    selected += usize::from(self.selected.contains(&component.id));
                }
                let pointer = if index == cursor { ">" } else { " " };
                self.line(&format!(
                    "{pointer} [{}] {} {} (selected {})",
                    category.shortcut, category.label, count, selected
                ))?;
            }
            self.line("")?;
            self.line(&format!("Selected: {} components", self.selected.len()))?;
            self.line("[Space] Toggle category safely   [Enter] Open")?;
            self.line("[B] Create Backup   [Esc] Back")?;
            match read_key()? {
                KeyCode::Up => cursor = cursor.saturating_sub(1),
                KeyCode::Down => cursor = (cursor + 1).min(categories.len() - 1),
                KeyCode::Enter => self.select_category(&inventory, categories[cursor].kind)?,
                KeyCode::Char(' ') => {
                    let components =
                        category_components(&inventory.graph.components, categories[cursor].kind);
                    let safe = components
                        .iter()
                        .copied()
                        .filter(|component| component_is_safe_for_default(component))
                        .collect::<Vec<_>>();
                    let all_selected = !safe.is_empty()
                        && safe
                            .iter()
                            .all(|component| self.selected.contains(&component.id));
                    for component in safe {
                        if all_selected {
                            self.selected.remove(&component.id);
                        } else {
                            self.selected.insert(component.id.clone());
                        }
                    }
                }
                KeyCode::Esc | KeyCode::Backspace => return Ok(()),
                KeyCode::Char('b') | KeyCode::Char('B') => {
                    if self.selected.is_empty() {
                        self.clear()?;
                        self.line("No components are selected.")?;
                        self.line("Choose at least one safe component before creating a backup.")?;
                        self.line("Press any key to return.")?;
                        let _ = read_key()?;
                        continue;
                    }
                    let selection = selection_from_ids(&self.selected);
                    let review = self.service.review_selection(selection)?;
                    loop {
                        self.render_custom_review(&inventory, &review)?;
                        match read_key()? {
                            KeyCode::Enter => {
                                self.create_reviewed_backup(&review).await?;
                                return Ok(());
                            }
                            KeyCode::Char('d') | KeyCode::Char('D') => {
                                self.show_secret_findings(&review.secret_findings)?
                            }
                            KeyCode::Esc | KeyCode::Backspace => break,
                            _ => {}
                        }
                    }
                }
                KeyCode::Char(character) => {
                    if let Some((index, category)) = categories
                        .iter()
                        .enumerate()
                        .find(|(_, category)| category.shortcut.eq_ignore_ascii_case(&character))
                    {
                        cursor = index;
                        self.select_category(&inventory, category.kind)?;
                    }
                }
                _ => {}
            }
        }
    }

    fn render_custom_review(
        &mut self,
        inventory: &Inventory,
        review: &SelectionReview,
    ) -> Result<(), Box<ErrorEnvelope>> {
        self.clear()?;
        self.line("Custom Backup")?;
        self.line("")?;
        self.line(&format!(
            "Selected components: {}",
            review.selected_components.len()
        ))?;
        self.line(&format!(
            "Selected files: {}",
            review.selected_artifacts.len()
        ))?;
        self.line(&format!(
            "Estimated size: {}",
            format_bytes(review.total_bytes)
        ))?;
        if review.selected_components.len() < self.selected.len() {
            self.line("[WARN] Required safety filtering changed the selection.")?;
        }
        self.line(&format!(
            "Potential secrets excluded: {}",
            review.secret_findings.len()
        ))?;
        self.line(&format!("Inventory warnings: {}", inventory.warnings.len()))?;
        self.line("")?;
        self.line("[Enter] Create safely   [D] Secret details   [Esc] Back")
    }

    fn select_category(
        &mut self,
        inventory: &Inventory,
        kind: CategoryKind,
    ) -> Result<(), Box<ErrorEnvelope>> {
        let components = category_components(&inventory.graph.components, kind);
        if components.is_empty() {
            self.clear()?;
            self.line("No components were detected in this category.")?;
            self.line("Press any key to go back.")?;
            let _ = read_key()?;
            return Ok(());
        }
        let mut cursor = 0usize;
        loop {
            self.clear()?;
            self.line(category_label(kind))?;
            self.line("[Space] Select   [A] Select all safe   [N] Select none")?;
            self.line("[Enter] Details   [Esc] Back")?;
            self.line("")?;
            let (start, end) = visible_range(cursor, components.len(), 6);
            for (offset, component) in components[start..end].iter().enumerate() {
                let absolute = start + offset;
                let marker = if self.selected.contains(&component.id) {
                    "x"
                } else {
                    " "
                };
                let pointer = if absolute == cursor { ">" } else { " " };
                let badges = badges(component).join(" ");
                self.line(&format!(
                    "{pointer}[{marker}] {} {}",
                    clean_text(&component.display_name, 60),
                    badges
                ))?;
            }
            match read_key()? {
                KeyCode::Up => cursor = cursor.saturating_sub(1),
                KeyCode::Down => cursor = (cursor + 1).min(components.len() - 1),
                KeyCode::Char(' ') => {
                    let component = components[cursor];
                    if component_is_safe_for_default(component) {
                        if !self.selected.insert(component.id.clone()) {
                            self.selected.remove(&component.id);
                        }
                    } else {
                        self.show_unsafe_selection_warning(component)?;
                    }
                }
                KeyCode::Char('a') | KeyCode::Char('A') => {
                    for component in &components {
                        if component_is_safe_for_default(component) {
                            self.selected.insert(component.id.clone());
                        }
                    }
                }
                KeyCode::Char('n') | KeyCode::Char('N') => {
                    for component in &components {
                        self.selected.remove(&component.id);
                    }
                }
                KeyCode::Enter => {
                    self.show_component_details(inventory, components[cursor], true)?
                }
                KeyCode::Esc | KeyCode::Backspace => return Ok(()),
                _ => {}
            }
        }
    }

    async fn scan_screen(&mut self) -> Result<(), Box<ErrorEnvelope>> {
        let inventory = self.scan_current().await?;
        loop {
            self.clear()?;
            self.line("Scan completed.")?;
            self.line(&format!(
                "Detected: {} components",
                inventory.graph.components.len()
            ))?;
            let mut counts = BTreeMap::<&str, usize>::new();
            for component in &inventory.graph.components {
                *counts
                    .entry(category_label(component_category(component)))
                    .or_default() += 1;
            }
            let labels = counts
                .iter()
                .map(|(name, count)| format!("{name}: {count}"))
                .collect::<Vec<_>>();
            for pair in labels.chunks(2) {
                self.line(&pair.join(" | "))?;
            }
            self.line("")?;
            self.render_warning_summary(&inventory.warnings)?;
            self.line("")?;
            self.line("[Enter] Done   [V] View warnings")?;
            match read_key()? {
                KeyCode::Enter | KeyCode::Esc | KeyCode::Backspace => return Ok(()),
                KeyCode::Char('v') | KeyCode::Char('V') => self.view_warnings(&inventory)?,
                _ => {}
            }
        }
    }

    fn render_warning_summary(&mut self, warnings: &[String]) -> Result<(), Box<ErrorEnvelope>> {
        let important = warnings
            .iter()
            .filter(|warning| matches!(warning_severity(warning), "HIGH" | "MEDIUM"))
            .count();
        self.line(&format!(
            "Warnings: {} important / {} low-priority observations",
            important,
            warnings.len() - important
        ))?;
        let mut groups = BTreeMap::<String, usize>::new();
        for warning in warnings {
            *groups.entry(warning_group(warning)).or_default() += 1;
        }
        let labels = groups
            .iter()
            .map(|(name, count)| format!("{name}: {count}"))
            .collect::<Vec<_>>();
        for pair in labels.chunks(2) {
            self.line(&pair.join(" | "))?;
        }
        Ok(())
    }

    fn view_warnings(&mut self, inventory: &Inventory) -> Result<(), Box<ErrorEnvelope>> {
        let mut warnings = inventory.warnings.iter().collect::<Vec<_>>();
        if !self.preferences.all_warnings {
            warnings.sort_by_key(|warning| match warning_severity(warning) {
                "HIGH" => 0,
                "MEDIUM" => 1,
                "LOW" => 2,
                _ => 3,
            });
        }
        let lines = warnings
            .iter()
            .map(|warning| format!("[{}] {}", warning_severity(warning), warning))
            .collect::<Vec<_>>();
        self.show_lines("Warnings", &lines)
    }

    async fn browse_components(&mut self) -> Result<(), Box<ErrorEnvelope>> {
        let Some(inventory) = self.ensure_inventory().await? else {
            return Ok(());
        };
        let mut components = inventory.graph.components.iter().collect::<Vec<_>>();
        components.sort_by(|left, right| {
            left.display_name
                .cmp(&right.display_name)
                .then_with(|| left.id.cmp(&right.id))
        });
        if components.is_empty() {
            self.clear()?;
            self.line("No components were detected.")?;
            self.line("Press any key to go back.")?;
            let _ = read_key()?;
            return Ok(());
        }
        let mut cursor = 0usize;
        loop {
            self.clear()?;
            self.line("Browse Detected Components")?;
            self.line("[Enter] Details   [Esc] Back")?;
            self.line("")?;
            let (start, end) = visible_range(cursor, components.len(), 5);
            for (index, component) in components[start..end].iter().enumerate() {
                let absolute = start + index;
                let pointer = if absolute == cursor { ">" } else { " " };
                self.line(&format!(
                    "{pointer} {} {}",
                    clean_text(&component.display_name, 64),
                    badges(component).join(" ")
                ))?;
            }
            match read_key()? {
                KeyCode::Up => cursor = cursor.saturating_sub(1),
                KeyCode::Down => cursor = (cursor + 1).min(components.len() - 1),
                KeyCode::Enter => {
                    self.show_component_details(&inventory, components[cursor], false)?
                }
                KeyCode::Esc | KeyCode::Backspace => return Ok(()),
                _ => {}
            }
        }
    }

    fn show_component_details(
        &mut self,
        inventory: &Inventory,
        component: &Component,
        selectable: bool,
    ) -> Result<(), Box<ErrorEnvelope>> {
        loop {
            let source = component
                .provenance
                .as_ref()
                .map(|provenance| {
                    provenance
                        .provider
                        .as_ref()
                        .map(ToString::to_string)
                        .unwrap_or_else(|| provenance.adapter_id.clone())
                })
                .unwrap_or_else(|| "Unknown".to_owned());
            let mut lines = vec![
                format!("Type: {:?}", component.kind),
                format!("Source: {source}"),
                format!("Restore: {:?}", component.restore.portability),
                format!(
                    "Requires administrator: {}",
                    yes_no(component.restore.requires_elevation)
                ),
                "Authentication: never copied; sign in again when required".to_owned(),
                "Secrets: excluded; portable files are screened before packaging".to_owned(),
                format!("Confidence: {:?}", component.confidence),
                format!("Badges: {}", badges(component).join(" ")),
                format!("Component ID: {}", component.id),
                format!(
                    "Selection: {}",
                    if self.selected.contains(&component.id) {
                        "Included"
                    } else {
                        "Excluded"
                    }
                ),
            ];
            if let Some(catalog) = component
                .extensions
                .get("agent_catalog")
                .and_then(|value| value.as_object())
            {
                if let Some(command) = catalog.get("command").and_then(|value| value.as_str()) {
                    lines.push(format!("Detected launcher: {command}"));
                }
                lines.push("No portable configuration was discovered for this launcher".to_owned());
            }
            if component_is_catalog_only(component) {
                lines.push(
                    "Catalog-only reference: Reforge will not copy the executable".to_owned(),
                );
            }
            if let Some(scope) = component
                .extensions
                .get("safe_backup")
                .and_then(|value| value.as_object())
            {
                lines.push("Backup scope: reviewed configuration only".to_owned());
                if let Some(files) = scope
                    .get("included_surfaces")
                    .and_then(|value| value.as_array())
                {
                    lines.push("Included surfaces:".to_owned());
                    for file in files.iter().filter_map(|value| value.as_str()) {
                        lines.push(format!("  + {file}"));
                    }
                }
                if let Some(note) = scope.get("security_note").and_then(|value| value.as_str()) {
                    lines.push(format!("Excluded by policy: {note}"));
                }
            }
            let names = component_name_map(Some(&inventory.graph));
            for dependency in &component.dependencies {
                lines.push(format!(
                    "Dependency: {}",
                    names
                        .get(&dependency.to)
                        .map(String::as_str)
                        .unwrap_or("Unavailable in inventory")
                ));
            }
            for artifact in &component.artifacts {
                lines.push(format!(
                    "File: {:?}/{} [{:?}] {}",
                    artifact.source_path.root,
                    artifact.source_path.relative,
                    artifact.policy,
                    format_bytes(artifact.size_bytes)
                ));
            }
            lines.extend(component.restore.rationale.iter().cloned());
            let action = selectable.then_some(KeyCode::Char(' '));
            let footer = if selectable {
                "[Space] Include / Exclude  [Enter/Esc] Back"
            } else {
                "[Enter/Esc] Back"
            };
            match self.view_lines(&component.display_name, &lines, footer, action)? {
                KeyCode::Char(' ') if selectable => {
                    if self.selected.contains(&component.id) {
                        self.selected.remove(&component.id);
                    } else if component_is_safe_for_default(component) {
                        self.selected.insert(component.id.clone());
                    } else {
                        self.show_unsafe_selection_warning(component)?;
                    }
                }
                _ => return Ok(()),
            }
        }
    }

    fn show_unsafe_selection_warning(
        &mut self,
        component: &Component,
    ) -> Result<(), Box<ErrorEnvelope>> {
        loop {
            self.clear()?;
            if component.selection.sensitive || component_has_secret_artifact(component) {
                self.line("[WARN] Sensitive data detected")?;
                self.line(
                    "This component may contain credentials, API keys, or authentication data.",
                )?;
            } else if component_is_catalog_only(component) {
                self.line("[WARN] Agent launcher detected; configuration not discovered")?;
                self.line("Reforge will not copy the executable or invent a backup scope.")?;
            } else if component_has_large_data(component) {
                self.line("[WARN] Large data excluded")?;
                self.line("This component exceeds the safe automatic backup policy.")?;
            } else if component_is_unknown_binary(component) {
                self.line("[WARN] Unknown or portable binary excluded")?;
                self.line("Reforge cannot prove this executable is safe to transfer.")?;
            } else {
                self.line("[WARN] Manual safety review required")?;
                self.line("Reforge cannot include this component under the safe backup policy.")?;
            }
            self.line("")?;
            self.line("[1] Exclude - Recommended")?;
            self.line("[2] View safety details")?;
            self.line("[Esc] Back")?;
            match read_key()? {
                KeyCode::Char('1') => {
                    self.selected.remove(&component.id);
                    return Ok(());
                }
                KeyCode::Char('2') => {
                    self.clear()?;
                    self.line("Safety details")?;
                    self.line(&format!(
                        "Component: {}",
                        clean_text(&component.display_name, 80)
                    ))?;
                    self.line(&format!("Badges: {}", badges(component).join(" ")))?;
                    self.line(&format!("Restore policy: {:?}", component.restore.primary))?;
                    for rationale in &component.restore.rationale {
                        self.line(&format!("- {}", clean_text(rationale, 120)))?;
                    }
                    self.line("")?;
                    self.line("Secret values and credential contents are never displayed.")?;
                    self.line("Press any key to return.")?;
                    let _ = read_key()?;
                }
                KeyCode::Esc | KeyCode::Backspace | KeyCode::Enter => return Ok(()),
                _ => {}
            }
        }
    }

    async fn backup_history(&mut self) -> Result<(), Box<ErrorEnvelope>> {
        let directory = self.preferences.backup_directory()?;
        let records = backup_history_records().unwrap_or_default();
        let mut cursor = 0usize;
        loop {
            let mut packages = package_files(&directory)?;
            packages.sort_by_key(|left| std::cmp::Reverse(left.1));
            if packages.is_empty() {
                self.clear()?;
                self.line("Backup History")?;
                self.line("")?;
                self.line("No backups found yet.")?;
                self.line("Press any key to go back.")?;
                let _ = read_key()?;
                return Ok(());
            }
            cursor = cursor.min(packages.len() - 1);
            self.clear()?;
            self.line("Backup History")?;
            self.line("[Enter] Actions   [Esc] Back")?;
            self.line("")?;
            let (start, end) = visible_range(cursor, packages.len(), 7);
            for (offset, (path, modified)) in packages[start..end].iter().enumerate() {
                let absolute = start + offset;
                let pointer = if absolute == cursor { ">" } else { " " };
                let shortcut = if absolute < 9 {
                    format!("[{}]", absolute + 1)
                } else {
                    "   ".to_owned()
                };
                let size = fs::metadata(path)
                    .map(|metadata| format_bytes(metadata.len()))
                    .unwrap_or_else(|_| "unknown size".to_owned());
                self.line(&format!(
                    "{pointer} {shortcut} {}  {}  {}",
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or("backup.reforge"),
                    format_date(*modified),
                    size
                ))?;
            }
            self.line(&backup_record_label(
                &records,
                &packages[cursor].0,
                packages[cursor].1,
            ))?;
            match read_key()? {
                KeyCode::Up => cursor = cursor.saturating_sub(1),
                KeyCode::Down => cursor = (cursor + 1).min(packages.len() - 1),
                KeyCode::Enter => {
                    self.backup_history_actions(&packages[cursor].0).await?;
                }
                KeyCode::Esc | KeyCode::Backspace => return Ok(()),
                KeyCode::Char(character) if character.is_ascii_digit() => {
                    let index = character.to_digit(10).unwrap_or(0) as usize;
                    if (1..=packages.len()).contains(&index) {
                        cursor = index - 1;
                        self.backup_history_actions(&packages[cursor].0).await?;
                    }
                }
                _ => {}
            }
        }
    }

    async fn backup_history_actions(&mut self, path: &Path) -> Result<(), Box<ErrorEnvelope>> {
        let package = self.service.inspect_package(path)?;
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("backup.reforge");
        loop {
            let context = vec![
                format!("Backup: {}", clean_text(name, 100)),
                format!("Created: {}", format_date(package.manifest.created_at)),
                format!("Components: {}", package.selection.components.len()),
                format!("Warnings: {}", package.warnings.len()),
            ];
            match self.select_menu_with_context(
                "Backup History",
                &context,
                &[
                    "Inspect backup",
                    "Verify package integrity",
                    "Restore this backup",
                    "Show location",
                    "Delete backup",
                ],
            )? {
                MenuChoice::Selected(0) => self.show_package_details(&package)?,
                MenuChoice::Selected(1) => {
                    let verified = self.service.inspect_package(path)?;
                    self.clear()?;
                    self.line("[OK] Package and object hashes are valid")?;
                    self.line(&format!(
                        "[OK] {} components, {} objects",
                        verified.selection.components.len(),
                        verified.object_index.objects.len()
                    ))?;
                    self.line("Press any key to return.")?;
                    let _ = read_key()?;
                }
                MenuChoice::Selected(2) => {
                    self.restore_package(path.to_owned()).await?;
                    return Ok(());
                }
                MenuChoice::Selected(3) => {
                    self.clear()?;
                    self.line("Backup location")?;
                    self.line(&path.display().to_string())?;
                    self.line("Press any key to return.")?;
                    let _ = read_key()?;
                }
                MenuChoice::Selected(4) => {
                    let confirmation = vec![format!(
                        "Delete {}? This cannot be undone.",
                        clean_text(name, 100)
                    )];
                    if matches!(
                        self.select_menu_with_context(
                            "Delete Backup",
                            &confirmation,
                            &["Cancel - keep backup", "Delete backup permanently"],
                        )?,
                        MenuChoice::Selected(1)
                    ) {
                        fs::remove_file(path)
                            .map_err(|error| io_error(error, "Delete backup package"))?;
                        self.clear()?;
                        self.line("[OK] Backup deleted")?;
                        self.line("Press any key to return to Backup History.")?;
                        let _ = read_key()?;
                        return Ok(());
                    }
                }
                MenuChoice::Back | MenuChoice::Exit => return Ok(()),
                MenuChoice::Selected(_) => {}
            }
        }
    }

    async fn restore_backup(&mut self) -> Result<(), Box<ErrorEnvelope>> {
        let Some(package_path) = self.choose_package()? else {
            return Ok(());
        };
        self.restore_package(package_path).await
    }

    async fn restore_package(&mut self, package_path: PathBuf) -> Result<(), Box<ErrorEnvelope>> {
        let package = self.service.inspect_package(&package_path)?;
        let selected = package.selection.components.iter().collect::<BTreeSet<_>>();
        let requires_user_action = package
            .graph
            .components
            .iter()
            .filter(|component| {
                selected.contains(&component.id) && component.restore.requires_user_action
            })
            .count();
        let requires_reauthentication = package
            .graph
            .components
            .iter()
            .filter(|component| {
                selected.contains(&component.id)
                    && component.restore.primary == RestoreStrategy::ReauthRequired
            })
            .count();
        let mut context = vec![
            "[OK] Package valid".to_owned(),
            "[OK] Hashes valid".to_owned(),
            format!("[OK] {} components", package.selection.components.len()),
        ];
        if !package.warnings.is_empty() {
            context.push(format!(
                "[WARN] {} package warnings",
                package.warnings.len()
            ));
        }
        if requires_user_action > 0 {
            context.push(format!(
                "[WARN] {requires_user_action} components require user action"
            ));
        }
        if requires_reauthentication > 0 {
            context.push(format!(
                "[WARN] {requires_reauthentication} require reauthentication"
            ));
        }
        let mode = match self.select_menu_with_context(
            "Inspecting Backup",
            &context,
            &[
                "Recommended - Merge safely with this PC",
                "Clean / Rebuild - for a fresh Windows installation",
                "Advanced",
            ],
        )? {
            MenuChoice::Selected(0) => RestoreMode::Migration,
            MenuChoice::Selected(1) => RestoreMode::Rebuild,
            MenuChoice::Selected(2) => match self.select_menu(&["Migration", "Rebuild"])? {
                MenuChoice::Selected(0) => RestoreMode::Migration,
                MenuChoice::Selected(1) => RestoreMode::Rebuild,
                _ => return Ok(()),
            },
            _ => return Ok(()),
        };
        let run_id = ApplicationService::allocate_run_id()?;
        let plan = self
            .build_plan_with_cancel(&package_path, mode, run_id.clone())
            .await?;
        self.render_restore_plan(&plan)?;
        loop {
            match read_key()? {
                KeyCode::Enter => break,
                KeyCode::Char('d') | KeyCode::Char('D') => self.show_plan_details(&plan)?,
                KeyCode::Esc | KeyCode::Backspace => return Ok(()),
                _ => {}
            }
        }

        let report = self
            .start_restore_with_cancel(run_id, Some(&package.graph))
            .await?;
        self.handle_restore_report(report, Some(&package.graph))
            .await
    }

    async fn handle_restore_report(
        &mut self,
        mut report: RestoreReport,
        graph: Option<&reforge_domain::PackageGraph>,
    ) -> Result<(), Box<ErrorEnvelope>> {
        loop {
            let pending = report
                .manual_actions
                .iter()
                .find(|action| matches!(&action.state, ManualActionState::Pending))
                .cloned();
            let Some(action) = pending else {
                return self.report_actions(report, graph).await;
            };

            self.render_action_required(&action)?;
            match read_key()? {
                KeyCode::Enter => {
                    self.service
                        .acknowledge_manual_action(&report.run_id, &action.id)?;
                    report = self
                        .resume_restore_with_cancel(report.run_id.clone(), graph)
                        .await?;
                }
                KeyCode::Char('s') | KeyCode::Char('S') => {
                    self.service
                        .skip_manual_action(&report.run_id, &action.id)?;
                    report = self
                        .resume_restore_with_cancel(report.run_id.clone(), graph)
                        .await?;
                }
                KeyCode::Char('d') | KeyCode::Char('D') => self.show_action_details(&action)?,
                KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc | KeyCode::Backspace => {
                    self.clear()?;
                    self.line("Restore stopped safely. No further operations were started.")?;
                    self.line("Use Advanced > Resume pending restore to continue later.")?;
                    self.line("Press any key to go back.")?;
                    let _ = read_key()?;
                    return Ok(());
                }
                _ => {}
            }
        }
    }

    fn render_action_required(
        &mut self,
        action: &reforge_domain::ManualAction,
    ) -> Result<(), Box<ErrorEnvelope>> {
        self.clear()?;
        self.line("Action Required")?;
        self.line("")?;
        self.line(&clean_text(&action.title, 120))?;
        self.line(&clean_text(&action.reason, 180))?;
        if let Some(instruction) = action.instructions.first() {
            self.line("")?;
            self.line(&clean_text(instruction, 180))?;
        }
        self.line("")?;
        self.line("[Enter] Check again   [S] Skip for now   [D] Details   [Q] Stop safely")
    }

    fn show_action_details(
        &mut self,
        action: &reforge_domain::ManualAction,
    ) -> Result<(), Box<ErrorEnvelope>> {
        self.clear()?;
        self.line("Action Details")?;
        self.line(&format!("Title: {}", clean_text(&action.title, 120)))?;
        self.line(&format!("Reason: {}", clean_text(&action.reason, 180)))?;
        self.line(&format!("Risk: {:?}", action.risk))?;
        for instruction in &action.instructions {
            self.line(&format!("- {}", clean_text(instruction, 180)))?;
        }
        self.line("")?;
        self.line("Press any key to return.")?;
        let _ = read_key()?;
        Ok(())
    }

    fn choose_package(&mut self) -> Result<Option<PathBuf>, Box<ErrorEnvelope>> {
        let directory = self.preferences.backup_directory()?;
        let mut packages = package_files(&directory)?;
        packages.sort_by_key(|left| std::cmp::Reverse(left.1));
        let records = backup_history_records().unwrap_or_default();
        if packages.is_empty() {
            self.clear()?;
            self.line("No backup files were found in the default backup directory.")?;
            self.line("")?;
            self.line("[Enter] Choose another .reforge file   [Esc] Back")?;
            return match read_key()? {
                KeyCode::Enter => self.browse_package_file(),
                _ => Ok(None),
            };
        }
        let mut cursor = 0usize;
        loop {
            self.clear()?;
            self.line("Select backup")?;
            self.line("[Enter] Select   [A] Choose another file   [Esc] Back")?;
            self.line("")?;
            let (start, end) = visible_range(cursor, packages.len(), 7);
            for (offset, (path, modified)) in packages[start..end].iter().enumerate() {
                let absolute = start + offset;
                let pointer = if absolute == cursor { ">" } else { " " };
                let shortcut = if absolute < 9 {
                    format!("[{}]", absolute + 1)
                } else {
                    "   ".to_owned()
                };
                self.line(&format!(
                    "{pointer} {shortcut} {}  {}",
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or("backup.reforge"),
                    format_date(*modified)
                ))?;
            }
            self.line(&backup_record_label(
                &records,
                &packages[cursor].0,
                packages[cursor].1,
            ))?;
            match read_key()? {
                KeyCode::Up => cursor = cursor.saturating_sub(1),
                KeyCode::Down => cursor = (cursor + 1).min(packages.len() - 1),
                KeyCode::Enter => return Ok(Some(packages[cursor].0.clone())),
                KeyCode::Esc | KeyCode::Backspace => return Ok(None),
                KeyCode::Char('a') | KeyCode::Char('A') => {
                    return self.browse_package_file();
                }
                KeyCode::Char(character) if character.is_ascii_digit() => {
                    let index = character.to_digit(10).unwrap_or(0) as usize;
                    if (1..=packages.len()).contains(&index) {
                        return Ok(Some(packages[index - 1].0.clone()));
                    }
                }
                _ => {}
            }
        }
    }

    fn browse_package_file(&mut self) -> Result<Option<PathBuf>, Box<ErrorEnvelope>> {
        let mut directory = self.preferences.backup_directory()?;
        while !directory.is_dir() {
            let Some(parent) = directory.parent() else {
                break;
            };
            directory = parent.to_owned();
        }
        loop {
            let mut paths = fs::read_dir(&directory)
                .map_err(|error| io_error(error, "Browse backup directory"))?
                .filter_map(Result::ok)
                .filter_map(|entry| {
                    let kind = entry.file_type().ok()?;
                    let path = entry.path();
                    (kind.is_dir()
                        || (kind.is_file()
                            && path.extension().is_some_and(|extension| {
                                extension.eq_ignore_ascii_case("reforge")
                            })))
                    .then_some((path, kind.is_dir()))
                })
                .collect::<Vec<_>>();
            paths.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
            let mut labels = vec![
                "Enter a file or folder path".to_owned(),
                "Parent folder".to_owned(),
                "Choose drive".to_owned(),
            ];
            labels.extend(paths.iter().map(|(path, is_dir)| {
                format!(
                    "{} {}",
                    if *is_dir { "[folder]" } else { "[backup]" },
                    path.file_name().unwrap_or_default().to_string_lossy()
                )
            }));
            let refs = labels.iter().map(String::as_str).collect::<Vec<_>>();
            match self.select_menu_with_context(
                "Choose a .reforge file",
                &[directory.display().to_string()],
                &refs,
            )? {
                MenuChoice::Selected(0) => {
                    if let Some(path) = self.prompt_path("File or folder path")? {
                        if path.is_dir() {
                            directory = path;
                        } else {
                            return Ok(Some(path));
                        }
                    }
                }
                MenuChoice::Selected(1) => {
                    if let Some(parent) = directory.parent() {
                        directory = parent.to_owned();
                    }
                }
                MenuChoice::Selected(2) => {
                    let drives = ('A'..='Z')
                        .map(|letter| format!("{letter}:\\"))
                        .filter(|drive| Path::new(drive).is_dir())
                        .collect::<Vec<_>>();
                    let refs = drives.iter().map(String::as_str).collect::<Vec<_>>();
                    if let MenuChoice::Selected(index) =
                        self.select_menu_with_context("Choose drive", &[], &refs)?
                    {
                        directory = PathBuf::from(&drives[index]);
                    }
                }
                MenuChoice::Selected(index) => {
                    let (path, is_dir) = &paths[index - 3];
                    if *is_dir {
                        directory = path.clone();
                    } else {
                        return Ok(Some(path.clone()));
                    }
                }
                MenuChoice::Back | MenuChoice::Exit => return Ok(None),
            }
        }
    }

    async fn build_plan_with_cancel(
        &mut self,
        package_path: &Path,
        mode: RestoreMode,
        run_id: reforge_domain::RunId,
    ) -> Result<RestorePlan, Box<ErrorEnvelope>> {
        self.clear()?;
        self.line("Preparing restore plan...")?;
        let cancellation = CancellationToken::new();
        let future = self.service.build_plan(
            package_path,
            mode,
            run_id,
            true,
            &cancellation,
            progress_to_terminal,
        );
        tokio::pin!(future);
        tokio::select! {
            result = &mut future => result,
            cancel_result = wait_for_cancel_request() => {
                cancellation.cancel();
                let _ = future.await;
                cancel_result?;
                Err(cancelled_error())
            }
        }
    }

    async fn start_restore_with_cancel(
        &mut self,
        run_id: reforge_domain::RunId,
        graph: Option<&reforge_domain::PackageGraph>,
    ) -> Result<RestoreReport, Box<ErrorEnvelope>> {
        self.clear()?;
        self.line("Restoring...")?;
        self.line("[ ] Operations are being applied safely. Ctrl+C requests a clean stop.")?;
        let cancellation = CancellationToken::new();
        let names = component_name_map(graph);
        let operation_progress =
            move |operation: &Operation, state: OperationState, completed: u64, total: u64| {
                restore_progress_to_terminal(&names, operation, state, completed, total);
            };
        let future = self
            .service
            .execute_planned_restore_with_operation_progress(
                run_id,
                &cancellation,
                progress_to_terminal,
                operation_progress,
            );
        tokio::pin!(future);
        tokio::select! {
            result = &mut future => result,
            cancel_result = wait_for_cancel_request() => {
                cancellation.cancel();
                let _ = future.await;
                cancel_result?;
                Err(cancelled_error())
            }
        }
    }

    async fn resume_restore_with_cancel(
        &mut self,
        run_id: reforge_domain::RunId,
        graph: Option<&reforge_domain::PackageGraph>,
    ) -> Result<RestoreReport, Box<ErrorEnvelope>> {
        self.clear()?;
        self.line("Checking restore status...")?;
        let cancellation = CancellationToken::new();
        let names = component_name_map(graph);
        let operation_progress =
            move |operation: &Operation, state: OperationState, completed: u64, total: u64| {
                restore_progress_to_terminal(&names, operation, state, completed, total);
            };
        let future = self.service.resume_restore_with_operation_progress(
            run_id,
            &cancellation,
            progress_to_terminal,
            operation_progress,
        );
        tokio::pin!(future);
        tokio::select! {
            result = &mut future => result,
            cancel_result = wait_for_cancel_request() => {
                cancellation.cancel();
                let _ = future.await;
                cancel_result?;
                Err(cancelled_error())
            }
        }
    }

    fn render_restore_plan(&mut self, plan: &RestorePlan) -> Result<(), Box<ErrorEnvelope>> {
        let summary = self.service.plan_summary(plan)?;
        self.clear()?;
        self.line("Restore Plan")?;
        self.line(&format!("Install {}", summary.install))?;
        self.line(&format!("Already present {}", summary.already_present))?;
        self.line(&format!("Update {}", summary.update))?;
        self.line(&format!(
            "Restore configurations {}",
            summary.configurations
        ))?;
        self.line(&format!("Manual action {}", summary.manual))?;
        self.line(&format!("Reauthentication {}", summary.reauth))?;
        self.line(&format!(
            "Conflicts {} / Warnings {}",
            plan.conflicts.len(),
            plan.warnings.len()
        ))?;
        self.line("")?;
        self.line("No changes have been made yet.")?;
        self.line("[Enter] Start Restore   [D] Details   [Esc] Cancel")
    }

    fn show_plan_details(&mut self, plan: &RestorePlan) -> Result<(), Box<ErrorEnvelope>> {
        let mut lines = plan
            .operations
            .iter()
            .map(|operation| format!("{} {:?}", operation.component, operation.kind))
            .collect::<Vec<_>>();
        for action in &plan.manual_actions {
            lines.push(format!("[ACTION] {} - {}", action.title, action.reason));
        }
        for conflict in &plan.conflicts {
            lines.push(format!("[CONFLICT] {conflict:?}"));
        }
        lines.extend(plan.warnings.iter().cloned());
        self.show_lines("Restore Plan Details (advanced)", &lines)?;
        self.render_restore_plan(plan)
    }

    fn render_report(&mut self, report: &RestoreReport) -> Result<(), Box<ErrorEnvelope>> {
        self.clear()?;
        self.line("Verifying restored environment...")?;
        self.line(&format!("[OK] Verified {}", report.counts.verified))?;
        self.line(&format!(
            "[OK] Already present {}",
            report.counts.already_present
        ))?;
        if report.counts.partial > 0 {
            self.line(&format!("[WARN] Partial {}", report.counts.partial))?;
        }
        if report.counts.reauth_required > 0 {
            self.line(&format!(
                "[WARN] Reauthentication {}",
                report.counts.reauth_required
            ))?;
        }
        if report.counts.waiting_for_user > 0 {
            self.line(&format!(
                "[WARN] Waiting for user {}",
                report.counts.waiting_for_user
            ))?;
        }
        if report.counts.reboot_required > 0 {
            self.line(&format!(
                "[WARN] Reboot required {}",
                report.counts.reboot_required
            ))?;
        }
        if report.counts.unsupported > 0 {
            self.line(&format!("[WARN] Unsupported {}", report.counts.unsupported))?;
        }
        if report.counts.failed > 0 {
            self.line(&format!("[FAIL] Failed {}", report.counts.failed))?;
        }
        let ready = report.counts.verified + report.counts.already_present;
        self.line("")?;
        self.line(&format!(
            "Overall: {ready} / {} ready",
            report.components.len()
        ))?;
        self.line(&format!("Status: {:?}", report.status))?;
        self.line("[Enter] Finish   [V] View issues   [R] Save report")
    }

    async fn report_actions(
        &mut self,
        report: RestoreReport,
        graph: Option<&reforge_domain::PackageGraph>,
    ) -> Result<(), Box<ErrorEnvelope>> {
        loop {
            self.render_report(&report)?;
            match read_key()? {
                KeyCode::Enter | KeyCode::Esc | KeyCode::Backspace => return Ok(()),
                KeyCode::Char('v') | KeyCode::Char('V') => {
                    self.show_report_issues(&report, graph)?
                }
                KeyCode::Char('r') | KeyCode::Char('R') => {
                    let filename = format!("report-{}.json", Utc::now().format("%Y%m%d-%H%M%S"));
                    let path =
                        unique_backup_path(self.preferences.backup_directory()?.join(filename))?;
                    self.service.save_report(&report.run_id, &path)?;
                    self.clear()?;
                    self.line(&format!("Report saved: {}", path.display()))?;
                    self.line("Press any key to continue.")?;
                    let _ = read_key()?;
                }
                _ => {}
            }
        }
    }

    fn show_report_issues(
        &mut self,
        report: &RestoreReport,
        graph: Option<&reforge_domain::PackageGraph>,
    ) -> Result<(), Box<ErrorEnvelope>> {
        let mut lines = Vec::new();
        for action in &report.manual_actions {
            lines.push(format!("[ACTION] {} - {}", action.title, action.reason));
            lines.extend(action.instructions.iter().cloned());
        }
        let names = component_name_map(graph);
        for (index, component) in report.components.iter().enumerate() {
            if !matches!(
                component.status,
                ReportStatus::Verified | ReportStatus::AlreadyPresent
            ) {
                let name = names
                    .get(&component.component)
                    .cloned()
                    .unwrap_or_else(|| format!("Component {}", index + 1));
                lines.push(format!("[{:?}] {name}", component.status));
            }
        }
        if lines.is_empty() {
            lines.push("No issues require attention.".to_owned());
        }
        self.show_lines("Restore Issues", &lines)
    }

    async fn advanced(&mut self) -> Result<(), Box<ErrorEnvelope>> {
        loop {
            match self.select_menu(&[
                "Raw inventory",
                "Package inspector",
                "Restore plan preview",
                "Runs / Resume pending restore",
                "Pending actions",
                "Verification reports",
                "Diagnostics",
                "Export inventory JSON",
                "CLI help",
            ])? {
                MenuChoice::Selected(0) => self.raw_inventory().await?,
                MenuChoice::Selected(1) => {
                    if let Some(path) = self.choose_package()? {
                        let package = self.service.inspect_package(&path)?;
                        self.show_package_details(&package)?;
                    }
                }
                MenuChoice::Selected(2) => {
                    if let Some(path) = self.choose_package()? {
                        let mode = match self.select_menu(&["Migration", "Rebuild"])? {
                            MenuChoice::Selected(0) => RestoreMode::Migration,
                            MenuChoice::Selected(1) => RestoreMode::Rebuild,
                            _ => continue,
                        };
                        let id = ApplicationService::allocate_run_id()?;
                        let plan = self.build_plan_with_cancel(&path, mode, id).await?;
                        let summary = self.service.plan_summary(&plan)?;
                        self.show_lines(
                            "Restore plan preview - no changes made",
                            &[
                                format!(
                                    "Install: {} / Update: {} / Already present: {}",
                                    summary.install, summary.update, summary.already_present
                                ),
                                format!(
                                    "Configurations: {} / Manual: {} / Reauthentication: {}",
                                    summary.configurations, summary.manual, summary.reauth
                                ),
                                format!(
                                    "Conflicts: {} / Warnings: {}",
                                    plan.conflicts.len(),
                                    plan.warnings.len()
                                ),
                                "To apply a backup, use Restore Backup from the main menu."
                                    .to_owned(),
                            ],
                        )?;
                    }
                }
                MenuChoice::Selected(3) => self.resume_pending().await?,
                MenuChoice::Selected(4) => self.pending_actions()?,
                MenuChoice::Selected(5) => self.verification_reports().await?,
                MenuChoice::Selected(6) => {
                    self.clear()?;
                    self.line("Diagnostics")?;
                    self.show_result(doctor_command())?;
                    self.line("Press any key to go back.")?;
                    let _ = read_key()?;
                }
                MenuChoice::Selected(7) => self.export_inventory().await?,
                MenuChoice::Selected(8) => self.cli_help()?,
                MenuChoice::Back | MenuChoice::Exit => return Ok(()),
                MenuChoice::Selected(_) => {}
            }
        }
    }

    async fn raw_inventory(&mut self) -> Result<(), Box<ErrorEnvelope>> {
        let Some(inventory) = self.ensure_inventory().await? else {
            return Ok(());
        };
        let lines = inventory
            .graph
            .components
            .iter()
            .map(|component| {
                format!(
                    "[{:?}] {}  {}",
                    component.kind, component.display_name, component.id
                )
            })
            .collect::<Vec<_>>();
        self.show_lines("Raw Inventory (advanced)", &lines)
    }

    fn pending_actions(&mut self) -> Result<(), Box<ErrorEnvelope>> {
        let state = super::state_paths()?;
        let mut actions = Vec::new();
        if let Ok(entries) = fs::read_dir(state.root.join("runs")) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
                    continue;
                }
                let Ok(run_state) = super::read_json_state::<super::RunState>(&path) else {
                    continue;
                };
                let Ok(Some(details)) = self.service.run_details(&run_state.run_id) else {
                    continue;
                };
                for action in details.manual_actions.into_iter().filter(|action| {
                    matches!(
                        action.state,
                        ManualActionState::Pending | ManualActionState::Acknowledged
                    )
                }) {
                    actions.push((run_state.package_path.clone(), action));
                }
            }
        }
        let mut lines = Vec::new();
        for (package, action) in &actions {
            let package = Path::new(package)
                .file_name()
                .unwrap_or_default()
                .to_string_lossy();
            lines.push(format!(
                "[{:?}] {} - {}",
                action.state, package, action.title
            ));
            lines.push(action.reason.clone());
        }
        if lines.is_empty() {
            lines.push("No pending actions.".to_owned());
        } else {
            lines.push("Use Runs / Resume pending restore to resolve these actions.".to_owned());
        }
        self.show_lines("Pending Actions", &lines)
    }

    async fn export_inventory(&mut self) -> Result<(), Box<ErrorEnvelope>> {
        let Some(inventory) = self.ensure_inventory().await? else {
            return Ok(());
        };
        self.clear()?;
        self.line("Export Inventory JSON")?;
        let Some(requested) = self.prompt_path("Output JSON path: ")? else {
            return Ok(());
        };
        let output = super::output_file_path(&requested)?;
        let safe = super::safe_json(&inventory)?;
        let bytes = serde_json::to_vec_pretty(&safe).map_err(|_| {
            boxed_error(
                reforge_domain::ReforgeErrorCode::SchemaInvalid,
                "Inventory export serialization failed",
            )
        })?;
        super::write_absolute_file(&output, &bytes)?;
        self.clear()?;
        self.line("[OK] Redacted inventory exported")?;
        self.line(&output.display().to_string())?;
        self.line("Press any key to go back.")?;
        let _ = read_key()?;
        Ok(())
    }

    fn cli_help(&mut self) -> Result<(), Box<ErrorEnvelope>> {
        self.clear()?;
        self.line("CLI Help")?;
        self.line("")?;
        self.line("Interactive: reforge | reforge backup | reforge restore")?;
        self.line("Automation: doctor, scan, inventory, package, target, plan,")?;
        self.line("            restore, resume, action, verify, report")?;
        self.line(
            "Add --help to a command for options. Add --json for one machine-readable document.",
        )?;
        self.line("")?;
        self.line("Press any key to go back.")?;
        let _ = read_key()?;
        Ok(())
    }

    async fn resume_pending(&mut self) -> Result<(), Box<ErrorEnvelope>> {
        let state = super::state_paths()?;
        let mut runs = Vec::new();
        let runs_path = state.root.join("runs");
        if let Ok(entries) = fs::read_dir(&runs_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
                    continue;
                }
                let Ok(run_state) = super::read_json_state::<super::RunState>(&path) else {
                    continue;
                };
                let Ok(Some(details)) = self.service.run_details(&run_state.run_id) else {
                    continue;
                };
                if details.run.approval_state == ApprovalState::Approved
                    && !matches!(&details.run.status, reforge_domain::RunStatus::Completed)
                {
                    runs.push((run_state.run_id, run_state.package_path, details.run.status));
                }
            }
        }
        if runs.is_empty() {
            self.clear()?;
            self.line("No pending restore runs.")?;
            self.line("Press any key to go back.")?;
            let _ = read_key()?;
            return Ok(());
        }
        let mut cursor = 0usize;
        loop {
            self.clear()?;
            self.line("Pending restores")?;
            self.line("[Enter] Resume   [Esc] Back")?;
            self.line("")?;
            let (start, end) = visible_range(cursor, runs.len(), 5);
            for (offset, (_, package, status)) in runs[start..end].iter().enumerate() {
                let absolute = start + offset;
                let pointer = if absolute == cursor { ">" } else { " " };
                let shortcut = if absolute < 9 {
                    format!("[{}]", absolute + 1)
                } else {
                    "   ".to_owned()
                };
                self.line(&format!(
                    "{pointer} {shortcut} {} ({:?})",
                    clean_text(package, 100),
                    status
                ))?;
            }
            match read_key()? {
                KeyCode::Up => cursor = cursor.saturating_sub(1),
                KeyCode::Down => cursor = (cursor + 1).min(runs.len() - 1),
                KeyCode::Enter => {
                    let (run_id, _, _) = &runs[cursor];
                    let report = self
                        .resume_restore_with_cancel(run_id.clone(), None)
                        .await?;
                    return self.handle_restore_report(report, None).await;
                }
                KeyCode::Esc | KeyCode::Backspace => return Ok(()),
                KeyCode::Char(character) if character.is_ascii_digit() => {
                    let index = character.to_digit(10).unwrap_or(0) as usize;
                    if (1..=runs.len()).contains(&index) {
                        cursor = index - 1;
                        let (run_id, _, _) = &runs[cursor];
                        let report = self
                            .resume_restore_with_cancel(run_id.clone(), None)
                            .await?;
                        return self.handle_restore_report(report, None).await;
                    }
                }
                _ => {}
            }
        }
    }

    async fn verification_reports(&mut self) -> Result<(), Box<ErrorEnvelope>> {
        let directory = super::state_paths()?.root.join("reports");
        let mut paths = match fs::read_dir(&directory) {
            Ok(entries) => entries
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| {
                    path.extension()
                        .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
                })
                .collect::<Vec<_>>(),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(io_error(error, "Read verification reports")),
        };
        paths.sort_by(|left, right| right.cmp(left));
        if paths.is_empty() {
            return self.show_lines(
                "Verification Reports",
                &["No verification reports found.".to_owned()],
            );
        }
        loop {
            let labels = paths
                .iter()
                .map(|path| {
                    path.file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .into_owned()
                })
                .collect::<Vec<_>>();
            let refs = labels.iter().map(String::as_str).collect::<Vec<_>>();
            let MenuChoice::Selected(index) =
                self.select_menu_with_context("Verification Reports", &[], &refs)?
            else {
                return Ok(());
            };
            let report: RestoreReport = super::read_json_state(&paths[index])?;
            self.report_actions(report, None).await?;
        }
    }

    fn show_package_details(
        &mut self,
        package: &reforge_package::InspectedPackage,
    ) -> Result<(), Box<ErrorEnvelope>> {
        let selection =
            reforge_domain::selection::build_selection_closure(&package.graph, &package.selection)?;
        let mut lines = vec![
            format!("Package: {}", package.manifest.package_id),
            format!("Created: {}", format_date(package.manifest.created_at)),
            format!("Trust: {:?}", package.trust),
            format!("Components: {}", selection.selected_components.len()),
            format!("Files: {}", selection.selected_artifacts.len()),
            format!("Archive size: {}", format_bytes(package.archive_bytes())),
            format!("Warnings: {}", package.warnings.len()),
            "Selected components:".to_owned(),
        ];
        let names = component_name_map(Some(&package.graph));
        for id in &package.selection.components {
            lines.push(format!(
                "- {}",
                names
                    .get(id)
                    .map(String::as_str)
                    .unwrap_or("Unknown component")
            ));
        }
        lines.extend(
            package
                .warnings
                .iter()
                .map(|warning| format!("[WARN] {warning}")),
        );
        self.show_lines("Package Details", &lines)
    }

    fn settings(&mut self) -> Result<(), Box<ErrorEnvelope>> {
        loop {
            let context = vec![
                format!(
                    "Backup directory: {}",
                    self.preferences.backup_directory()?.display()
                ),
                format!("Last preset: {}", self.preferences.last_preset.label()),
                format!(
                    "Appearance: {}",
                    if self.preferences.unicode {
                        "Unicode"
                    } else {
                        "ASCII (compatible)"
                    }
                ),
                format!(
                    "Warnings: {}",
                    if self.preferences.all_warnings {
                        "All"
                    } else {
                        "Important first"
                    }
                ),
                "Safety is fixed: secrets, large data and unknown binaries excluded.".to_owned(),
            ];
            let mut preferences = self.preferences.clone();
            match self.select_menu_with_context(
                "Settings",
                &context,
                &[
                    "Change backup directory",
                    "Use the default Documents backup directory",
                    "Choose default backup preset",
                    "Toggle ASCII / Unicode appearance",
                    "Toggle warning detail",
                ],
            )? {
                MenuChoice::Selected(0) => {
                    let Some(path) = self.prompt_path("Absolute backup directory")? else {
                        continue;
                    };
                    if !path.is_absolute() {
                        self.show_lines(
                            "Backup directory",
                            &["Use an absolute path, such as C:\\Backups.".to_owned()],
                        )?;
                        continue;
                    }
                    preferences.backup_directory = Some(path);
                }
                MenuChoice::Selected(1) => preferences.backup_directory = None,
                MenuChoice::Selected(2) => {
                    self.choose_preset()?;
                    continue;
                }
                MenuChoice::Selected(3) => preferences.unicode = !preferences.unicode,
                MenuChoice::Selected(4) => preferences.all_warnings = !preferences.all_warnings,
                MenuChoice::Back | MenuChoice::Exit => return Ok(()),
                _ => continue,
            }
            preferences.save()?;
            self.preferences = preferences;
        }
    }

    async fn ensure_inventory(&mut self) -> Result<Option<Inventory>, Box<ErrorEnvelope>> {
        let inventory = self
            .inventory
            .clone()
            .or_else(|| self.service.inventory().ok());
        if let Some(inventory) = inventory {
            self.inventory = Some(inventory.clone());
            if !inventory_is_stale(&inventory) {
                return Ok(Some(inventory));
            }
            let context = vec![
                format!("Last scan: {}", format_date(inventory.captured_at)),
                format!("Detected: {} components", inventory.graph.components.len()),
                "This scan is over 24 hours old. Rescan is recommended.".to_owned(),
            ];
            match self.select_menu_with_context(
                "Refresh inventory?",
                &context,
                &["Rescan this PC - recommended", "Use the existing scan"],
            )? {
                MenuChoice::Selected(0) => {}
                MenuChoice::Selected(1) => return Ok(Some(inventory)),
                _ => return Ok(None),
            }
        }
        self.scan_current().await.map(Some)
    }

    async fn scan_current(&mut self) -> Result<Inventory, Box<ErrorEnvelope>> {
        self.clear()?;
        self.line("Scanning this PC...")?;
        self.line("Progress is grouped here; detailed warnings stay hidden until requested.")?;
        let run_id = ApplicationService::allocate_run_id()?;
        let cancellation = CancellationToken::new();
        let future = self
            .service
            .scan(run_id, &cancellation, progress_to_terminal);
        tokio::pin!(future);
        let result = tokio::select! {
            result = &mut future => result,
            cancel_result = wait_for_cancel_request() => {
                cancellation.cancel();
                let _ = future.await;
                cancel_result?;
                Err(cancelled_error())
            }
        }?;
        self.inventory = Some(result.clone());
        Ok(result)
    }

    fn secret_component_count(&self, inventory: Option<&Inventory>) -> usize {
        inventory
            .map(|inventory| {
                inventory
                    .graph
                    .components
                    .iter()
                    .filter(|component| {
                        component.selection.sensitive
                            || component.kind == ComponentKind::SecretReference
                    })
                    .count()
            })
            .unwrap_or(0)
    }

    fn show_result(
        &mut self,
        result: Result<CommandResult, Box<ErrorEnvelope>>,
    ) -> Result<(), Box<ErrorEnvelope>> {
        match result {
            Ok(result) => {
                if !result.human.is_empty() {
                    self.raw(&result.human)?;
                }
            }
            Err(error) => self.show_error(&error)?,
        }
        Ok(())
    }

    fn show_error(&mut self, error: &ErrorEnvelope) -> Result<(), Box<ErrorEnvelope>> {
        let explanation = match error.code {
            reforge_domain::ReforgeErrorCode::InsufficientDisk => {
                "There is not enough free space. Choose another backup directory or free space, then retry."
            }
            reforge_domain::ReforgeErrorCode::PackageCorrupt => {
                "This backup is damaged or incomplete. Select another copy; nothing has been restored."
            }
            reforge_domain::ReforgeErrorCode::PathNotFound
            | reforge_domain::ReforgeErrorCode::InvalidPath => {
                "The location is unavailable. Check the drive and folder, or choose another location."
            }
            reforge_domain::ReforgeErrorCode::SecurityPolicy => {
                "Reforge stopped this operation to protect your data. Review the safety details before continuing."
            }
            reforge_domain::ReforgeErrorCode::ProviderParseFailed => {
                "A discovery provider returned unreadable data. The rest of the scan may still be usable."
            }
            _ => "Reforge could not finish this operation. You can return safely and try again.",
        };
        loop {
            self.clear()?;
            self.line("Operation could not be completed")?;
            self.line(explanation)?;
            self.line(&clean_text(&error.message, 500))?;
            self.line("[Enter] Continue   [D] Technical details")?;
            match read_key()? {
                KeyCode::Enter | KeyCode::Esc | KeyCode::Backspace => return Ok(()),
                KeyCode::Char('d') | KeyCode::Char('D') => {
                    let safe = super::safe_json(error)?;
                    let text = serde_json::to_string_pretty(&safe)
                        .map_err(|error| io_error(error, "Format diagnostic"))?;
                    self.show_lines(
                        "Technical details (redacted)",
                        &text.lines().map(str::to_owned).collect::<Vec<_>>(),
                    )?;
                }
                _ => {}
            }
        }
    }

    fn prompt_path(&mut self, prompt: &str) -> Result<Option<PathBuf>, Box<ErrorEnvelope>> {
        let mut value = String::new();
        loop {
            self.clear()?;
            self.line(prompt)?;
            self.line("[Enter] Use path   [Esc] Cancel   [Backspace] Delete")?;
            self.line("")?;
            let width = terminal::size()
                .map_or(80, |size| usize::from(size.0))
                .saturating_sub(4);
            let visible = value
                .chars()
                .rev()
                .take(width)
                .collect::<String>()
                .chars()
                .rev()
                .collect::<String>();
            self.line(&format!("> {visible}_"))?;
            match read_key()? {
                KeyCode::Enter => {
                    let path = value.trim().trim_matches('"');
                    return Ok((!path.is_empty()).then(|| PathBuf::from(path)));
                }
                KeyCode::Esc => return Ok(None),
                KeyCode::Backspace => {
                    value.pop();
                }
                KeyCode::Char(character) if !character.is_control() && value.len() < 32_000 => {
                    value.push(character)
                }
                _ => {}
            }
        }
    }

    fn show_lines(&mut self, title: &str, lines: &[String]) -> Result<(), Box<ErrorEnvelope>> {
        self.view_lines(title, lines, "[Enter/Esc] Back", None)
            .map(|_| ())
    }

    fn view_lines(
        &mut self,
        title: &str,
        lines: &[String],
        footer: &str,
        action: Option<KeyCode>,
    ) -> Result<KeyCode, Box<ErrorEnvelope>> {
        let mut offset = 0usize;
        let mut wrapped = Vec::new();
        let mut wrapped_width = 0;
        loop {
            let (width, height) = terminal::size().unwrap_or((80, 25));
            let width = usize::from(width).saturating_sub(2).max(1);
            let page = usize::from(height).saturating_sub(6).max(1);
            if wrapped_width != width {
                wrapped.clear();
                wrapped_width = width;
                for text in lines {
                    let safe = reforge_domain::RedactionPolicy::default()
                        .redact_interactive_text(text)
                        .unwrap_or_else(|| "<redacted>".to_owned());
                    let chars = safe
                        .chars()
                        .filter(|character| !character.is_control())
                        .collect::<Vec<_>>();
                    if chars.is_empty() {
                        wrapped.push(String::new());
                    }
                    for chunk in chars.chunks(width) {
                        wrapped.push(chunk.iter().collect::<String>());
                    }
                }
            }
            offset = offset.min(wrapped.len().saturating_sub(page));
            self.clear()?;
            self.line(title)?;
            self.line("")?;
            for line in wrapped.iter().skip(offset).take(page) {
                self.line(line)?;
            }
            self.line("")?;
            self.line(&format!(
                "{}-{} / {}   Up/Down PgUp/PgDn",
                usize::from(!wrapped.is_empty()) + offset,
                (offset + page).min(wrapped.len()),
                wrapped.len()
            ))?;
            self.line(footer)?;
            match read_key()? {
                KeyCode::Up => offset = offset.saturating_sub(1),
                KeyCode::Down => offset = offset.saturating_add(1),
                KeyCode::PageUp => offset = offset.saturating_sub(page),
                KeyCode::PageDown => offset = offset.saturating_add(page),
                KeyCode::Home => offset = 0,
                KeyCode::End => offset = wrapped.len(),
                key @ (KeyCode::Enter | KeyCode::Esc | KeyCode::Backspace) => return Ok(key),
                key if action == Some(key) => return Ok(key),
                _ => {}
            }
        }
    }

    fn clear(&mut self) -> Result<(), Box<ErrorEnvelope>> {
        execute!(self.out, Clear(ClearType::All), MoveTo(0, 0))
            .map_err(|error| io_error(error, "Clear terminal"))
    }

    fn line(&mut self, value: &str) -> Result<(), Box<ErrorEnvelope>> {
        let width = terminal::size()
            .map_or(80, |size| usize::from(size.0))
            .saturating_sub(1);
        let safe = reforge_domain::RedactionPolicy::default()
            .redact_interactive_text(value)
            .unwrap_or_else(|| "<redacted>".to_owned());
        let unicode = self.preferences.unicode && std::env::var("TERM").as_deref() != Ok("dumb");
        let safe = if unicode {
            safe.replacen("[OK]", "[\u{2713}]", 1)
        } else {
            safe
        };
        let text = safe
            .chars()
            .filter(|character| !character.is_control())
            .map(|character| {
                if unicode || character.is_ascii() {
                    character
                } else {
                    '?'
                }
            })
            .take(width)
            .collect::<String>();
        write!(self.out, "{text}\r\n").map_err(|error| io_error(error, "Write terminal output"))?;
        self.out
            .flush()
            .map_err(|error| io_error(error, "Flush terminal output"))
    }

    fn raw(&mut self, value: &str) -> Result<(), Box<ErrorEnvelope>> {
        for line in value.lines() {
            self.line(line)?;
        }
        Ok(())
    }
}

fn backup_record_label(
    records: &BTreeMap<PathBuf, super::interactive::BackupHistoryRecord>,
    path: &Path,
    modified: DateTime<Utc>,
) -> String {
    match records
        .get(path)
        .filter(|record| DateTime::<Utc>::from(record.modified) == modified)
    {
        Some(record) => format!(
            "{} / {} components / {}",
            record.preset.label(),
            record.components,
            format_bytes(record.bytes)
        ),
        None => "Component count and trust are checked when this backup is opened.".to_owned(),
    }
}

fn visible_range(cursor: usize, count: usize, reserved_rows: usize) -> (usize, usize) {
    let rows = terminal::size()
        .map_or(25, |size| usize::from(size.1))
        .saturating_sub(reserved_rows)
        .max(1);
    let start = cursor
        .saturating_sub(rows / 2)
        .min(count.saturating_sub(rows));
    (start, (start + rows).min(count))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MenuChoice {
    Selected(usize),
    Back,
    Exit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MenuInput {
    Cursor(usize),
    Choice(MenuChoice),
    Unhandled,
}

fn menu_input(key: KeyCode, cursor: usize, item_count: usize) -> MenuInput {
    match key {
        KeyCode::Up => MenuInput::Cursor(cursor.saturating_sub(1)),
        KeyCode::Down if item_count > 0 => MenuInput::Cursor((cursor + 1).min(item_count - 1)),
        KeyCode::Enter if item_count > 0 => {
            MenuInput::Choice(MenuChoice::Selected(cursor.min(item_count - 1)))
        }
        KeyCode::Esc | KeyCode::Backspace => MenuInput::Choice(MenuChoice::Back),
        KeyCode::Char('0') => MenuInput::Choice(MenuChoice::Exit),
        KeyCode::Char(character) if character.is_ascii_digit() => {
            let index = character.to_digit(10).unwrap_or(0) as usize;
            if (1..=item_count).contains(&index) {
                MenuInput::Choice(MenuChoice::Selected(index - 1))
            } else {
                MenuInput::Unhandled
            }
        }
        _ => MenuInput::Unhandled,
    }
}

fn badges(component: &Component) -> Vec<String> {
    let mut result = Vec::new();
    if (component.selection.recommended || component.selection.selected_by_default)
        && component_is_safe_for_default(component)
    {
        result.push("RECOMMENDED".to_owned());
    }
    match component.restore.portability {
        Portability::Portable | Portability::SupportedExport | Portability::SyncRestorable => {
            result.push("PORTABLE".to_owned())
        }
        Portability::PartiallyPortable => result.push("PARTIAL".to_owned()),
        Portability::ApplicationBound
        | Portability::UserBound
        | Portability::MachineBound
        | Portability::Unsupported
        | Portability::Unknown => {}
        Portability::ReauthRequired => result.push("REAUTH REQUIRED".to_owned()),
    }
    if matches!(
        &component.restore.primary,
        RestoreStrategy::Partial | RestoreStrategy::Manual
    ) {
        result.push("MANUAL".to_owned());
    }
    if component.selection.sensitive || component_has_secret_artifact(component) {
        result.push("SENSITIVE".to_owned());
    }
    if component_has_large_data(component) {
        result.push("LARGE DATA".to_owned());
    }
    if matches!(&component.confidence, Confidence::Low | Confidence::Unknown)
        || component_is_catalog_only(component)
        || component_is_unknown_binary(component)
    {
        result.push("UNVERIFIED".to_owned());
    }
    if component.restore.requires_user_action
        || component.restore.requires_elevation
        || !component_is_safe_for_default(component)
    {
        result.push("WARNING".to_owned());
    }
    if result.is_empty() {
        result.push("SAFE".to_owned());
    }
    result
}

fn category_counts(
    components: &[Component],
    selected: &[ComponentId],
) -> BTreeMap<&'static str, usize> {
    let selected = selected.iter().collect::<BTreeSet<_>>();
    let mut counts = BTreeMap::new();
    for component in components {
        if !selected.contains(&component.id) {
            continue;
        }
        let label = match component_category(component) {
            CategoryKind::Programs => "Programs",
            CategoryKind::DeveloperTools => "Developer tools",
            CategoryKind::AiHarnesses => "AI harnesses",
            CategoryKind::McpServers => "MCP servers",
            CategoryKind::Configurations => "Configurations",
            CategoryKind::Runtimes => "Language runtimes",
            CategoryKind::Packages => "Package manager packages",
            CategoryKind::Docker => "Docker",
            CategoryKind::Wsl => "WSL",
            CategoryKind::Windows => "Windows components",
            CategoryKind::Other => "Advanced / Manual",
        };
        *counts.entry(label).or_default() += 1;
    }
    counts
}

fn package_files(directory: &Path) -> Result<Vec<(PathBuf, DateTime<Utc>)>, Box<ErrorEnvelope>> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(io_error(error, "Read backup directory")),
    };
    let mut packages = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| io_error(error, "Read backup directory entry"))?;
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("reforge") {
            continue;
        }
        let metadata = entry
            .metadata()
            .map_err(|error| io_error(error, "Inspect backup file"))?;
        if !metadata.is_file() {
            continue;
        }
        let modified = metadata
            .modified()
            .ok()
            .map(DateTime::<Utc>::from)
            .unwrap_or_else(Utc::now);
        packages.push((path, modified));
    }
    Ok(packages)
}

fn unique_backup_path(mut path: PathBuf) -> Result<PathBuf, Box<ErrorEnvelope>> {
    if !path.exists() {
        return Ok(path);
    }
    let stem = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("Reforge-backup")
        .to_owned();
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or("reforge")
        .to_owned();
    for index in 1..=1000 {
        path.set_file_name(format!("{stem}-{index}.{extension}"));
        if !path.exists() {
            return Ok(path);
        }
    }
    Err(boxed_error(
        reforge_domain::ReforgeErrorCode::OperationFailed,
        "Could not allocate a unique backup filename",
    ))
}

fn inventory_is_stale(inventory: &Inventory) -> bool {
    Utc::now()
        .signed_duration_since(inventory.captured_at)
        .gt(&STALE_AFTER)
}

fn warning_group(warning: &str) -> String {
    let warning = warning.to_ascii_lowercase();
    if warning.contains("registry") || warning.contains("registration") {
        "Windows registration".to_owned()
    } else if warning.contains("docker") {
        "Docker".to_owned()
    } else if warning.contains("wsl") {
        "WSL".to_owned()
    } else if warning.contains("codex") {
        "Codex".to_owned()
    } else if warning.contains("claude") {
        "Claude Code".to_owned()
    } else if warning.contains("opencode") {
        "OpenCode".to_owned()
    } else if warning.contains("winget") {
        "WinGet".to_owned()
    } else if warning.contains("python") {
        "Python".to_owned()
    } else if warning.contains("access") || warning.contains("failed") || warning.contains("error")
    {
        "Important".to_owned()
    } else {
        "Other observations".to_owned()
    }
}

fn warning_severity(warning: &str) -> &'static str {
    let warning = warning.to_ascii_lowercase();
    if warning.contains("secret")
        || warning.contains("credential")
        || warning.contains("access denied")
        || warning.contains("failed")
        || warning.contains("error")
    {
        "HIGH"
    } else if warning.contains("docker") || warning.contains("wsl") || warning.contains("manual") {
        "MEDIUM"
    } else if warning.contains("registry") || warning.contains("registration") {
        "LOW"
    } else {
        "INFO"
    }
}

fn progress_to_terminal(event: ProgressEvent) {
    let current = if event.current_component.is_some() {
        "component"
    } else {
        "phase"
    };
    let mut out = io::stdout().lock();
    let _ = write!(
        out,
        "  {} {:?} {}/{} {}\r\n",
        current,
        event.status,
        event.completed,
        event
            .total
            .map_or_else(|| "?".to_owned(), |total| total.to_string()),
        RedactionSafe::new(&event.message)
    );
    let _ = out.flush();
}

fn component_name_map(
    graph: Option<&reforge_domain::PackageGraph>,
) -> BTreeMap<ComponentId, String> {
    graph
        .into_iter()
        .flat_map(|graph| &graph.components)
        .map(|component| {
            (
                component.id.clone(),
                clean_text(&component.display_name, 80),
            )
        })
        .collect()
}

fn restore_progress_to_terminal(
    names: &BTreeMap<ComponentId, String>,
    operation: &Operation,
    state: OperationState,
    completed: u64,
    total: u64,
) {
    let marker = match state {
        OperationState::Running => "->",
        OperationState::Completed | OperationState::Skipped => "OK",
        OperationState::WaitingForUser | OperationState::WaitingForReboot => "WARN",
        OperationState::Failed => "FAIL",
        OperationState::Cancelled => "STOP",
        OperationState::Interrupted => "WARN",
        OperationState::Pending => " ",
    };
    let name = names
        .get(&operation.component)
        .map(String::as_str)
        .unwrap_or("Component");
    let mut out = io::stdout().lock();
    let _ = write!(
        out,
        "[{marker}] {name} ({completed}/{total} operations)\r\n"
    );
    let _ = out.flush();
}

async fn wait_for_cancel_request() -> Result<(), Box<ErrorEnvelope>> {
    loop {
        tokio::select! {
            signal = tokio::signal::ctrl_c() => {
                return signal.map_err(|error| io_error(error, "Listen for Ctrl+C"));
            }
            _ = tokio::time::sleep(Duration::from_millis(50)) => {
                while event::poll(Duration::ZERO)
                    .map_err(|error| io_error(error, "Poll terminal input"))?
                {
                    match event::read().map_err(|error| io_error(error, "Read terminal input"))? {
                        Event::Key(KeyEvent { code, modifiers, kind, .. })
                            if kind != KeyEventKind::Release
                                && is_cancel_key(code, modifiers) => return Ok(()),
                        _ => {}
                    }
                }
            }
        }
    }
}

fn is_cancel_key(code: KeyCode, modifiers: KeyModifiers) -> bool {
    code == KeyCode::Char('\u{3}')
        || (modifiers.contains(KeyModifiers::CONTROL)
            && matches!(code, KeyCode::Char(character) if reforge_platform_windows::is_physical_c_key(character)))
}

fn read_key() -> Result<KeyCode, Box<ErrorEnvelope>> {
    loop {
        match event::read().map_err(|error| io_error(error, "Read terminal input"))? {
            Event::Key(KeyEvent {
                code,
                modifiers,
                kind,
                ..
            }) if kind != KeyEventKind::Release => {
                if is_cancel_key(code, modifiers) {
                    return Err(cancelled_error());
                }
                return Ok(code);
            }
            Event::Resize(_, _) => return Ok(KeyCode::Null),
            _ => {}
        }
    }
}

async fn run_line_mode() -> Result<CommandResult, Box<ErrorEnvelope>> {
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let stdout = io::stdout();
    let mut output = stdout.lock();
    writeln!(output, "REFORGE\nBackup & Restore your Windows setup\n")
        .map_err(|error| io_error(error, "Write interactive menu"))?;
    writeln!(output, "[1] Quick Backup")
        .and_then(|_| writeln!(output, "[2] Custom Backup"))
        .and_then(|_| writeln!(output, "[3] Restore Backup"))
        .and_then(|_| writeln!(output, "[4] Browse Detected Components"))
        .and_then(|_| writeln!(output, "[5] Scan This PC"))
        .and_then(|_| writeln!(output, "[6] Backup History"))
        .and_then(|_| writeln!(output, "[7] Advanced"))
        .and_then(|_| writeln!(output, "[8] Settings"))
        .and_then(|_| writeln!(output, "[0] Exit"))
        .and_then(|_| write!(output, "Choose an option: "))
        .map_err(|error| io_error(error, "Write interactive menu"))?;
    output
        .flush()
        .map_err(|error| io_error(error, "Flush interactive menu"))?;
    let mut line = String::new();
    let read = input
        .read_line(&mut line)
        .map_err(|error| io_error(error, "Read interactive choice"))?;
    if read == 0 || line.trim().is_empty() || line.trim() == "0" {
        writeln!(output, "Exit.").map_err(|error| io_error(error, "Write interactive result"))?;
    } else {
        writeln!(
            output,
            "Interactive keyboard mode requires a terminal; use `reforge` in Windows Terminal."
        )
        .map_err(|error| io_error(error, "Write interactive result"))?;
    }
    Ok(CommandResult {
        payload: json!({"status": "exited", "interface": "line-fallback"}),
        human: String::new(),
        exit_code: 0,
    })
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut value = bytes as f64;
    let mut unit = 0usize;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", bytes, UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn format_date(value: DateTime<Utc>) -> String {
    value.format("%d %b %Y %H:%M").to_string()
}

fn clean_text(value: &str, max_chars: usize) -> String {
    let safe = reforge_domain::RedactionPolicy::default()
        .redact_text(value)
        .unwrap_or_else(|| "<redacted>".to_owned());
    let mut output = safe
        .chars()
        .filter(|character| !character.is_control())
        .take(max_chars)
        .collect::<String>();
    if output.is_empty() {
        output.push_str("(unnamed)");
    }
    output
}

fn yes_no(value: bool) -> &'static str {
    if value { "Yes" } else { "No" }
}

struct RedactionSafe(String);

impl RedactionSafe {
    fn new(value: &str) -> Self {
        let safe = reforge_domain::RedactionPolicy::default()
            .redact_text(value)
            .unwrap_or_else(|| "<redacted diagnostic>".to_owned());
        Self(safe)
    }
}

impl std::fmt::Display for RedactionSafe {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&clean_text(&self.0, 180))
    }
}

fn io_error(error: impl std::fmt::Display, context: &str) -> Box<ErrorEnvelope> {
    Box::new(
        ErrorEnvelope::new(reforge_domain::ReforgeErrorCode::OperationFailed, context)
            .with_technical_detail(error.to_string()),
    )
}

fn cancelled_error() -> Box<ErrorEnvelope> {
    boxed_error(
        reforge_domain::ReforgeErrorCode::Cancelled,
        "Operation cancelled safely; no further changes will be started",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn badges_expose_safety_metadata_without_ids() {
        let component = test_component();
        let labels = badges(&component);
        assert!(!labels.contains(&"RECOMMENDED".to_owned()));
        assert!(labels.contains(&"PORTABLE".to_owned()));
        assert!(labels.contains(&"SENSITIVE".to_owned()));
        assert!(labels.contains(&"WARNING".to_owned()));
    }

    #[test]
    fn warning_groups_are_human_readable() {
        assert_eq!(
            warning_group("registry registration missing"),
            "Windows registration"
        );
        assert_eq!(warning_severity("credential access denied"), "HIGH");
    }

    #[test]
    fn menu_navigation_is_bounded_and_keyboard_addressable() {
        assert_eq!(menu_input(KeyCode::Up, 0, 4), MenuInput::Cursor(0));
        assert_eq!(menu_input(KeyCode::Down, 3, 4), MenuInput::Cursor(3));
        assert_eq!(
            menu_input(KeyCode::Char('3'), 0, 4),
            MenuInput::Choice(MenuChoice::Selected(2))
        );
        assert_eq!(
            menu_input(KeyCode::Enter, 2, 4),
            MenuInput::Choice(MenuChoice::Selected(2))
        );
        assert_eq!(
            menu_input(KeyCode::Backspace, 2, 4),
            MenuInput::Choice(MenuChoice::Back)
        );
        assert_eq!(
            menu_input(KeyCode::Char('0'), 2, 4),
            MenuInput::Choice(MenuChoice::Exit)
        );
    }

    #[test]
    fn control_c_and_conpty_etx_cancel_but_plain_c_does_not() {
        assert!(is_cancel_key(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert!(is_cancel_key(KeyCode::Char('C'), KeyModifiers::CONTROL));
        assert!(is_cancel_key(KeyCode::Char('\u{3}'), KeyModifiers::NONE));
        assert!(!is_cancel_key(KeyCode::Char('c'), KeyModifiers::NONE));
        assert!(!is_cancel_key(KeyCode::Char('C'), KeyModifiers::SHIFT));
    }

    #[test]
    fn unsafe_components_cannot_enter_default_selection() {
        let sensitive = test_component();
        assert!(!component_is_safe_for_default(&sensitive));

        let mut portable = sensitive.clone();
        portable.selection.sensitive = false;
        let mut catalog = test_component();
        catalog.selection.sensitive = false;
        catalog
            .extensions
            .insert("catalog_only".to_owned(), json!(true));
        assert!(component_is_catalog_only(&catalog));
        assert!(!component_is_safe_for_default(&catalog));
        assert!(badges(&catalog).contains(&"UNVERIFIED".to_owned()));
        assert!(component_is_safely_portable(&portable));
        portable.restore.portability = Portability::MachineBound;
        assert!(!component_is_safely_portable(&portable));

        let mut large = portable;
        large.restore.portability = Portability::Portable;
        large.selection.size_bytes = LARGE_ARTIFACT_THRESHOLD + 1;
        assert!(component_has_large_data(&large));
        assert!(!component_is_safe_for_default(&large));
        assert!(badges(&large).contains(&"LARGE DATA".to_owned()));

        let mut binary = sensitive;
        binary.selection.sensitive = false;
        binary.kind = ComponentKind::PortableBinary;
        binary.restore.primary = RestoreStrategy::PortableBinary;
        assert!(component_is_unknown_binary(&binary));
        assert!(!component_is_safe_for_default(&binary));
    }

    #[test]
    fn presets_use_metadata_without_including_sensitive_or_executable_hooks() {
        let mut core = test_component();
        core.selection.sensitive = false;
        let mut runtime = core.clone();
        runtime.id = ComponentId::new(format!("cmp_{}", "b".repeat(52))).unwrap();
        runtime.kind = ComponentKind::Runtime;
        runtime.selection.recommended = false;
        let mut secret = test_component();
        secret.id = ComponentId::new(format!("cmp_{}", "c".repeat(52))).unwrap();
        let mut hook = core.clone();
        hook.id = ComponentId::new(format!("cmp_{}", "d".repeat(52))).unwrap();
        hook.kind = ComponentKind::Hook;
        let graph = reforge_domain::PackageGraph {
            components: vec![core.clone(), runtime.clone(), secret.clone(), hook.clone()],
            edges: Vec::new(),
        };
        for preset in BackupPreset::ALL {
            let selection = preset_selection(&graph, preset);
            assert!(!selection.components.contains(&secret.id));
            assert!(!selection.components.contains(&hook.id));
            if preset == BackupPreset::Custom {
                assert!(selection.components.is_empty());
            } else {
                assert!(selection.components.contains(&core.id));
                assert_eq!(
                    selection.components.contains(&runtime.id),
                    matches!(
                        preset,
                        BackupPreset::Recommended
                            | BackupPreset::Developer
                            | BackupPreset::AiDevelopment
                            | BackupPreset::AiWorkstation
                            | BackupPreset::FullSafe
                    )
                );
            }
            assert_eq!(
                selection.policy.secrets,
                reforge_domain::SecretSelectionPolicy::Exclude
            );
            assert_eq!(
                selection.policy.large_data,
                reforge_domain::LargeDataSelectionPolicy::Exclude
            );
            assert_eq!(
                selection.policy.unknown_binaries,
                reforge_domain::UnknownBinarySelectionPolicy::Exclude
            );
        }
    }

    fn test_component() -> Component {
        serde_json::from_value(json!({
            "id": format!("cmp_{}", "a".repeat(52)),
            "kind": "CONFIGURATION",
            "identity": {
                "provider_package": null,
                "provider_source": null,
                "package_family": null,
                "product_name": "test",
                "executable_name": null,
                "publisher": null,
                "executable_hash": null,
                "install_role": null,
                "identity_quality": "LOCAL"
            },
            "display_name": "Test",
            "version": null,
            "architecture": null,
            "publisher": null,
            "provenance": null,
            "evidence": [],
            "confidence": "HIGH",
            "dependencies": [],
            "artifacts": [],
            "restore": {
                "primary": "CONFIG_PORTABLE",
                "alternatives": [],
                "portability": "PORTABLE",
                "requires_elevation": false,
                "requires_user_action": false,
                "rationale": []
            },
            "compatibility": {
                "required_os": null,
                "required_architecture": null,
                "requires_provider": null,
                "requires_runtime": null,
                "requires_elevation": false,
                "requires_wsl": false,
                "requires_docker": false
            },
            "verification": [],
            "selection": {
                "recommended": true,
                "score": 50,
                "selected_by_default": false,
                "sensitive": true,
                "size_bytes": 0
            }
        }))
        .expect("component fixture")
    }
}
