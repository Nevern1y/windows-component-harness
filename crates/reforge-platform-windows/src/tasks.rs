//! Read-only Windows Task Scheduler observations.
//!
//! Task definitions are inspected only for bounded metadata. XML, action
//! command lines, credentials, and security descriptors never cross this
//! boundary, and no task is created, started, stopped, or modified.

use std::convert::TryFrom;

use reforge_domain::{ErrorEnvelope, ReforgeErrorCode};
use windows::{
    Win32::{
        Foundation::{RPC_E_CHANGED_MODE, S_FALSE, S_OK},
        System::{
            Com::{
                CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
                CoUninitialize,
            },
            TaskScheduler::{
                IActionCollection, IRegisteredTask, ITaskFolder, ITaskService, TASK_STATE_DISABLED,
                TASK_STATE_QUEUED, TASK_STATE_READY, TASK_STATE_RUNNING, TASK_STATE_UNKNOWN,
                TaskScheduler as CLSID_TASK_SCHEDULER,
            },
            Variant::{VARIANT, VT_I4},
        },
    },
    core::{BSTR, Error as WindowsError},
};

const MAX_TASKS: usize = 100_000;
const MAX_FOLDERS: usize = 20_000;
const MAX_TASK_DEPTH: usize = 32;
const MAX_TASK_TEXT_CHARS: usize = 32 * 1024;

/// State reported by the Task Scheduler service.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ScheduledTaskState {
    Unknown,
    Disabled,
    Queued,
    Ready,
    Running,
}

/// Bounded, non-executable metadata for one registered task.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScheduledTaskObservation {
    pub name: String,
    pub path: String,
    pub state: ScheduledTaskState,
    pub enabled: Option<bool>,
    pub action_count: Option<u32>,
}

/// Task Scheduler operation associated with an access failure.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum TaskOperation {
    InitializeCom,
    CreateService,
    Connect,
    GetFolder,
    EnumerateFolders,
    EnumerateTasks,
    ReadTask,
    ReadDefinition,
}

/// A non-fatal Task Scheduler failure without command or credential data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskAccessError {
    pub path: Option<String>,
    pub operation: TaskOperation,
    pub hresult: u32,
    pub error: ErrorEnvelope,
}

/// Complete bounded Task Scheduler enumeration result.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TaskSnapshot {
    pub observations: Vec<ScheduledTaskObservation>,
    pub errors: Vec<TaskAccessError>,
}

/// Enumerate the local Task Scheduler hierarchy through its COM API.
pub fn enumerate_scheduled_tasks() -> TaskSnapshot {
    let mut snapshot = TaskSnapshot::default();
    let apartment = match ComApartment::initialize() {
        Ok(apartment) => apartment,
        Err(error) => {
            snapshot.errors.push(TaskAccessError {
                path: None,
                operation: TaskOperation::InitializeCom,
                hresult: 0,
                error: *error,
            });
            return snapshot;
        }
    };

    let service: ITaskService =
        match unsafe { CoCreateInstance(&CLSID_TASK_SCHEDULER, None, CLSCTX_INPROC_SERVER) } {
            Ok(service) => service,
            Err(error) => {
                snapshot.errors.push(TaskAccessError {
                    path: None,
                    operation: TaskOperation::CreateService,
                    hresult: error_code(&error),
                    error: *com_error("create Task Scheduler service", &error),
                });
                drop(apartment);
                return snapshot;
            }
        };

    let empty_server = VARIANT::default();
    let empty_user = VARIANT::default();
    let empty_domain = VARIANT::default();
    let empty_password = VARIANT::default();
    if let Err(error) =
        unsafe { service.Connect(&empty_server, &empty_user, &empty_domain, &empty_password) }
    {
        snapshot.errors.push(TaskAccessError {
            path: None,
            operation: TaskOperation::Connect,
            hresult: error_code(&error),
            error: *com_error("connect to Task Scheduler", &error),
        });
        drop(service);
        drop(apartment);
        return snapshot;
    }

    let root_path = BSTR::from("\\");
    let root = match unsafe { service.GetFolder(&root_path) } {
        Ok(root) => root,
        Err(error) => {
            snapshot.errors.push(TaskAccessError {
                path: Some("\\".to_owned()),
                operation: TaskOperation::GetFolder,
                hresult: error_code(&error),
                error: *com_error("open Task Scheduler root", &error),
            });
            drop(service);
            drop(apartment);
            return snapshot;
        }
    };

    enumerate_folder(&root, &mut snapshot, 0);
    drop(root);
    drop(service);
    drop(apartment);

    snapshot
        .observations
        .sort_by(|left, right| left.path.cmp(&right.path));
    snapshot.errors.sort_by(|left, right| {
        (&left.path, left.operation, left.hresult).cmp(&(
            &right.path,
            right.operation,
            right.hresult,
        ))
    });
    snapshot
}

fn enumerate_folder(folder: &ITaskFolder, snapshot: &mut TaskSnapshot, depth: usize) {
    if depth > MAX_TASK_DEPTH {
        snapshot.errors.push(TaskAccessError {
            path: None,
            operation: TaskOperation::EnumerateFolders,
            hresult: 0,
            error: ErrorEnvelope::new(
                ReforgeErrorCode::SecurityPolicy,
                "The Task Scheduler hierarchy exceeded its reviewed depth",
            ),
        });
        return;
    }

    let folder_path = unsafe { folder.Path() }
        .ok()
        .and_then(bstr_text)
        .unwrap_or_else(|| "\\".to_owned());

    let tasks = match unsafe { folder.GetTasks(0) } {
        Ok(tasks) => tasks,
        Err(error) => {
            snapshot.errors.push(TaskAccessError {
                path: Some(folder_path.clone()),
                operation: TaskOperation::EnumerateTasks,
                hresult: error_code(&error),
                error: *com_error("enumerate Task Scheduler tasks", &error),
            });
            return;
        }
    };
    let task_count = match bounded_count(unsafe { tasks.Count() }, MAX_TASKS) {
        Ok(count) => count,
        Err(error) => {
            snapshot.errors.push(TaskAccessError {
                path: Some(folder_path.clone()),
                operation: TaskOperation::EnumerateTasks,
                hresult: 0,
                error: *error,
            });
            0
        }
    };

    for index in 1..=task_count {
        if snapshot.observations.len() >= MAX_TASKS {
            snapshot.errors.push(TaskAccessError {
                path: Some(folder_path.clone()),
                operation: TaskOperation::EnumerateTasks,
                hresult: 0,
                error: ErrorEnvelope::new(
                    ReforgeErrorCode::SecurityPolicy,
                    "The Task Scheduler enumeration exceeded its reviewed bound",
                ),
            });
            break;
        }
        let item = index_variant(index as i32);
        let task = match unsafe { tasks.get_Item(&item) } {
            Ok(task) => task,
            Err(error) => {
                snapshot.errors.push(TaskAccessError {
                    path: Some(folder_path.clone()),
                    operation: TaskOperation::ReadTask,
                    hresult: error_code(&error),
                    error: *com_error("read Task Scheduler task", &error),
                });
                continue;
            }
        };
        read_task(&task, snapshot, &folder_path);
    }

    let folders = match unsafe { folder.GetFolders(0) } {
        Ok(folders) => folders,
        Err(error) => {
            snapshot.errors.push(TaskAccessError {
                path: Some(folder_path),
                operation: TaskOperation::EnumerateFolders,
                hresult: error_code(&error),
                error: *com_error("enumerate Task Scheduler folders", &error),
            });
            return;
        }
    };
    let folder_count = match bounded_count(unsafe { folders.Count() }, MAX_FOLDERS) {
        Ok(count) => count,
        Err(error) => {
            snapshot.errors.push(TaskAccessError {
                path: Some(folder_path.clone()),
                operation: TaskOperation::EnumerateFolders,
                hresult: 0,
                error: *error,
            });
            0
        }
    };

    for index in 1..=folder_count {
        let item = index_variant(index as i32);
        let child = match unsafe { folders.get_Item(&item) } {
            Ok(child) => child,
            Err(error) => {
                snapshot.errors.push(TaskAccessError {
                    path: Some(folder_path.clone()),
                    operation: TaskOperation::EnumerateFolders,
                    hresult: error_code(&error),
                    error: *com_error("read Task Scheduler folder", &error),
                });
                continue;
            }
        };
        enumerate_folder(&child, snapshot, depth + 1);
    }
}

fn read_task(task: &IRegisteredTask, snapshot: &mut TaskSnapshot, folder_path: &str) {
    let path = match unsafe { task.Path() }.ok().and_then(bstr_text) {
        Some(path) => path,
        None => {
            snapshot.errors.push(TaskAccessError {
                path: Some(folder_path.to_owned()),
                operation: TaskOperation::ReadTask,
                hresult: 0,
                error: ErrorEnvelope::new(
                    ReforgeErrorCode::OperationFailed,
                    "Windows returned invalid Task Scheduler path metadata",
                ),
            });
            return;
        }
    };
    let name = unsafe { task.Name() }
        .ok()
        .and_then(bstr_text)
        .unwrap_or_else(|| path.rsplit('\\').next().unwrap_or(&path).to_owned());
    let state = unsafe { task.State() }
        .map(task_state)
        .unwrap_or(ScheduledTaskState::Unknown);
    let enabled = unsafe { task.Enabled() }.ok().map(|value| value.0 != 0);

    let action_count = match unsafe { task.Definition() } {
        Ok(definition) => match unsafe { definition.Actions() } {
            Ok(actions) => match action_count(&actions) {
                Ok(count) => Some(count),
                Err(error) => {
                    snapshot.errors.push(TaskAccessError {
                        path: Some(path.clone()),
                        operation: TaskOperation::ReadDefinition,
                        hresult: 0,
                        error: *error,
                    });
                    None
                }
            },
            Err(error) => {
                snapshot.errors.push(TaskAccessError {
                    path: Some(path.clone()),
                    operation: TaskOperation::ReadDefinition,
                    hresult: error_code(&error),
                    error: *com_error("read Task Scheduler actions", &error),
                });
                None
            }
        },
        Err(error) => {
            snapshot.errors.push(TaskAccessError {
                path: Some(path.clone()),
                operation: TaskOperation::ReadDefinition,
                hresult: error_code(&error),
                error: *com_error("read Task Scheduler definition", &error),
            });
            None
        }
    };

    snapshot.observations.push(ScheduledTaskObservation {
        name,
        path,
        state,
        enabled,
        action_count,
    });
}

fn action_count(actions: &IActionCollection) -> Result<u32, Box<ErrorEnvelope>> {
    let mut count = 0i32;
    unsafe { actions.Count(&mut count) }
        .map_err(|error| com_error("count Task Scheduler actions", &error))?;
    if count < 0 || count as usize > MAX_TASKS {
        return Err(Box::new(ErrorEnvelope::new(
            ReforgeErrorCode::SecurityPolicy,
            "The Task Scheduler action count exceeds the reviewed bound",
        )));
    }
    Ok(count as u32)
}

fn bounded_count(
    count: windows::core::Result<i32>,
    maximum: usize,
) -> Result<usize, Box<ErrorEnvelope>> {
    let count = count.map_err(|error| com_error("count Task Scheduler collection", &error))?;
    if count < 0 || count as usize > maximum {
        return Err(Box::new(ErrorEnvelope::new(
            ReforgeErrorCode::SecurityPolicy,
            "The Task Scheduler collection exceeds the reviewed bound",
        )));
    }
    Ok(count as usize)
}

fn index_variant(index: i32) -> VARIANT {
    let mut variant = VARIANT::default();
    unsafe {
        let inner = &mut *variant.Anonymous.Anonymous;
        inner.vt = VT_I4;
        inner.Anonymous.lVal = index;
    }
    variant
}

fn bstr_text(value: BSTR) -> Option<String> {
    if value.len() > MAX_TASK_TEXT_CHARS {
        return None;
    }
    let text = String::try_from(&value).ok()?;
    if text.is_empty() || text.chars().any(|character| character.is_control()) {
        return None;
    }
    Some(text)
}

fn task_state(value: windows::Win32::System::TaskScheduler::TASK_STATE) -> ScheduledTaskState {
    match value {
        TASK_STATE_UNKNOWN => ScheduledTaskState::Unknown,
        TASK_STATE_DISABLED => ScheduledTaskState::Disabled,
        TASK_STATE_QUEUED => ScheduledTaskState::Queued,
        TASK_STATE_READY => ScheduledTaskState::Ready,
        TASK_STATE_RUNNING => ScheduledTaskState::Running,
        _ => ScheduledTaskState::Unknown,
    }
}

fn error_code(error: &WindowsError) -> u32 {
    error.code().0 as u32
}

fn com_error(operation: &str, error: &WindowsError) -> Box<ErrorEnvelope> {
    let code = error_code(error);
    let kind = if code & 0xffff == 5 {
        ReforgeErrorCode::AccessDenied
    } else {
        ReforgeErrorCode::OperationFailed
    };
    Box::new(
        ErrorEnvelope::new(kind, format!("{operation} failed"))
            .with_technical_detail(format!("HRESULT=0x{code:08x}")),
    )
}

struct ComApartment {
    uninitialize: bool,
}

impl ComApartment {
    fn initialize() -> Result<Self, Box<ErrorEnvelope>> {
        let result = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        if result == S_OK || result == S_FALSE {
            return Ok(Self { uninitialize: true });
        }
        if result == RPC_E_CHANGED_MODE {
            return Err(Box::new(ErrorEnvelope::new(
                ReforgeErrorCode::AccessDenied,
                "The current thread uses an incompatible COM apartment",
            )));
        }
        Err(Box::new(
            ErrorEnvelope::new(
                ReforgeErrorCode::OperationFailed,
                "Windows COM initialization failed",
            )
            .with_technical_detail(format!("HRESULT=0x{:08x}", result.0 as u32)),
        ))
    }
}

impl Drop for ComApartment {
    fn drop(&mut self) {
        if self.uninitialize {
            unsafe { CoUninitialize() };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_state_mapping_is_fail_closed() {
        assert_eq!(task_state(TASK_STATE_READY), ScheduledTaskState::Ready);
        assert_eq!(
            task_state(windows::Win32::System::TaskScheduler::TASK_STATE(99)),
            ScheduledTaskState::Unknown
        );
    }

    #[test]
    fn index_variant_is_a_literal_integer() {
        let variant = index_variant(7);
        unsafe {
            assert_eq!(variant.Anonymous.Anonymous.vt, VT_I4);
            assert_eq!(variant.Anonymous.Anonymous.Anonymous.lVal, 7);
        }
    }
}
