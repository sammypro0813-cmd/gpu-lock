//! GPU Lock core.
//!
//! Two jobs, both on the iPhone itself:
//!
//! 1. Pairing (iOS 27+): act as the "computer" in device-initiated pairing.
//!    We listen on a TCP port; the Swift side advertises it as a
//!    `_remotepairing-pairable-host._tcp` Bonjour service. The user taps
//!    "Pair with GPU Lock" in Settings > Privacy & Security > Developer Mode
//!    and types the PIN we show. The result is an RPPairing file.
//!
//! 2. Session: through LocalDevVPN's loopback (10.7.0.1) open a remote-pairing
//!    tunnel to our own device, make sure the Developer Disk Image is installed,
//!    then open the Instruments Condition Inducer and keep that connection
//!    alive. A condition (e.g. GPU performance state) stays on only while the
//!    connection is open, so one session thread owns it for the app's life.
//!
//! Everything is exposed as a small blocking C API (see `../GPULock-Bridge.h`).
//! Swift calls it from background queues, never from the main thread.

use std::ffi::{CStr, CString, c_char, c_void};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::path::PathBuf;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use idevice::cryptexd::{self, Cryptex1Assets};
use idevice::dvt::condition_inducer::{ConditionInducerClient, ConditionInducerGroup};
use idevice::dvt::remote_server::RemoteServerClient;
use idevice::remote_pairing::{
    PairableHost, PairableHostInfo, RemotePairingClient, RpPairingFile, RpPairingSocket,
    connect_tls_psk_tunnel_native,
};
use idevice::rsd::RsdHandshake;
use idevice::tcp::adapter::Adapter;
use idevice::tcp::handle::AdapterHandle;
use idevice::{IdeviceError, ReadWrite, RsdService};
use serde::Serialize;
use tokio::sync::{Notify, mpsc, oneshot};
use tokio::task::JoinSet;
use tokio::time::timeout;

/// iOS lists the pairing host as a computer, so present a Mac model.
const HOST_MODEL: &str = "Mac17,7";

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn to_cstring(text: impl Into<String>) -> CString {
    let text: String = text.into();
    CString::new(text.replace('\0', " ")).unwrap_or_default()
}

fn set_error(out: *mut *mut c_char, message: impl Into<String>) {
    if !out.is_null() {
        unsafe { *out = to_cstring(message).into_raw() };
    }
}

fn read_str(p: *const c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(p) }.to_str().ok().map(str::to_string)
}

/// Frees any string returned by this library (results and errors).
///
/// # Safety
/// `s` must be NULL or a string returned by this library, freed only once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gl_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(unsafe { CString::from_raw(s) });
    }
}

// ---------------------------------------------------------------------------
// Logging back to Swift
// ---------------------------------------------------------------------------

pub type GlLogCallback = Option<extern "C" fn(message: *const c_char, context: *mut c_void)>;

#[derive(Clone, Copy)]
struct LogTarget {
    callback: GlLogCallback,
    context: *mut c_void,
}
// The context is only handed back to the callback, which Swift makes thread-safe.
unsafe impl Send for LogTarget {}
unsafe impl Sync for LogTarget {}

static LOG: Mutex<Option<LogTarget>> = Mutex::new(None);

fn log(message: impl Into<String>) {
    let target = LOG.lock().ok().and_then(|t| *t);
    if let Some(LogTarget {
        callback: Some(callback),
        context,
    }) = target
    {
        let text = to_cstring(message);
        callback(text.as_ptr(), context);
    }
}

/// Sets the function that receives progress messages (any thread).
///
/// # Safety
/// `context` must stay valid for as long as the callback is set.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gl_set_log_callback(callback: GlLogCallback, context: *mut c_void) {
    if let Ok(mut slot) = LOG.lock() {
        *slot = Some(LogTarget { callback, context });
    }
}

// ---------------------------------------------------------------------------
// 1. On-device pairing (device-initiated, iOS 27+)
// ---------------------------------------------------------------------------

pub type GlPinCallback = Option<extern "C" fn(pin: *const c_char, context: *mut c_void)>;

#[derive(Clone, Copy)]
struct PinTarget {
    callback: GlPinCallback,
    context: *mut c_void,
}
unsafe impl Send for PinTarget {}
unsafe impl Sync for PinTarget {}

impl PinTarget {
    fn show(&self, pin: &str) {
        if let Some(callback) = self.callback {
            let pin = to_cstring(pin);
            callback(pin.as_ptr(), self.context);
        }
    }
}

pub struct GlPairing {
    port: u16,
    service_name: CString,
    txt: Vec<(CString, CString)>,
    listener: Mutex<Option<TcpListener>>,
    identity: Mutex<Option<(RpPairingFile, PairableHostInfo)>>,
    cancelled: AtomicBool,
    cancel: Notify,
}

/// Creates a pairing session: a fresh host identity and a listening port.
/// Returns NULL on failure with `*error` set.
///
/// # Safety
/// `name` must be a valid C string; `error` NULL or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gl_pairing_new(name: *const c_char, error: *mut *mut c_char) -> *mut GlPairing {
    let Some(name) = read_str(name).filter(|n| !n.is_empty()) else {
        set_error(error, "페어링 이름이 없습니다");
        return ptr::null_mut();
    };

    let listener = match TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)) {
        Ok(l) => l,
        Err(e) => {
            set_error(error, format!("페어링 포트를 열지 못했습니다: {e}"));
            return ptr::null_mut();
        }
    };
    let port = match listener
        .set_nonblocking(true)
        .and_then(|_| listener.local_addr())
    {
        Ok(addr) => addr.port(),
        Err(e) => {
            set_error(error, format!("페어링 포트를 열지 못했습니다: {e}"));
            return ptr::null_mut();
        }
    };

    let pairing_file = RpPairingFile::generate(&name);
    let host_info = PairableHostInfo::generate(&name, HOST_MODEL);
    let identifier = pairing_file.identifier.clone();
    let txt = host_info
        .mdns_txt_records(&identifier)
        .into_iter()
        .map(|(k, v)| (to_cstring(k), to_cstring(v)))
        .collect();

    Box::into_raw(Box::new(GlPairing {
        port,
        service_name: to_cstring(identifier),
        txt,
        listener: Mutex::new(Some(listener)),
        identity: Mutex::new(Some((pairing_file, host_info))),
        cancelled: AtomicBool::new(false),
        cancel: Notify::new(),
    }))
}

/// # Safety
/// `s` must be a live pointer from `gl_pairing_new`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gl_pairing_port(s: *const GlPairing) -> u16 {
    unsafe { &*s }.port
}

/// Bonjour instance name to publish. Owned by the session.
///
/// # Safety
/// `s` must be a live pointer from `gl_pairing_new`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gl_pairing_service_name(s: *const GlPairing) -> *const c_char {
    unsafe { &*s }.service_name.as_ptr()
}

/// # Safety
/// `s` must be a live pointer from `gl_pairing_new`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gl_pairing_txt_count(s: *const GlPairing) -> usize {
    unsafe { &*s }.txt.len()
}

/// # Safety
/// `s` must be a live pointer from `gl_pairing_new`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gl_pairing_txt_key(s: *const GlPairing, i: usize) -> *const c_char {
    unsafe { &*s }.txt.get(i).map_or(ptr::null(), |(k, _)| k.as_ptr())
}

/// # Safety
/// `s` must be a live pointer from `gl_pairing_new`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gl_pairing_txt_value(s: *const GlPairing, i: usize) -> *const c_char {
    unsafe { &*s }.txt.get(i).map_or(ptr::null(), |(_, v)| v.as_ptr())
}

/// Ends a running (or the next) `gl_pairing_accept` with result 2. Any thread.
///
/// # Safety
/// `s` must be a live pointer from `gl_pairing_new`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gl_pairing_cancel(s: *const GlPairing) {
    let s = unsafe { &*s };
    s.cancelled.store(true, Ordering::SeqCst);
    s.cancel.notify_one();
}

/// # Safety
/// `s` must be NULL or from `gl_pairing_new`, and any accept must have returned.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gl_pairing_free(s: *mut GlPairing) {
    if !s.is_null() {
        drop(unsafe { Box::from_raw(s) });
    }
}

enum PairFailure {
    Cancelled,
    Error(String),
}

/// Blocks until the iPhone pairs (0), pairing fails (1, `*error` set) or the
/// session is cancelled (2). `pin_callback` gets the 6-digit code to show.
/// On success the RPPairing file is written to `out_path` and the device's
/// name is put in `*out_device_name` (free with `gl_string_free`).
///
/// # Safety
/// `s` from `gl_pairing_new`; `out_path` a valid C string; out pointers NULL or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gl_pairing_accept(
    s: *const GlPairing,
    pin_callback: GlPinCallback,
    pin_context: *mut c_void,
    out_path: *const c_char,
    out_device_name: *mut *mut c_char,
    error: *mut *mut c_char,
) -> i32 {
    let session = unsafe { &*s };
    let Some(out_path) = read_str(out_path).map(PathBuf::from) else {
        set_error(error, "페어링 파일 경로가 없습니다");
        return 1;
    };
    let listener = session.listener.lock().ok().and_then(|mut l| l.take());
    let identity = session.identity.lock().ok().and_then(|mut i| i.take());
    let (Some(listener), Some((file, info))) = (listener, identity) else {
        set_error(error, "이미 사용한 페어링 세션입니다");
        return 1;
    };

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            set_error(error, format!("페어링을 시작하지 못했습니다: {e}"));
            return 1;
        }
    };
    let pin = PinTarget {
        callback: pin_callback,
        context: pin_context,
    };

    match runtime.block_on(wait_for_pairing(session, listener, file, info, pin)) {
        Ok((file, device_name)) => {
            if let Some(parent) = out_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Err(e) = std::fs::write(&out_path, file.to_bytes()) {
                set_error(error, format!("페어링은 됐지만 파일 저장에 실패했습니다: {e}"));
                return 1;
            }
            if !out_device_name.is_null() {
                unsafe { *out_device_name = to_cstring(device_name).into_raw() };
            }
            0
        }
        Err(PairFailure::Cancelled) => 2,
        Err(PairFailure::Error(message)) => {
            set_error(error, message);
            1
        }
    }
}

async fn pair_one_connection(
    stream: tokio::net::TcpStream,
    mut file: RpPairingFile,
    info: PairableHostInfo,
    pin: PinTarget,
    pin_shown: Arc<AtomicBool>,
) -> Result<(RpPairingFile, String), IdeviceError> {
    let mut host = PairableHost::new(RpPairingSocket::new_device(stream), info);
    let peer = host
        .accept(&mut file, move |code: String| {
            pin_shown.store(true, Ordering::SeqCst);
            pin.show(&code);
            async {}
        })
        .await?;
    Ok((file, peer.name))
}

async fn wait_for_pairing(
    session: &GlPairing,
    listener: TcpListener,
    file: RpPairingFile,
    info: PairableHostInfo,
    pin: PinTarget,
) -> Result<(RpPairingFile, String), PairFailure> {
    if session.cancelled.load(Ordering::SeqCst) {
        return Err(PairFailure::Cancelled);
    }
    let listener = tokio::net::TcpListener::from_std(listener)
        .map_err(|e| PairFailure::Error(format!("아이폰 연결을 기다리지 못했습니다: {e}")))?;
    let pin_shown = Arc::new(AtomicBool::new(false));
    let mut attempts = JoinSet::new();
    let deadline = tokio::time::sleep(Duration::from_secs(15 * 60));
    tokio::pin!(deadline);

    loop {
        tokio::select! {
            _ = session.cancel.notified() => return Err(PairFailure::Cancelled),
            _ = &mut deadline => {
                return Err(PairFailure::Error("15분 안에 페어링이 끝나지 않았습니다".into()));
            }
            accepted = listener.accept() => {
                let (stream, _) = accepted
                    .map_err(|e| PairFailure::Error(format!("아이폰 연결을 받지 못했습니다: {e}")))?;
                attempts.spawn(pair_one_connection(
                    stream,
                    file.clone(),
                    info.clone(),
                    pin,
                    pin_shown.clone(),
                ));
            }
            Some(done) = attempts.join_next(), if !attempts.is_empty() => match done {
                Ok(Ok(paired)) => return Ok(paired),
                // A connection that failed before the PIN step was not the
                // iPhone's pairing attempt (or it backed out); keep waiting.
                _ if !pin_shown.load(Ordering::SeqCst) => continue,
                Ok(Err(e)) => return Err(PairFailure::Error(format!("페어링 실패 (PIN이 틀렸을 수 있음): {e}"))),
                Err(e) => return Err(PairFailure::Error(format!("페어링 실패: {e}"))),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// 2. Session: tunnel + DDI + Condition Inducer, owned by one thread
// ---------------------------------------------------------------------------

struct StartConfig {
    address: SocketAddr,
    pairing_path: PathBuf,
    hostname: String,
    ddi_dir: Option<PathBuf>,
}

type Reply<T> = oneshot::Sender<Result<T, String>>;

enum Command {
    Start(StartConfig, Reply<String>),
    Enable(String, String, Reply<()>),
    Disable(Reply<()>),
    Refresh(Reply<String>),
    Stop(Reply<()>),
}

const NOT_CONNECTED: &str = "아직 연결되지 않았습니다";

fn session_sender() -> Option<mpsc::UnboundedSender<Command>> {
    static SENDER: OnceLock<Option<mpsc::UnboundedSender<Command>>> = OnceLock::new();
    SENDER
        .get_or_init(|| {
            let (tx, mut rx) = mpsc::unbounded_channel::<Command>();
            std::thread::Builder::new()
                .name("gpulock-session".into())
                .spawn(move || {
                    loop {
                        let runtime = match tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                        {
                            Ok(r) => r,
                            Err(e) => {
                                log(format!("내부 오류: {e}"));
                                return;
                            }
                        };
                        let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            runtime.block_on(session_loop(&mut rx))
                        }));
                        match run {
                            Ok(()) => return,
                            Err(_) => log("내부 오류가 나서 연결을 초기화했습니다"),
                        }
                    }
                })
                .ok()
                .map(|_| tx)
        })
        .clone()
}

fn call<T>(make: impl FnOnce(Reply<T>) -> Command) -> Result<T, String> {
    let sender = session_sender().ok_or("연결 스레드를 시작하지 못했습니다")?;
    let (tx, rx) = oneshot::channel();
    sender
        .send(make(tx))
        .map_err(|_| "연결 스레드가 멈췄습니다".to_string())?;
    rx.blocking_recv()
        .map_err(|_| "연결 작업이 중단됐습니다".to_string())?
}

struct Link {
    // Field order matters for drop order: services first, tunnel last.
    remote: RemoteServerClient<Box<dyn ReadWrite>>,
    _handshake: RsdHandshake,
    _adapter: AdapterHandle,
}

async fn session_loop(rx: &mut mpsc::UnboundedReceiver<Command>) {
    let mut pending: Option<Command> = None;
    loop {
        let command = match pending.take() {
            Some(c) => c,
            None => match rx.recv().await {
                Some(c) => c,
                None => return,
            },
        };
        match command {
            Command::Start(config, reply) => match open_link(&config).await {
                Ok(mut link) => pending = serve(&mut link, rx, reply).await,
                Err(e) => {
                    log(format!("연결 실패: {e}"));
                    let _ = reply.send(Err(e));
                }
            },
            Command::Stop(reply) => {
                let _ = reply.send(Ok(()));
            }
            Command::Enable(_, _, reply) | Command::Disable(reply) => {
                let _ = reply.send(Err(NOT_CONNECTED.into()));
            }
            Command::Refresh(reply) => {
                let _ = reply.send(Err(NOT_CONNECTED.into()));
            }
        }
    }
}

async fn step<T, F>(what: &str, seconds: u64, fut: F) -> Result<T, String>
where
    F: std::future::Future<Output = Result<T, IdeviceError>>,
{
    match timeout(Duration::from_secs(seconds), fut).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(format!("{what}: {e}")),
        Err(_) => Err(format!("{what}: {seconds}초 안에 응답이 없습니다")),
    }
}

async fn tcp_connect(address: SocketAddr) -> Result<tokio::net::TcpStream, IdeviceError> {
    tokio::net::TcpStream::connect(address)
        .await
        .map_err(|e| IdeviceError::InternalError(e.to_string()))
}

async fn open_link(config: &StartConfig) -> Result<Link, String> {
    log("페어링 파일 읽는 중");
    let mut pairing = RpPairingFile::read_from_file(&config.pairing_path)
        .await
        .map_err(|e| format!("쓸 수 있는 페어링 파일이 없습니다. 먼저 페어링하세요 ({e})"))?;

    log(format!("{}에 연결 중", config.address));
    let stream = step(
        "기기 연결 (LocalDevVPN이 켜져 있나요?)",
        10,
        tcp_connect(config.address),
    )
    .await?;

    let mut rpc = RemotePairingClient::new(RpPairingSocket::new(stream), &config.hostname);
    log("페어링 확인 중");
    step("페어링 핸드셰이크", 15, rpc.attempt_pair_verify()).await?;
    step(
        "페어링 확인 (계속 실패하면 다시 페어링하세요)",
        15,
        rpc.validate_pairing(&mut pairing),
    )
    .await?;

    log("터널 여는 중");
    let tunnel_port = step("터널 준비", 15, rpc.create_tcp_listener()).await?;
    let mut tunnel_address = config.address;
    tunnel_address.set_port(tunnel_port);
    let tunnel_stream = step("터널 연결", 10, tcp_connect(tunnel_address)).await?;
    let tunnel = step(
        "터널 핸드셰이크",
        20,
        connect_tls_psk_tunnel_native(tunnel_stream, rpc.encryption_key()),
    )
    .await?;
    drop(rpc);

    let client_ip: IpAddr = tunnel
        .info
        .client_address
        .parse()
        .map_err(|e| format!("터널 주소 오류: {e}"))?;
    let server_ip: IpAddr = tunnel
        .info
        .server_address
        .parse()
        .map_err(|e| format!("터널 주소 오류: {e}"))?;
    let mtu = tunnel.info.mtu as usize;
    let rsd_port = tunnel.info.server_rsd_port;

    let raw = tunnel.into_inner();
    let mut adapter = Adapter::new(Box::new(raw), client_ip, server_ip);
    adapter.set_mss(mtu.clamp(1280, 8192) - 60);
    let mut adapter = adapter.to_async_handle();

    log("기기 서비스 목록 읽는 중");
    let mut handshake = read_services(&mut adapter, rsd_port).await?;

    if !has_instruments(&handshake) {
        install_ddi_if_needed(&mut adapter, &mut handshake, config.ddi_dir.as_ref()).await?;
        // The service list only gains Instruments once the image is active.
        let mut tries = 0;
        loop {
            handshake = read_services(&mut adapter, rsd_port).await?;
            if has_instruments(&handshake) {
                break;
            }
            tries += 1;
            if tries >= 10 {
                return Err(
                    "개발자 디스크 이미지를 설치했지만 Instruments 서비스가 나타나지 않았습니다. 아이폰을 재시동한 뒤 다시 시도하세요"
                        .into(),
                );
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    } else {
        log("개발자 디스크 이미지 이미 준비됨");
    }

    log("Instruments 여는 중");
    let remote: RemoteServerClient<Box<dyn ReadWrite>> = step(
        "Instruments 연결",
        20,
        RemoteServerClient::connect_rsd(&mut adapter, &mut handshake),
    )
    .await?;

    Ok(Link {
        remote,
        _handshake: handshake,
        _adapter: adapter,
    })
}

const INSTRUMENTS_SERVICE: &str = "com.apple.instruments.dtservicehub";

fn has_instruments(handshake: &RsdHandshake) -> bool {
    handshake.services.contains_key(INSTRUMENTS_SERVICE)
}

async fn read_services(adapter: &mut AdapterHandle, rsd_port: u16) -> Result<RsdHandshake, String> {
    let stream = step("서비스 목록 연결", 15, async {
        adapter
            .connect(rsd_port)
            .await
            .map_err(|e| IdeviceError::InternalError(e.to_string()))
    })
    .await?;
    step("서비스 목록", 15, RsdHandshake::new(stream)).await
}

async fn install_ddi_if_needed(
    adapter: &mut AdapterHandle,
    handshake: &mut RsdHandshake,
    ddi_dir: Option<&PathBuf>,
) -> Result<(), String> {
    log("개발자 디스크 이미지 확인 중");
    match step("디스크 이미지 상태", 20, cryptexd::installed_ddi(adapter, handshake)).await {
        Ok(Some(_)) => {
            log("개발자 디스크 이미지가 이미 설치돼 있음");
            return Ok(());
        }
        Ok(None) => {}
        Err(e) => log(format!("상태를 못 읽어서 설치를 시도합니다 ({e})")),
    }
    let dir = ddi_dir.ok_or("앱 안에 개발자 디스크 이미지 파일이 없습니다")?;
    let assets = step("디스크 이미지 파일 읽기", 30, Cryptex1Assets::load(dir)).await?;
    log("개발자 디스크 이미지 설치 중 (Apple 서버에서 서명을 받습니다)");
    step(
        "디스크 이미지 설치 (인터넷 연결 필요)",
        180,
        cryptexd::install_ddi(adapter, handshake, &assets),
    )
    .await?;
    log("개발자 디스크 이미지 설치 완료");
    Ok(())
}

#[derive(Serialize)]
struct GroupJson<'a> {
    identifier: &'a str,
    profiles: Vec<ProfileJson<'a>>,
}

#[derive(Serialize)]
struct ProfileJson<'a> {
    identifier: &'a str,
    description: &'a str,
}

fn groups_json(groups: &[ConditionInducerGroup]) -> String {
    let groups: Vec<GroupJson> = groups
        .iter()
        .map(|g| GroupJson {
            identifier: &g.identifier,
            profiles: g
                .profiles
                .iter()
                .map(|p| ProfileJson {
                    identifier: &p.identifier,
                    description: &p.description,
                })
                .collect(),
        })
        .collect();
    serde_json::to_string(&groups).unwrap_or_else(|_| "[]".into())
}

fn text(e: IdeviceError) -> String {
    e.to_string()
}

/// Runs the connected session until Stop, or until a new Start arrives
/// (returned so the loop reconnects).
async fn serve(
    link: &mut Link,
    rx: &mut mpsc::UnboundedReceiver<Command>,
    start_reply: Reply<String>,
) -> Option<Command> {
    let mut inducer = match step(
        "조건 서비스 연결",
        15,
        ConditionInducerClient::new(&mut link.remote),
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            let _ = start_reply.send(Err(e));
            return None;
        }
    };
    match step("조건 목록", 15, inducer.available_conditions()).await {
        Ok(groups) => {
            log(format!("연결됨, 조건 그룹 {}개", groups.len()));
            let _ = start_reply.send(Ok(groups_json(&groups)));
        }
        Err(e) => {
            let _ = start_reply.send(Err(e));
            return None;
        }
    }

    let mut active: Option<(String, String)> = None;
    while let Some(command) = rx.recv().await {
        match command {
            Command::Start(..) => {
                if active.is_some() {
                    let _ = inducer.disable_condition().await;
                }
                return Some(command);
            }
            Command::Enable(group, profile, reply) => {
                if let Some((g, p)) = &active
                    && (g != &group || p != &profile)
                {
                    let _ = inducer.disable_condition().await;
                    active = None;
                }
                let result = timeout(
                    Duration::from_secs(15),
                    inducer.enable_condition(&group, &profile),
                )
                .await
                .map_err(|_| "조건 켜기: 응답이 없습니다".to_string())
                .and_then(|r| r.map_err(text));
                if result.is_ok() {
                    log(format!("켜짐: {profile}"));
                    active = Some((group, profile));
                }
                let _ = reply.send(result);
            }
            Command::Disable(reply) => {
                let result = inducer.disable_condition().await.map_err(text);
                if result.is_ok() {
                    log("조건 꺼짐");
                    active = None;
                }
                let _ = reply.send(result);
            }
            Command::Refresh(reply) => {
                let result = timeout(Duration::from_secs(10), inducer.available_conditions())
                    .await
                    .map_err(|_| "연결 확인: 응답이 없습니다".to_string())
                    .and_then(|r| r.map_err(text))
                    .map(|g| groups_json(&g));
                let _ = reply.send(result);
            }
            Command::Stop(reply) => {
                if active.is_some() {
                    let _ = inducer.disable_condition().await;
                }
                log("연결 끊음");
                let _ = reply.send(Ok(()));
                return None;
            }
        }
    }
    None
}

// ----- C API for the session -----

/// Connects (tunnel + DDI + Instruments) and returns the condition list as
/// JSON, or NULL with `*error` set. Blocks; call off the main thread.
///
/// # Safety
/// String arguments must be valid C strings (`ddi_dir` may be NULL);
/// `error` NULL or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gl_start(
    ip: *const c_char,
    port: u16,
    pairing_path: *const c_char,
    hostname: *const c_char,
    ddi_dir: *const c_char,
    error: *mut *mut c_char,
) -> *mut c_char {
    let ip: Option<IpAddr> = read_str(ip).and_then(|s| s.parse().ok());
    let (Some(ip), Some(pairing_path), Some(hostname)) =
        (ip, read_str(pairing_path), read_str(hostname))
    else {
        set_error(error, "연결 설정이 잘못됐습니다");
        return ptr::null_mut();
    };
    let config = StartConfig {
        address: SocketAddr::new(ip, port),
        pairing_path: PathBuf::from(pairing_path),
        hostname,
        ddi_dir: read_str(ddi_dir).map(PathBuf::from),
    };
    match call(|r| Command::Start(config, r)) {
        Ok(json) => to_cstring(json).into_raw(),
        Err(e) => {
            set_error(error, e);
            ptr::null_mut()
        }
    }
}

fn status(result: Result<(), String>, error: *mut *mut c_char) -> i32 {
    match result {
        Ok(()) => 0,
        Err(e) => {
            set_error(error, e);
            1
        }
    }
}

/// Enables one condition profile. 0 on success, 1 with `*error` set.
///
/// # Safety
/// `group`/`profile` valid C strings; `error` NULL or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gl_enable(
    group: *const c_char,
    profile: *const c_char,
    error: *mut *mut c_char,
) -> i32 {
    let (Some(group), Some(profile)) = (read_str(group), read_str(profile)) else {
        set_error(error, "잘못된 조건입니다");
        return 1;
    };
    status(call(|r| Command::Enable(group, profile, r)), error)
}

/// Turns the active condition off. 0 on success, 1 with `*error` set.
///
/// # Safety
/// `error` NULL or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gl_disable(error: *mut *mut c_char) -> i32 {
    status(call(Command::Disable), error)
}

/// Re-reads the condition list; doubles as a "still connected?" check.
///
/// # Safety
/// `error` NULL or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gl_refresh(error: *mut *mut c_char) -> *mut c_char {
    match call(Command::Refresh) {
        Ok(json) => to_cstring(json).into_raw(),
        Err(e) => {
            set_error(error, e);
            ptr::null_mut()
        }
    }
}

/// Turns any condition off and closes the connection.
#[unsafe(no_mangle)]
pub extern "C" fn gl_stop() {
    let _ = call(Command::Stop);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairing_session_advertises_consistently() {
        let mut err = ptr::null_mut();
        let s = unsafe { gl_pairing_new(c"GPU Lock".as_ptr(), &mut err) };
        assert!(!s.is_null() && err.is_null());
        unsafe {
            assert_ne!(gl_pairing_port(s), 0);
            let name = CStr::from_ptr(gl_pairing_service_name(s)).to_str().unwrap().to_string();
            let mut found_identifier = false;
            for i in 0..gl_pairing_txt_count(s) {
                let k = CStr::from_ptr(gl_pairing_txt_key(s, i)).to_str().unwrap();
                let v = CStr::from_ptr(gl_pairing_txt_value(s, i)).to_str().unwrap();
                assert!(k.len() + v.len() < 255);
                if k == "identifier" {
                    assert_eq!(v, name);
                    found_identifier = true;
                }
            }
            assert!(found_identifier);
            gl_pairing_cancel(s);
            let mut out_name = ptr::null_mut();
            let rc = gl_pairing_accept(
                s,
                None,
                ptr::null_mut(),
                c"/tmp/gl-test-pairing.plist".as_ptr(),
                &mut out_name,
                &mut err,
            );
            assert_eq!(rc, 2);
            gl_pairing_free(s);
        }
    }

    #[test]
    fn session_commands_without_connection_fail_cleanly() {
        let mut err = ptr::null_mut();
        assert_eq!(unsafe { gl_disable(&mut err) }, 1);
        assert!(!err.is_null());
        unsafe { gl_string_free(err) };
        gl_stop();
    }

    #[test]
    fn start_reports_missing_pairing_file() {
        let mut err = ptr::null_mut();
        let out = unsafe {
            gl_start(
                c"127.0.0.1".as_ptr(),
                1,
                c"/nonexistent/pairing.plist".as_ptr(),
                c"GPU Lock".as_ptr(),
                ptr::null(),
                &mut err,
            )
        };
        assert!(out.is_null());
        let msg = unsafe { CStr::from_ptr(err) }.to_str().unwrap().to_string();
        assert!(msg.contains("페어링 파일"), "{msg}");
        unsafe { gl_string_free(err) };
    }
}
