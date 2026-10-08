//! CSU Portal CLI. No logout, network reset, or insecure TLS fallback.
#![cfg(windows)]

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{Duration as ChronoDuration, Local};
use clap::{Parser, Subcommand};
use regex::Regex;
use reqwest::{blocking::Client, redirect::Policy};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    net::Ipv4Addr,
    os::windows::process::CommandExt,
    path::PathBuf,
    process::{Command, Output},
    ptr,
    time::Duration,
};
use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    },
};

const PORTAL: &str = "https://portal.csu.edu.cn";
const API: &str = "https://portal.csu.edu.cn:802/eportal/portal/";
const TASK_NAME: &str = "CSU-Portal-Watchdog";
const BACKGROUND_EXE: &str = "csu-portal-watchdog-background.exe";
type Result<T> = std::result::Result<T, &'static str>;
type Parameters = Vec<(String, String)>;

#[derive(Parser)]
#[command(
    version,
    about = "中南大学校园网自动认证",
    arg_required_else_help = true
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, PartialEq, Subcommand)]
enum Commands {
    /// 在本机配置账号密码
    Setup {
        /// 配置后启用五分钟计划任务
        #[arg(long)]
        install: bool,
    },
    /// 使用已有配置启用五分钟计划任务
    Install,
    /// 只读查看网络和认证状态
    Status,
    /// 检测一次；必要时认证一次
    Once {
        /// 只读检测，不提交认证请求
        #[arg(long)]
        dry_run: bool,
    },
    /// 停用定时检查，保留当前校园网连接和登录
    Disable,
}

#[derive(Clone)]
struct Paths {
    exe: PathBuf,
    directory: PathBuf,
    state: PathBuf,
}

impl Paths {
    fn current() -> Result<Self> {
        let exe = std::env::current_exe().map_err(|_| "无法取得程序路径")?;
        let directory = exe.parent().ok_or("无法取得程序目录")?.to_path_buf();
        let state = directory.join("state");
        fs::create_dir_all(&state).map_err(|_| "程序目录不可写，请放到当前用户可写的目录")?;
        Ok(Self {
            exe,
            directory,
            state,
        })
    }

    fn credentials(&self) -> PathBuf {
        self.state.join("credentials.json")
    }

    fn log(&self, message: &str) {
        println!("{message}");
        let path = self.state.join("watchdog.log");
        if fs::metadata(&path)
            .map(|m| m.len() > 512 * 1024)
            .unwrap_or(false)
        {
            let _ = fs::remove_file(self.state.join("watchdog.log.2"));
            let _ = fs::rename(
                self.state.join("watchdog.log.1"),
                self.state.join("watchdog.log.2"),
            );
            let _ = fs::rename(&path, self.state.join("watchdog.log.1"));
        }
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(
                file,
                "{} {message}",
                Local::now().format("%Y-%m-%d %H:%M:%S")
            );
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
struct Context {
    online: Option<bool>,
    ip: String,
    mac: String,
    username: String,
}

#[derive(Serialize, Deserialize)]
struct StoredCredentials {
    username: String,
    password_dpapi: String,
}

struct Credentials {
    username: String,
    password: String,
}

fn dpapi(data: &[u8], decrypt: bool) -> Result<Vec<u8>> {
    let size = u32::try_from(data.len()).map_err(|_| "凭据长度无效")?;
    let input = CRYPT_INTEGER_BLOB {
        cbData: size,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };
    // DPAPI allocates output with LocalAlloc. Input lives throughout the call.
    let success = unsafe {
        if decrypt {
            CryptUnprotectData(
                &input,
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        } else {
            CryptProtectData(
                &input,
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        }
    };
    if success == 0 {
        return Err("Windows 凭据加密或解密失败，请在同一 Windows 用户下重新配置");
    }
    let bytes =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        LocalFree(output.pbData.cast());
    }
    Ok(bytes)
}

fn load_credentials(paths: &Paths) -> Result<Credentials> {
    let bytes = fs::read(paths.credentials()).map_err(|_| "尚未配置凭据，请运行 setup.cmd")?;
    let stored: StoredCredentials =
        serde_json::from_slice(&bytes).map_err(|_| "配置文件无效，请重新运行 setup.cmd")?;
    let encrypted = BASE64
        .decode(stored.password_dpapi)
        .map_err(|_| "加密凭据格式无效")?;
    let password = String::from_utf8(dpapi(&encrypted, true)?).map_err(|_| "密码编码无效")?;
    if stored.username.is_empty() || password.is_empty() {
        return Err("凭据不完整，请重新运行 setup.cmd");
    }
    Ok(Credentials {
        username: stored.username,
        password,
    })
}

fn save_credentials(paths: &Paths, credentials: &Credentials) -> Result<()> {
    let encrypted = dpapi(credentials.password.as_bytes(), false)?;
    let stored = StoredCredentials {
        username: credentials.username.clone(),
        password_dpapi: BASE64.encode(encrypted),
    };
    let bytes = serde_json::to_vec_pretty(&stored).map_err(|_| "配置编码失败")?;
    let temporary = paths.state.join("credentials.tmp");
    fs::write(&temporary, bytes).map_err(|_| "凭据文件无法写入")?;
    fs::rename(temporary, paths.credentials()).map_err(|_| "凭据文件无法保存")?;
    Ok(())
}

fn scalar(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        _ => String::new(),
    }
}

fn parse_jsonp(text: &str) -> Result<Value> {
    let text = text.trim_start_matches('\u{feff}').trim();
    let json = if text.starts_with('{') {
        text.to_string()
    } else {
        let pattern = Regex::new(r"(?s)^[A-Za-z_$][\w$]*\s*\(\s*(\{.*\})\s*\)\s*;?$").unwrap();
        pattern
            .captures(text)
            .ok_or("认证服务器返回了无法识别的数据")?[1]
            .to_string()
    };
    let value: Value = serde_json::from_str(&json).map_err(|_| "认证服务器返回了无效 JSON")?;
    if !value.is_object() {
        return Err("认证服务器数据格式不符");
    }
    Ok(value)
}

fn js_string(text: &str, name: &str) -> String {
    let pattern = Regex::new(&format!(
        r#"\b{}\s*=\s*(?:'([^']*)'|"([^"]*)")"#,
        regex::escape(name)
    ))
    .unwrap();
    pattern
        .captures(text)
        .and_then(|c| c.get(1).or_else(|| c.get(2)))
        .map(|m| m.as_str().to_string())
        .unwrap_or_default()
}

fn context_from(html: &str, status: &Value) -> Context {
    let pattern = Regex::new(r"<!--\s*Dr\.COMWebLoginID_([013])\.htm\s*-->").unwrap();
    let page_online = pattern.captures(html).map(|c| &c[1] != "0");
    let status_online = match scalar(&status["result"]).as_str() {
        "1" => Some(true),
        "0" => Some(false),
        _ => None,
    };
    let online = if page_online == Some(true) || status_online == Some(true) {
        Some(true)
    } else if page_online == Some(false) && status_online == Some(false) {
        Some(false)
    } else {
        None
    };
    let mut ip = js_string(html, "v4ip");
    if ip.is_empty() {
        ip = scalar(&status["v4ip"]);
    }
    if ip.is_empty() {
        ip = scalar(&status["ss5"]);
    }
    ip = ip
        .parse::<Ipv4Addr>()
        .ok()
        .filter(|a| !a.is_unspecified() && !a.is_loopback())
        .map(|a| a.to_string())
        .unwrap_or_default();
    let mut mac = js_string(html, "ss4");
    if mac.is_empty() {
        mac = scalar(&status["ss4"]);
    }
    mac = mac.replace(['-', ':'], "").to_uppercase();
    if !Regex::new(r"^[0-9A-F]{12}$").unwrap().is_match(&mac) {
        mac = "000000000000".to_string();
    }
    Context {
        online,
        ip,
        mac,
        username: scalar(&status["uid"]),
    }
}

fn parameters(items: &[(&str, &str)]) -> Parameters {
    items
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn jsonp(mut values: Parameters) -> Parameters {
    if !values.iter().any(|(k, _)| k == "jsVersion") {
        values.push(("jsVersion".into(), "4.1.3".into()));
    }
    let nonce = Local::now().timestamp_millis().rem_euclid(10000) + 500;
    values.extend(parameters(&[("callback", "csuWatchdog"), ("lang", "zh")]));
    values.push(("v".into(), nonce.to_string()));
    values
}

fn login_payload(
    credentials: &Credentials,
    context: &Context,
    info: &Value,
    script: &str,
) -> Result<Parameters> {
    if context.ip.is_empty() {
        return Err("未能取得当前终端 IPv4");
    }
    if !info.is_object() || scalar(&info["login_method"]) != "1" {
        return Err("当前认证方式与已确认的 Portal 协议不一致");
    }
    for key in ["en_md5", "password_cut"] {
        if !info[key].is_null() && scalar(&info[key]) != "0" {
            return Err("认证页密码处理规则已改变，需要重新核对接口");
        }
    }
    let version = js_string(script, "jsVersion");
    if !Regex::new(r"^\d+(?:\.\d+)*$").unwrap().is_match(&version) {
        return Err("未能取得认证页脚本版本");
    }
    let prefix = if info["account_prefix"].is_null() || scalar(&info["account_prefix"]) == "1" {
        if scalar(&info["custom_perceive"]) == "1" {
            ",b,"
        } else {
            ",0,"
        }
    } else {
        ""
    };
    let account = format!(
        "{prefix}{}{}",
        credentials.username,
        scalar(&info["account_suffix"])
    );
    Ok(jsonp(parameters(&[
        ("login_method", "1"),
        ("user_account", &account),
        ("user_password", &credentials.password),
        ("wlan_user_ip", &context.ip),
        ("wlan_user_ipv6", ""),
        ("wlan_user_mac", &context.mac),
        ("wlan_ac_ip", ""),
        ("wlan_ac_name", ""),
        ("jsVersion", &version),
        ("terminal_type", "1"),
    ])))
}

struct Http {
    client: Client,
}

impl Http {
    fn new() -> Result<Self> {
        let client = Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .cookie_store(true)
            .timeout(Duration::from_secs(8))
            .user_agent("CSU-Watchdog/0.2 (Windows)")
            .build()
            .map_err(|_| "网络客户端初始化失败")?;
        Ok(Self { client })
    }

    fn fetch(&self, url: &str, query: &Parameters) -> Result<(Vec<u8>, String)> {
        // Never expose reqwest errors: a login URL contains the password.
        let response = self
            .client
            .get(url)
            .query(query)
            .header("Cache-Control", "no-cache")
            .send()
            .map_err(|_| "连接超时、网络不可达或 HTTPS 校验失败")?;
        if response.status() != 200 {
            return Err("HTTP 状态异常（不跟随重定向）");
        }
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let mut body = Vec::new();
        response
            .take(1024 * 1024 + 1)
            .read_to_end(&mut body)
            .map_err(|_| "响应读取失败")?;
        if body.len() > 1024 * 1024 {
            return Err("响应超过读取上限");
        }
        Ok((body, content_type))
    }

    fn portal_text(&self, url: &str, query: &Parameters) -> Result<String> {
        let (body, content_type) = self.fetch(url, query)?;
        if content_type.to_ascii_lowercase().contains("charset=gb") {
            return Ok(encoding_rs::GBK.decode(&body).0.into_owned());
        }
        Ok(String::from_utf8(body.clone())
            .unwrap_or_else(|_| encoding_rs::GBK.decode(&body).0.into_owned()))
    }

    fn portal_json(&self, url: &str, query: &Parameters) -> Result<Value> {
        parse_jsonp(&self.portal_text(url, query)?)
    }

    fn context(&self) -> Context {
        let html = self
            .portal_text(&format!("{PORTAL}/"), &vec![])
            .unwrap_or_default();
        let status = self
            .portal_json(&format!("{PORTAL}/drcom/chkstatus"), &jsonp(vec![]))
            .unwrap_or(Value::Null);
        context_from(&html, &status)
    }

    fn healthy(&self) -> bool {
        for (url, expected) in [
            (
                "http://www.msftconnecttest.com/connecttest.txt",
                "Microsoft Connect Test",
            ),
            ("https://www.baidu.com/robots.txt", "User-agent:"),
        ] {
            if let Ok((body, _)) = self.fetch(url, &vec![]) {
                let text = String::from_utf8_lossy(&body);
                if (url.starts_with("http:") && text.trim() == expected)
                    || (url.starts_with("https:") && text.trim_start().starts_with(expected))
                {
                    return true;
                }
            }
        }
        false
    }

    fn login_parameters(&self, credentials: &Credentials, context: &Context) -> Result<Parameters> {
        if context.ip.is_empty() {
            return Err("未能取得当前终端 IPv4");
        }
        let encoded_ip = BASE64.encode(context.ip.as_bytes());
        let query = jsonp(parameters(&[
            ("program_index", ""),
            ("wlan_vlan_id", "1"),
            ("wlan_user_ip", &encoded_ip),
            ("wlan_user_ipv6", ""),
            ("wlan_user_ssid", ""),
            ("wlan_user_areaid", ""),
            ("wlan_ac_ip", ""),
            ("wlan_ap_mac", "000000000000"),
            ("gw_id", "000000000000"),
        ]));
        let info = self.portal_json(&format!("{API}page/loadConfig"), &query)?;
        let script = self.portal_text(&format!("{PORTAL}/a40.js"), &vec![])?;
        login_payload(credentials, context, &info["data"], &script)
    }
}

trait Environment {
    fn healthy(&mut self) -> bool;
    fn context(&mut self) -> Context;
    fn prepare(&mut self, context: &Context) -> Result<Parameters>;
    fn authenticate(&mut self, parameters: &Parameters) -> Result<Value>;
    fn pause(&mut self);
    fn log(&mut self, message: &str);
}

struct Runtime<'a> {
    http: &'a Http,
    paths: &'a Paths,
}

impl Environment for Runtime<'_> {
    fn healthy(&mut self) -> bool {
        self.http.healthy()
    }
    fn context(&mut self) -> Context {
        self.http.context()
    }
    fn prepare(&mut self, context: &Context) -> Result<Parameters> {
        self.http
            .login_parameters(&load_credentials(self.paths)?, context)
    }
    fn authenticate(&mut self, parameters: &Parameters) -> Result<Value> {
        self.http.portal_json(&format!("{API}login"), parameters)
    }
    fn pause(&mut self) {
        std::thread::sleep(Duration::from_secs(5));
    }
    fn log(&mut self, message: &str) {
        self.paths.log(message);
    }
}

#[derive(Debug, PartialEq)]
enum Outcome {
    Healthy,
    StillOnline,
    Unknown,
    DryRun,
    ConfigurationError,
    StateChanged,
    Recovered,
    NotRecovered,
}

fn cycle(env: &mut impl Environment, dry_run: bool) -> Outcome {
    if env.healthy() {
        env.log("网络正常，跳过认证。");
        return Outcome::Healthy;
    }
    env.pause();
    if env.healthy() {
        env.log("复测时网络已恢复，跳过认证。");
        return Outcome::Healthy;
    }
    let context = env.context();
    if context.online == Some(true) {
        env.log("外网探测失败，但认证仍在线；保留当前登录，等待下次检查。");
        return Outcome::StillOnline;
    }
    if context.online != Some(false) {
        env.log("无法明确确认认证离线；本轮不提交登录请求。");
        return Outcome::Unknown;
    }
    if dry_run {
        env.log("外网不可用且认证离线；只读检查结束，未提交认证。");
        return Outcome::DryRun;
    }
    let parameters = match env.prepare(&context) {
        Ok(p) => p,
        Err(message) => {
            env.log(message);
            return Outcome::ConfigurationError;
        }
    };
    let current = env.context();
    if current.online != Some(false) || current.ip != context.ip || current.mac != context.mac {
        env.log("提交前认证状态或终端地址发生变化，本轮停止认证。");
        return Outcome::StateChanged;
    }
    if env.healthy() {
        env.log("提交前网络已恢复，跳过认证。");
        return Outcome::Healthy;
    }
    env.log("确认当前终端离线，尝试一次 HTTPS Portal 登录。");
    let reply = match env.authenticate(&parameters) {
        Ok(value) => value,
        Err(_) => {
            env.log("登录请求未得到有效响应，将独立复测网络。");
            Value::Null
        }
    };
    env.pause();
    if env.healthy() {
        env.log("外网复测通过，网络已恢复。");
        return Outcome::Recovered;
    }
    if matches!(scalar(&reply["result"]).as_str(), "1" | "ok") {
        env.log("认证接口报告成功，外网仍未恢复；等待下个五分钟周期。");
    } else {
        env.log("未确认登录成功，外网仍未恢复；等待下个五分钟周期。");
    }
    Outcome::NotRecovered
}

fn configure(paths: &Paths, http: &Http) -> Result<()> {
    let context = http.context();
    let mut default = if context.online == Some(true) {
        context.username
    } else {
        String::new()
    };
    if let Ok(bytes) = fs::read(paths.credentials()) {
        if let Ok(stored) = serde_json::from_slice::<StoredCredentials>(&bytes) {
            default = stored.username;
        }
    }
    print!(
        "校园网账号{}：",
        if default.is_empty() {
            String::new()
        } else {
            format!(" [{default}]")
        }
    );
    io::stdout().flush().map_err(|_| "无法显示输入提示")?;
    let mut username = String::new();
    io::stdin()
        .read_line(&mut username)
        .map_err(|_| "账号输入失败")?;
    let username = if username.trim().is_empty() {
        default
    } else {
        username.trim().to_string()
    };
    if !Regex::new(r"^[A-Za-z0-9@_.-]{1,80}$")
        .unwrap()
        .is_match(&username)
    {
        return Err("请输入有效的校园网账号");
    }
    let password =
        rpassword::prompt_password("校园网密码（输入时不显示）：").map_err(|_| "密码输入失败")?;
    let confirm = rpassword::prompt_password("再次输入密码：").map_err(|_| "密码输入失败")?;
    if password.is_empty() || password != confirm {
        return Err("两次密码不一致或密码为空");
    }
    save_credentials(paths, &Credentials { username, password })?;
    paths.log("账号已配置，密码由当前 Windows 用户的 DPAPI 加密保存。");
    Ok(())
}

fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn task_xml(paths: &Paths, sid: &str) -> Vec<u8> {
    let start = (Local::now() + ChronoDuration::minutes(1)).format("%Y-%m-%dT%H:%M:%S%:z");
    let executable = xml_escape(&paths.exe.with_file_name(BACKGROUND_EXE).to_string_lossy());
    let directory = xml_escape(&paths.directory.to_string_lossy());
    let sid = xml_escape(sid);
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
<RegistrationInfo><Description>中南大学校园网：每五分钟探测；明确离线时才登录。</Description></RegistrationInfo>
<Triggers><TimeTrigger><Repetition><Interval>PT5M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition><StartBoundary>{start}</StartBoundary><Enabled>true</Enabled></TimeTrigger><LogonTrigger><Enabled>true</Enabled><UserId>{sid}</UserId></LogonTrigger></Triggers>
<Principals><Principal id="Author"><UserId>{sid}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><StartWhenAvailable>true</StartWhenAvailable><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>true</Hidden><ExecutionTimeLimit>PT3M</ExecutionTimeLimit></Settings>
<Actions Context="Author"><Exec><Command>{executable}</Command><Arguments>once</Arguments><WorkingDirectory>{directory}</WorkingDirectory></Exec></Actions>
</Task>"#
    );
    let mut bytes = vec![0xff, 0xfe];
    bytes.extend(xml.encode_utf16().flat_map(u16::to_le_bytes));
    bytes
}

fn windows_command(program: &str, arguments: &[&str]) -> Result<Output> {
    Command::new(program)
        .args(arguments)
        .creation_flags(0x08000000)
        .output()
        .map_err(|_| "无法执行 Windows 计划任务命令")
}

fn install(paths: &Paths) -> Result<()> {
    if !paths.exe.with_file_name(BACKGROUND_EXE).is_file() {
        return Err("找不到后台启动程序，请下载完整仓库");
    }
    load_credentials(paths)?;
    let who = windows_command("whoami.exe", &["/user", "/fo", "csv", "/nh"])?;
    let text = String::from_utf8_lossy(&who.stdout);
    let sid_pattern = Regex::new(r"S-1-[\d-]+").unwrap();
    let sid = sid_pattern
        .find(&text)
        .filter(|_| who.status.success())
        .ok_or("无法取得当前 Windows 用户标识")?
        .as_str();
    let file = paths.state.join("scheduled-task.xml");
    fs::write(&file, task_xml(paths, sid)).map_err(|_| "计划任务文件无法写入")?;
    let output = windows_command(
        "schtasks.exe",
        &[
            "/Create",
            "/TN",
            TASK_NAME,
            "/XML",
            &file.to_string_lossy(),
            "/F",
        ],
    )?;
    if !output.status.success() {
        return Err("计划任务安装失败，请检查当前用户的创建权限");
    }
    let started = windows_command("schtasks.exe", &["/Run", "/TN", TASK_NAME])?;
    paths.log("已启用计划任务：每五分钟检查，登录 Windows 时也检查。");
    paths.log(if started.status.success() {
        "首次检查已启动。"
    } else {
        "首次检查将在一分钟内启动。"
    });
    Ok(())
}

fn run(paths: &Paths, command: Commands) -> Result<bool> {
    match command {
        Commands::Install => install(paths)?,
        Commands::Disable => {
            let output =
                windows_command("schtasks.exe", &["/Change", "/TN", TASK_NAME, "/DISABLE"])?;
            if !output.status.success() {
                return Err("停用失败，请在任务计划程序中检查该任务");
            }
            paths.log("定时检查已停用；当前校园网连接和认证保持原状。");
        }
        Commands::Setup {
            install: enable_install,
        } => {
            configure(paths, &Http::new()?)?;
            if enable_install {
                install(paths)?;
            }
        }
        Commands::Status => {
            let http = Http::new()?;
            let healthy = http.healthy();
            let context = http.context();
            let state = match context.online {
                Some(true) => "已登录",
                Some(false) => "明确离线",
                None => "状态不确定",
            };
            paths.log(&format!(
                "外网：{}；校园网认证：{state}；终端 IPv4：{}。",
                if healthy { "正常" } else { "探测失败" },
                if context.ip.is_empty() {
                    "未知"
                } else {
                    &context.ip
                }
            ));
        }
        Commands::Once { dry_run } => {
            let http = Http::new()?;
            let outcome = cycle(&mut Runtime { http: &http, paths }, dry_run);
            return Ok(matches!(
                outcome,
                Outcome::Healthy | Outcome::Recovered | Outcome::DryRun
            ));
        }
    }
    Ok(true)
}

fn main() {
    let cli = Cli::parse();
    let paths = match Paths::current() {
        Ok(p) => p,
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(2);
        }
    };
    let code = match run(&paths, cli.command) {
        Ok(true) => 0,
        Ok(false) => 1,
        Err(message) => {
            paths.log(message);
            2
        }
    };
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::VecDeque, net::TcpListener};

    #[test]
    fn clap_supports_every_documented_python_command() {
        let cases = [
            (vec!["setup"], Commands::Setup { install: false }),
            (
                vec!["setup", "--install"],
                Commands::Setup { install: true },
            ),
            (vec!["install"], Commands::Install),
            (vec!["status"], Commands::Status),
            (vec!["once"], Commands::Once { dry_run: false }),
            (vec!["once", "--dry-run"], Commands::Once { dry_run: true }),
            (vec!["disable"], Commands::Disable),
        ];
        for (arguments, expected) in cases {
            let cli = Cli::try_parse_from(std::iter::once("watchdog").chain(arguments)).unwrap();
            assert_eq!(cli.command, expected);
        }
        for command in ["setup", "install", "status", "once", "disable"] {
            let error = Cli::try_parse_from(["watchdog", command, "--help"])
                .err()
                .unwrap();
            assert_eq!(error.kind(), clap::error::ErrorKind::DisplayHelp);
        }
    }

    fn offline() -> Context {
        Context {
            online: Some(false),
            ip: "192.0.2.10".into(),
            mac: "000000000000".into(),
            username: String::new(),
        }
    }

    struct Fake {
        probes: VecDeque<bool>,
        contexts: VecDeque<Context>,
        prepares: usize,
        auth_calls: usize,
        accepted: bool,
        messages: Vec<String>,
    }

    impl Fake {
        fn new(probes: &[bool], contexts: Vec<Context>) -> Self {
            Self {
                probes: probes.iter().copied().collect(),
                contexts: contexts.into(),
                prepares: 0,
                auth_calls: 0,
                accepted: true,
                messages: vec![],
            }
        }
    }

    impl Environment for Fake {
        fn healthy(&mut self) -> bool {
            self.probes.pop_front().expect("unexpected probe")
        }
        fn context(&mut self) -> Context {
            self.contexts.pop_front().expect("unexpected context query")
        }
        fn prepare(&mut self, _: &Context) -> Result<Parameters> {
            self.prepares += 1;
            Ok(parameters(&[
                ("user_account", "fake-user"),
                ("user_password", "test-only-secret"),
            ]))
        }
        fn authenticate(&mut self, _: &Parameters) -> Result<Value> {
            self.auth_calls += 1;
            if self.accepted {
                Ok(serde_json::json!({"result": 1}))
            } else {
                Err("测试请求失败")
            }
        }
        fn pause(&mut self) {}
        fn log(&mut self, message: &str) {
            self.messages.push(message.to_string());
        }
    }

    #[test]
    fn healthy_and_transient_failure_never_read_credentials() {
        for probes in [vec![true], vec![false, true]] {
            let mut env = Fake::new(&probes, vec![]);
            assert_eq!(cycle(&mut env, false), Outcome::Healthy);
            assert_eq!((env.prepares, env.auth_calls), (0, 0));
        }
    }

    #[test]
    fn online_or_unknown_authentication_never_logs_in() {
        for (online, outcome) in [(Some(true), Outcome::StillOnline), (None, Outcome::Unknown)] {
            let mut context = offline();
            context.online = online;
            let mut env = Fake::new(&[false, false], vec![context]);
            assert_eq!(cycle(&mut env, false), outcome);
            assert_eq!((env.prepares, env.auth_calls), (0, 0));
        }
    }

    #[test]
    fn dry_run_offline_never_reads_password_or_submits_login() {
        let mut env = Fake::new(&[false, false], vec![offline()]);
        assert_eq!(cycle(&mut env, true), Outcome::DryRun);
        assert_eq!((env.prepares, env.auth_calls), (0, 0));
    }

    #[test]
    fn status_ip_or_mac_change_stops_prepared_login() {
        let mut online = offline();
        online.online = Some(true);
        let mut ip = offline();
        ip.ip = "192.0.2.11".into();
        let mut mac = offline();
        mac.mac = "001122334455".into();
        let mut unknown = offline();
        unknown.online = None;
        for changed in [online, ip, mac, unknown] {
            let mut env = Fake::new(&[false, false], vec![offline(), changed]);
            assert_eq!(cycle(&mut env, false), Outcome::StateChanged);
            assert_eq!(env.auth_calls, 0);
        }
    }

    #[test]
    fn last_probe_recovery_skips_login() {
        let mut env = Fake::new(&[false, false, true], vec![offline(), offline()]);
        assert_eq!(cycle(&mut env, false), Outcome::Healthy);
        assert_eq!(env.auth_calls, 0);
    }

    #[test]
    fn one_login_must_be_confirmed_by_internet_response() {
        for (healthy, expected) in [(true, Outcome::Recovered), (false, Outcome::NotRecovered)] {
            let mut env = Fake::new(&[false, false, false, healthy], vec![offline(), offline()]);
            assert_eq!(cycle(&mut env, false), expected);
            assert_eq!(env.auth_calls, 1);
            assert!(!env.messages.join("\n").contains("test-only-secret"));
            assert!(!env.messages.join("\n").contains("fake-user"));
        }
    }

    #[test]
    fn failed_login_response_still_checks_internet() {
        let mut env = Fake::new(&[false, false, false, true], vec![offline(), offline()]);
        env.accepted = false;
        assert_eq!(cycle(&mut env, false), Outcome::Recovered);
        assert_eq!(env.auth_calls, 1);
    }

    #[test]
    fn jsonp_parsing_never_executes_javascript() {
        assert_eq!(
            parse_jsonp("callback({\"result\":1});").unwrap()["result"],
            1
        );
        assert!(parse_jsonp("alert('bad');callback({\"result\":1});").is_err());
        assert!(parse_jsonp("[]").is_err());
    }

    #[test]
    fn only_two_explicit_offline_observations_allow_login() {
        for (page, status, expected) in [
            (0, 0, Some(false)),
            (0, 1, Some(true)),
            (1, 0, Some(true)),
            (0, 7, None),
        ] {
            let html = format!("<!--Dr.COMWebLoginID_{page}.htm--> v4ip='192.0.2.10';");
            let context = context_from(&html, &serde_json::json!({"result": status}));
            assert_eq!(context.online, expected);
            assert_eq!(context.ip, "192.0.2.10");
        }
        assert_eq!(context_from("", &Value::Null).online, None);
        assert!(context_from("v4ip='127.0.0.1';", &Value::Null)
            .ip
            .is_empty());
    }

    #[test]
    fn payload_uses_current_credentials_address_and_server_rules() {
        let info = serde_json::json!({"login_method":"1", "account_prefix":"1", "account_suffix":"", "en_md5":"0", "password_cut":"0"});
        let creds = Credentials {
            username: "test-user".into(),
            password: "p&+?#中文".into(),
        };
        let payload = login_payload(&creds, &offline(), &info, "var jsVersion='4.1.3';").unwrap();
        let get = |name| &payload.iter().find(|(k, _)| k == name).unwrap().1;
        assert_eq!(get("user_account"), ",0,test-user");
        assert_eq!(get("user_password"), "p&+?#中文");
        assert_eq!(get("wlan_user_ip"), "192.0.2.10");
        assert_eq!(get("wlan_user_mac"), "000000000000");
        assert_eq!(get("jsVersion"), "4.1.3");
    }

    #[test]
    fn unknown_protocol_or_password_rules_are_rejected() {
        let creds = Credentials {
            username: "test-user".into(),
            password: "test-only".into(),
        };
        for info in [
            serde_json::json!({"login_method":"14"}),
            serde_json::json!({"login_method":"1", "en_md5":"1"}),
        ] {
            assert!(login_payload(&creds, &offline(), &info, "var jsVersion='4.1.3';").is_err());
        }
    }

    #[test]
    fn http_redirect_is_not_followed_and_response_is_bounded() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 1024];
            stream.read(&mut request).unwrap();
            stream.write_all(b"HTTP/1.1 302 Found\r\nLocation: /must-not-visit\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
            listener.set_nonblocking(true).unwrap();
            std::thread::sleep(Duration::from_millis(100));
            assert!(listener.accept().is_err());
        });
        assert!(Http::new()
            .unwrap()
            .fetch(&format!("http://{address}/start"), &vec![])
            .is_err());
        server.join().unwrap();
    }

    fn test_paths(directory: PathBuf) -> Paths {
        Paths {
            exe: directory.join("csu-portal-watchdog.exe"),
            state: directory.join("state"),
            directory,
        }
    }

    #[test]
    fn task_xml_is_utf16_and_uses_dynamic_exe_directory_sid_and_five_minutes() {
        let paths = test_paths(PathBuf::from("C:/Portable 校园网 & test"));
        let bytes = task_xml(&paths, "S-1-5-21-123-1001");
        assert!(bytes.starts_with(&[0xff, 0xfe]));
        let units = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect::<Vec<_>>();
        let xml = String::from_utf16(&units).unwrap();
        assert!(xml.contains(&format!(
            "<Command>{}</Command>",
            xml_escape(&paths.exe.with_file_name(BACKGROUND_EXE).to_string_lossy())
        )));
        assert!(xml.contains("<Arguments>once</Arguments>"));
        assert!(xml.contains("<Interval>PT5M</Interval>"));
        assert!(xml.contains("<UserId>S-1-5-21-123-1001</UserId>"));
        assert!(xml.contains("<LogonType>InteractiveToken</LogonType>"));
    }

    #[test]
    fn dpapi_roundtrip_and_credential_format_are_compatible() {
        let directory = std::env::temp_dir().join(format!(
            "csu-rust-test-{}-{}",
            std::process::id(),
            Local::now().timestamp_nanos_opt().unwrap()
        ));
        let paths = test_paths(directory);
        fs::create_dir_all(&paths.state).unwrap();
        let credentials = Credentials {
            username: "test-user".into(),
            password: "test-only-中文".into(),
        };
        save_credentials(&paths, &credentials).unwrap();
        let bytes = fs::read(paths.credentials()).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains(&credentials.password));
        let stored: StoredCredentials = serde_json::from_slice(&bytes).unwrap();
        assert!(!stored.password_dpapi.is_empty());
        let loaded = load_credentials(&paths).unwrap();
        assert_eq!(loaded.username, credentials.username);
        assert_eq!(loaded.password, credentials.password);
        save_credentials(
            &paths,
            &Credentials {
                username: "replacement".into(),
                password: "new-test-only".into(),
            },
        )
        .unwrap();
        assert_eq!(load_credentials(&paths).unwrap().username, "replacement");
        fs::remove_file(paths.credentials()).unwrap();
        fs::remove_dir(&paths.state).unwrap();
        fs::remove_dir(&paths.directory).unwrap();
    }
}
