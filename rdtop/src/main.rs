use tui::{
    backend::CrosstermBackend,
    Terminal,
    widgets::{Table, Row, Block, Borders, Cell},
    layout::Constraint,
    style::{Style, Modifier, Color},
};
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use std::{io, time::Duration};
use mysql::*;
use mysql::prelude::*;
use dotenvy::from_path;
use std::env;
use chrono::{NaiveDateTime, Utc, TimeZone};
use chrono_tz::Tz;
use std::time::Instant;

// Struct for a peer (unchanged)
#[derive(Debug)]
struct Peer {
    id: String,
    ip_addr: Option<String>,
    hostname: Option<String>,
    username: Option<String>,
    os: Option<String>,
    version: Option<String>,
    cpu: Option<String>,
    memory: Option<String>,
    last_seen: String,
}

// Struct for a session (from new sessions table)
#[derive(Debug)]
struct Session {
    //id: i32,
    //uuid: String,
    start_time: String,
    end_time: String,
    viewer_id: String,
    viewer_name: String,
    target_id: String,
    //start_dt: NaiveDateTime,
}

// Get timezone from system, fallback UTC
fn get_system_timezone() -> String {
    env::var("TZ").unwrap_or_else(|_| "UTC".to_string())
}

// Get language/locale from system, fallback "en"
fn get_system_language() -> String {
    env::var("LC_TIME")
        .or_else(|_| env::var("LANG"))
        .map(|s| s.split('.').next().unwrap_or("en").to_string())
        .unwrap_or_else(|_| "en".to_string())
}

// Date format selection by language
fn datetime_format_for_language(lang: &str) -> &str {
    if lang.starts_with("de") {
        "%d.%m.%Y %H:%M:%S"
    } else if lang.starts_with("en_GB") {
        "%d/%m/%Y %H:%M:%S"
    } else if lang.starts_with("en") {
        "%m/%d/%Y %I:%M:%S %p"
    } else {
        "%Y-%m-%d %H:%M:%S"
    }
}

// Convert UTC datetime string to local with flexible format
fn format_utc_to_local_with_tz(utc_str: &str, tz_name: &str, lang: &str) -> String {
    if let Ok(naive_utc) = NaiveDateTime::parse_from_str(utc_str, "%Y-%m-%d %H:%M:%S") {
        let utc_dt = Utc.from_utc_datetime(&naive_utc);
        let tz: Tz = tz_name.parse().unwrap_or(chrono_tz::UTC);
        let local_time = utc_dt.with_timezone(&tz);
        let fmt = datetime_format_for_language(lang);
        local_time.format(fmt).to_string()
    } else {
        utc_str.to_string()
    }
}

// Helper to pretty-print IPv4-mapped IPv6 addresses and IP:Port combos
fn prettify_ip_str(ip: &str) -> String {
    if let Some(rest) = ip.strip_prefix("[::ffff:") {
        if let Some(end_bracket) = rest.find(']') {
            let ip_part = &rest[..end_bracket];
            return ip_part.to_string();
        }
    } else if let Some(rest) = ip.strip_prefix("::ffff:") {
        if let Some(colon) = rest.find(':') {
            return rest[..colon].to_string();
        } else {
            return rest.to_string();
        }
    }
    let stripped = ip.trim_start_matches('[').trim_end_matches(']');
    stripped.split(':').next().unwrap_or(stripped).to_string()
}

fn prettify_ip(opt: &Option<String>) -> String {
    if let Some(ip) = opt {
        prettify_ip_str(ip)
    } else {
        "-".to_string()
    }
}

// Load DB credentials from config
fn load_db_url() -> String {
    from_path("/etc/rdtop.conf").expect("/etc/rdtop.conf missing or not readable");

    let user = env::var("DB_USER").expect("DB_USER missing!");
    let pass_plain = env::var("DB_PASS").expect("DB_PASS missing!");
    let pass = urlencoding::encode(&pass_plain);
    let host = env::var("DB_HOST").unwrap_or("127.0.0.1".to_string());
    let port = env::var("DB_PORT").unwrap_or("3306".to_string());
    let name = env::var("DB_NAME").expect("DB_NAME missing!");

    format!("mysql://{user}:{pass}@{host}:{port}/{name}")
}

// Query all peers from database
fn select_peers() -> Vec<Peer> {
    let url = load_db_url();
    let pool = Pool::new(url.as_str()).expect("DB-Pool Error");
    let mut conn = pool.get_conn().expect("DB-Connect Error");

    conn.query_map(
        r"SELECT id, ip_addr, hostname, username, os, version, cpu, memory, last_seen FROM peers WHERE last_seen >= UTC_TIMESTAMP() - INTERVAL 10 MINUTE ORDER BY last_seen ASC",
        |(id, ip_addr, hostname, username, os, version, cpu, memory, last_seen): (String, Option<String>, Option<String>, Option<String>, Option<String>, Option<String>, Option<String>, Option<String>, String)| Peer {
            id,
            ip_addr,
            hostname,
            username,
            os,
            version,
            cpu,
            memory,
            last_seen,
        }
    ).expect("MySQL query error!")
}

// Query latest sessions from the new sessions table
fn select_sessions(limit: u32) -> Vec<Session> {
    let url = load_db_url();
    let pool = Pool::new(url.as_str()).expect("DB-Pool error");
    let mut conn = pool.get_conn().expect("DB-Connect error");

    let query = format!(
        "SELECT id, uuid, start_time, end_time, viewer_name, viewer_id, target_id FROM sessions ORDER BY start_time DESC LIMIT {}", limit);

    conn.query_map(
        query,
        |(_id, _uuid, start_time, end_time, viewer_name, viewer_id, target_id): (i32, String, String, String, String, String, String)| {
            Session {
                start_time,
                end_time,
                viewer_name,
                viewer_id,
                target_id,
            }
        }
    ).expect("MySQL sessions query error!")
}

// Calculate duration as HH:MM:SS from start_time and end_time
fn calc_duration(start: &str, end: &str) -> String {
    let s = NaiveDateTime::parse_from_str(start, "%Y-%m-%d %H:%M:%S");
    let e = NaiveDateTime::parse_from_str(end, "%Y-%m-%d %H:%M:%S");
    if let (Ok(s), Ok(e)) = (s, e) {
        let d = e - s;
        format!("{:02}:{:02}:{:02}", d.num_hours(), d.num_minutes() % 60, d.num_seconds() % 60)
    } else {
        "-".to_string()
    }
}

// Calculate dynamic duration for running session (live, UTC)
fn calc_dynamic_duration(start: &str) -> String {
    if let Ok(start_dt) = NaiveDateTime::parse_from_str(start, "%Y-%m-%d %H:%M:%S") {
        let now = Utc::now().naive_utc(); // <-- UTC, passend zur Datenbank
        let d = now - start_dt;
        format!("{:02}:{:02}:{:02}", d.num_hours(), d.num_minutes() % 60, d.num_seconds() % 60)
    } else {
        "-".to_string()
    }
}


// Main TUI application loop
fn run_app<B: tui::backend::Backend>(
    terminal: &mut Terminal<B>,
    timezone: &str,
    language: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut peers = select_peers();
    let mut sessions = select_sessions(20);
    let mut last_db_refresh = Instant::now();

    loop {
        // Refresh data from DB every 5 seconds
        if last_db_refresh.elapsed() >= Duration::from_secs(5) {
            peers = select_peers();
            sessions = select_sessions(20);
            last_db_refresh = Instant::now();
        }

        let session_rows: Vec<Row> = sessions.iter().map(|s| {
            let no_end = s.end_time.is_empty() || s.end_time == "0000-00-00 00:00:00";
            let display_end = if no_end {
                "-".to_string()
            } else {
                format_utc_to_local_with_tz(&s.end_time, timezone, language)
            };

            let (duration_str, duration_style, status_str, status_style) = if no_end {
                (
                    calc_dynamic_duration(&s.start_time),
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),  // Duration: red, bold, no blink
                    "RUNNING",
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD | Modifier::RAPID_BLINK),
                )
            } else {
                (
                    calc_duration(&s.start_time, &s.end_time),
                    Style::default().fg(Color::Green).add_modifier(Modifier::BOLD), // Duration: green, bold
                    "FINISHED",
                    Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                )
            };

            Row::new(vec![
                Cell::from(format_utc_to_local_with_tz(&s.start_time, timezone, language)),
                Cell::from(display_end),
                Cell::from(s.viewer_name.clone()),
                Cell::from(s.viewer_id.clone()),
                Cell::from(s.target_id.clone()),
                Cell::from(duration_str).style(duration_style),
                Cell::from(status_str).style(status_style),
            ])
        }).collect();


        terminal.draw(|f| {
            let size = f.size();

            // Split the layout vertically: 60% for peers, 40% for sessions
            let chunks = tui::layout::Layout::default()
                .direction(tui::layout::Direction::Vertical)
                .margin(1)
                .constraints([
                    tui::layout::Constraint::Percentage(60),
                    tui::layout::Constraint::Percentage(40)
                ].as_ref())
                .split(size);

            // Build table rows for peers
            let peer_rows: Vec<Row> = peers.iter().map(|peer| {
                Row::new(vec![
                    Cell::from(format_utc_to_local_with_tz(&peer.last_seen, timezone, language)),
                    Cell::from(peer.id.clone()).style(Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
                    Cell::from(prettify_ip(&peer.ip_addr)),
                    Cell::from(peer.hostname.clone().unwrap_or("-".into())),
                    Cell::from(peer.username.clone().unwrap_or("-".into())),
                    Cell::from(peer.os.clone().unwrap_or("-".into())),
                    Cell::from(peer.version.clone().unwrap_or("-".into())),
                    Cell::from(peer.cpu.clone().unwrap_or("-".into())),
                    Cell::from(peer.memory.clone().unwrap_or("-".into())),
                ])
            }).collect();

            // Create the peers table widget
            let table = Table::new(peer_rows)
                .header(Row::new(vec![
                    "Last Seen", "ID", "IP-ADDR", "Host", "User", "OS", "Ver", "CPU", "RAM"
                ]).style(Style::default().add_modifier(Modifier::REVERSED)))
                .block(Block::default().title("Active peers (last 10 minutes)").borders(Borders::ALL))
                .widths(&[
                    Constraint::Length(20),
                    Constraint::Length(10),
                    Constraint::Length(21),
                    Constraint::Length(20),
                    Constraint::Length(20),
                    Constraint::Length(30),
                    Constraint::Length(8),
                    Constraint::Length(80),
                    Constraint::Length(8),
                ]);

            // Create the sessions table widget
            let session_table = Table::new(session_rows)
                .header(Row::new(vec![
                    "Start", "End", "Viewer Name", "Viewer ID", "Target ID", "Duration", "Status"
                ]).style(Style::default().add_modifier(Modifier::REVERSED)))
                .block(Block::default().title("Last 20 Sessions").borders(Borders::ALL))
                .widths(&[
                    Constraint::Length(20),
                    Constraint::Length(20),
                    Constraint::Length(16),
                    Constraint::Length(12),
                    Constraint::Length(10),
                    Constraint::Length(10),
                    Constraint::Length(10),
                ]);

            // Render the widgets
            f.render_widget(table, chunks[0]);
            f.render_widget(session_table, chunks[1]);
        })?;

        // End condition: quit on 'q', otherwise refresh/redraw every second
        if event::poll(Duration::from_secs(1))? {
            if let Event::Key(key) = event::read()? {
                if key.code == KeyCode::Char('q') {
                    break;
                }
            }
        }
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    from_path("/etc/rdtop.conf").ok();

    let timezone = get_system_timezone();
    let language = get_system_language();

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let res = run_app(&mut terminal, &timezone, &language);

    disable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, LeaveAlternateScreen)?;

    println!("Loaded timezone: {}", &timezone);
    println!("Loaded language: {}", &language);

    if let Err(err) = res {
        eprintln!("Error: {err:?}");
    }

    Ok(())
}
