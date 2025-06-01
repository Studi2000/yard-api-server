use tui::{
    backend::CrosstermBackend,
    Terminal,
    widgets::{Table, Row, Block, Borders},
    layout::Constraint,
    style::{Style, Modifier, Color},
    widgets::Cell
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
use std::collections::HashMap;


// Data struct for a peer
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

#[derive(Debug)]
struct SessionEvent {
    event_type: String,
    uuid: String,
    viewer_ip: String,
    target_ip: String,
    target_id: Option<String>,
    event_time: String,
}

// Struct for displaying a summarized session (start/end/duration)
struct SessionSummary {
    uuid: String,
    start_time: String,
    end_time: String,
    duration: String,
    viewer_ip: String,
    target_ip: String,
    target_id: String,
    start_dt: NaiveDateTime,
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

/// Merge session events by UUID and calculate session durations
fn merge_sessions(events: &[SessionEvent], tz: &str, lang: &str) -> Vec<SessionSummary> {
    // Map for storing start events (uuid -> &SessionEvent)
    let mut start_map: HashMap<String, &SessionEvent> = HashMap::new();
    let mut summaries = Vec::new();

    for event in events {
        match event.event_type.as_str() {
            "start" => {
                // Store the start event in the map
                start_map.insert(event.uuid.clone(), event);
            }
            "end" => {
                // Try to find the matching start event by uuid
                if let Some(start_event) = start_map.remove(&event.uuid) {
                    // Parse datetime strings into NaiveDateTime
                    let start_dt = NaiveDateTime::parse_from_str(&start_event.event_time, "%Y-%m-%d %H:%M:%S").unwrap();
                    let end_dt = NaiveDateTime::parse_from_str(&event.event_time, "%Y-%m-%d %H:%M:%S").unwrap();
                    // Calculate duration between start and end
                    let duration = end_dt - start_dt;
                    let duration_str = format!(
                        "{:02}:{:02}:{:02}",
                        duration.num_hours(),
                        duration.num_minutes() % 60,
                        duration.num_seconds() % 60
                    );
                    // Add the summarized session to the result vector
                    summaries.push(SessionSummary {
                        uuid: event.uuid.clone(),
                        start_time: format_utc_to_local_with_tz(&start_event.event_time, tz, lang),
                        end_time: format_utc_to_local_with_tz(&event.event_time, tz, lang),
                        duration: duration_str,
                        viewer_ip: prettify_ip(&Some(event.viewer_ip.clone())),
                        target_ip: prettify_ip(&Some(event.target_ip.clone())),
                        target_id: event.target_id.clone().unwrap_or("-".to_string()),
                        start_dt,
                    });
                }
            }
            _ => {}
        }
    }
    summaries
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

// Select peers from database
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

/// Query the last N session events from the database, newest first
fn select_last_sessions(limit: u32) -> Vec<SessionEvent> {
    let url = load_db_url();
    let pool = Pool::new(url.as_str()).expect("DB-Pool error");
    let mut conn = pool.get_conn().expect("DB-Connect error");

    // Prepare and execute the SQL query, ordered by event_time descending
    let query = format!("SELECT event_type, uuid, viewer_ip, target_ip, target_id, event_time FROM session_events ORDER BY event_time ASC LIMIT {}", limit);

    // Map the result set into a vector of SessionEvent structs
    conn.query_map(
        query,
        |(event_type, uuid, viewer_ip, target_ip, target_id, event_time): (String, String, String, String, Option<String>, String)| {
            SessionEvent {
                event_type,
                uuid,
                viewer_ip,
                target_ip,
                target_id,
                event_time,
            }
        }
    ).expect("MySQL session_events query error!")
}

// Main TUI application loop
fn run_app<B: tui::backend::Backend>(
    terminal: &mut Terminal<B>,
    timezone: &str,
    language: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        // Query current peers and session events from the database
        let peers = select_peers();
        let last_sessions = select_last_sessions(100);

        // Merge session events by UUID into summarized sessions with duration
        let mut merged_sessions = merge_sessions(&last_sessions, timezone, language);

        // Sort merged sessions descending by end_time (newest first)
        merged_sessions.sort_by(|a, b| b.start_dt.cmp(&a.start_dt));

        // Only take the first 10 newest sessions for display
        let session_rows: Vec<Row> = merged_sessions.iter().take(10).map(|summary| {
            Row::new(vec![
                Cell::from(summary.start_time.clone()),
                Cell::from(summary.end_time.clone()),
                Cell::from(summary.duration.clone()).style(Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
                Cell::from(summary.viewer_ip.clone()),
                Cell::from(summary.target_ip.clone()),
                Cell::from(summary.target_id.clone()).style(Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
                Cell::from(summary.uuid.clone()),
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
                ]).style(tui::style::Style::default().add_modifier(tui::style::Modifier::REVERSED)))
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

            // Create the session durations table widget
            let session_table = Table::new(session_rows)
                .header(Row::new(vec![
                    "Start", "End", "Duration", "Viewer IP", "Target IP", "Target ID", "UUID"
                ]).style(tui::style::Style::default().add_modifier(tui::style::Modifier::REVERSED)))
                .block(Block::default().title("Session Durations").borders(Borders::ALL))
                .widths(&[
                    Constraint::Length(20),
                    Constraint::Length(20),
                    Constraint::Length(10),
                    Constraint::Length(21),
                    Constraint::Length(21),
                    Constraint::Length(10),
                    Constraint::Length(32),
                ]);

            // Render the widgets
            f.render_widget(table, chunks[0]);
            f.render_widget(session_table, chunks[1]);
        })?;

        // End condition: quit on 'q', otherwise refresh every 5 seconds
        const REFRESH_INTERVAL_SECS: u64 = 5;
        if event::poll(Duration::from_secs(REFRESH_INTERVAL_SECS))? {
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
