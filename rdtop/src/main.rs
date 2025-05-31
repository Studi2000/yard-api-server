use tui::{
    backend::CrosstermBackend,
    Terminal,
    widgets::{Table, Row, Block, Borders},
    layout::Constraint,
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

// Data struct for a peer
#[derive(Debug)]
struct Peer {
    id: String,
    //uuid: String,
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
    viewer_ip: String,
    target_ip: String,
    target_id: Option<String>,
    event_time: String,
}

/// Converts UTC datetime string to a given local time zone
fn format_utc_to_local_with_tz(utc_str: &str, tz_name: &str) -> String {
    // Parse the input string "YYYY-MM-DD HH:MM:SS"
    if let Ok(naive_utc) = NaiveDateTime::parse_from_str(utc_str, "%Y-%m-%d %H:%M:%S") {
        // Interpret as UTC
        let utc_dt = Utc.from_utc_datetime(&naive_utc);

        // Try to parse the timezone string, default to UTC on error
        let tz: Tz = tz_name.parse().unwrap_or(chrono_tz::UTC);

        // Convert to the target local time zone
        let local_time = utc_dt.with_timezone(&tz);

        // Format e.g. "31.05.2025 21:27:01"
        local_time.format("%d.%m.%Y %H:%M:%S").to_string()
    } else {
        // Fallback: return as is
        utc_str.to_string()
    }
}

// Load DB credentials from config
fn load_db_url() -> String {
    // Load config, panic on error
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
    // Case: [::ffff:192.168.120.90]:54268
    if let Some(rest) = ip.strip_prefix("[::ffff:") {
        if let Some(end_bracket) = rest.find(']') {
            let ip_part = &rest[..end_bracket];
            return ip_part.to_string();
        }
    } else if let Some(rest) = ip.strip_prefix("::ffff:") {
        // Case: ::ffff:192.168.120.90:PORT
        if let Some(colon) = rest.find(':') {
            return rest[..colon].to_string();
        } else {
            return rest.to_string();
        }
    }
    // Default: remove [ ] and port if present
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
        r"SELECT id, ip_addr, hostname, username, os, version, cpu, memory, last_seen FROM peers WHERE last_seen >= UTC_TIMESTAMP() - INTERVAL 3000 MINUTE ORDER BY last_seen ASC",
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

fn select_last_sessions() -> Vec<SessionEvent> {
    let url = load_db_url();
    let pool = Pool::new(url.as_str()).expect("DB-Pool Error");
    let mut conn = pool.get_conn().expect("DB-Connect Error");

    conn.query_map(
        "SELECT event_type, viewer_ip, target_ip, target_id, event_time FROM session_events ORDER BY event_time DESC LIMIT 10",
        |(event_type, viewer_ip, target_ip, target_id, event_time): (String, String, String, Option<String>, String)| SessionEvent {
            event_type,
            viewer_ip,
            target_ip,
            target_id,
            event_time,
        }
    ).expect("MySQL session_events query error!")
}

// Main TUI app loop
fn run_app<B: tui::backend::Backend>(terminal: &mut Terminal<B>) -> Result<(), Box<dyn std::error::Error>> {
    // Read locale from env (from /etc/rdtop.conf)
    let locale = std::env::var("LOCALE").unwrap_or("UTC".to_string());
    loop {
        let peers = select_peers();
        let last_sessions = select_last_sessions();

        terminal.draw(|f| {
            let size = f.size();

            // Layout: split vertically (50% peers, 50% sessions)
            let chunks = tui::layout::Layout::default()
                .direction(tui::layout::Direction::Vertical)
                .margin(1)
                .constraints([
                    tui::layout::Constraint::Percentage(50),
                    tui::layout::Constraint::Percentage(50)
                ].as_ref())
                .split(size);

            // Peers table
            let peer_rows: Vec<Row> = peers.iter().map(|peer| {
                Row::new(vec![
                    format_utc_to_local_with_tz(&peer.last_seen, &locale),
                    peer.id.clone(),
                    prettify_ip(&peer.ip_addr),
                    peer.hostname.clone().unwrap_or("-".into()),
                    peer.username.clone().unwrap_or("-".into()),
                    peer.os.clone().unwrap_or("-".into()),
                    peer.version.clone().unwrap_or("-".into()),
                    peer.cpu.clone().unwrap_or("-".into()),
                    peer.memory.clone().unwrap_or("-".into()),

                ])
            }).collect();

            let table = Table::new(peer_rows)
                .header(Row::new(vec![
                    "Last Seen", "ID", "IP-ADDR", "Host", "User", "OS", "Ver", "CPU", "RAM"
                ]).style(tui::style::Style::default().add_modifier(tui::style::Modifier::REVERSED)))
                .block(Block::default().title("Peers").borders(Borders::ALL))
                .widths(&[
                    Constraint::Length(20),
                    Constraint::Length(10),
                    Constraint::Length(35),
                    Constraint::Length(20),
                    Constraint::Length(20),
                    Constraint::Length(30),
                    Constraint::Length(8),
                    Constraint::Length(70),
                    Constraint::Length(8),

                ]);

            // Sessions table (Event Time nach vorne!)
            let session_rows: Vec<Row> = last_sessions.iter().map(|event| {
                Row::new(vec![
                    format_utc_to_local_with_tz(&event.event_time, &locale),
                    event.event_type.clone(),
                    prettify_ip(&Some(event.viewer_ip.clone())),
                    prettify_ip(&Some(event.target_ip.clone())),
                    event.target_id.clone().unwrap_or("-".to_string()),
                ])
            }).collect();

            let session_table = Table::new(session_rows)
                .header(Row::new(vec![
                    "Event Time", "Type", "Viewer IP", "Target IP", "Target ID"
                ]).style(tui::style::Style::default().add_modifier(tui::style::Modifier::REVERSED)))
                .block(Block::default().title("Last 10 Sessions").borders(Borders::ALL))
                .widths(&[
                    Constraint::Length(20),
                    Constraint::Length(8),
                    Constraint::Length(35),
                    Constraint::Length(35),
                    Constraint::Length(10),
                ]);

            f.render_widget(table, chunks[0]);
            f.render_widget(session_table, chunks[1]);
        })?;

        // End condition: quit on 'q', else refresh every 5 seconds
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
    // Setup terminal in raw mode & alternate screen
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let res = run_app(&mut terminal);

    // Always restore terminal
    disable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, LeaveAlternateScreen)?;

    if let Err(err) = res {
        eprintln!("Error: {err:?}");
    }

    Ok(())
}
