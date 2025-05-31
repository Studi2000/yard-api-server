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

fn prettify_ip(opt: &Option<String>) -> String {
    if let Some(ip) = opt {
        if let Some(stripped) = ip.strip_prefix("::ffff:") {
            // Return only IPv4 part
            stripped.to_string()
        } else {
            ip.clone()
        }
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
        r"SELECT id, ip_addr, hostname, username, os, version, cpu, memory, last_seen FROM peers WHERE last_seen >= UTC_TIMESTAMP() - INTERVAL 30 MINUTE ORDER BY last_seen ASC",
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

// Main TUI app loop
fn run_app<B: tui::backend::Backend>(terminal: &mut Terminal<B>) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        let peers = select_peers();

        terminal.draw(|f| {
            let size = f.size();

            let locale = std::env::var("LOCALE").unwrap_or("UTC".to_string());
            let rows: Vec<Row> = peers.iter().map(|peer| {
                Row::new(vec![
                    peer.id.clone(),
                    //peer.uuid.clone(),
                    prettify_ip(&peer.ip_addr),
                    peer.hostname.clone().unwrap_or("-".into()),
                    peer.username.clone().unwrap_or("-".into()),
                    peer.os.clone().unwrap_or("-".into()),
                    peer.version.clone().unwrap_or("-".into()),
                    peer.cpu.clone().unwrap_or("-".into()),
                    peer.memory.clone().unwrap_or("-".into()),
                    format_utc_to_local_with_tz(&peer.last_seen, &locale),
                ])
            }).collect();

            let table = Table::new(rows)
                .header(Row::new(vec![
                    "ID", "IP-ADDR", "Host", "User", "OS", "Ver", "CPU", "RAM", "Last Seen"
                ]))
                .block(Block::default().title("Peers").borders(Borders::ALL))
                .widths(&[
                    Constraint::Length(10),
                    Constraint::Length(18),
                    Constraint::Length(10),
                    Constraint::Length(10),
                    Constraint::Length(25),
                    Constraint::Length(8),
                    Constraint::Length(60),
                    Constraint::Length(8),
                    Constraint::Length(20),
                ]);
            f.render_widget(table, size);
        })?;

        // End condition: quit on 'q', else refresh every 2 seconds
        if event::poll(Duration::from_secs(5))? {
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
