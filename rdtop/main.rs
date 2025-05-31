// main.rs

use tui::{
    backend::CrosstermBackend,
    Terminal,
    widgets::{Table, Row, Block, Borders},
    layout::Constraint,
};
use crossterm::event::{self, Event, KeyCode};
use std::{io, time::Duration};
use mysql::*;
use mysql::prelude::*;
use chrono::NaiveDateTime;

// Datenstruktur für einen Peer
#[derive(Debug)]
struct Peer {
    id: String,
    uuid: String,
    ip_addr: Option<String>,
    hostname: Option<String>,
    username: Option<String>,
    os: Option<String>,
    version: Option<String>,
    cpu: Option<String>,
    memory: Option<String>,
    last_seen: NaiveDateTime,
}

// Holt alle Peers aus der Datenbank
fn lade_peers_aus_db() -> Vec<Peer> {
    // <<< HIER DEINE DB-DATEN ANPASSEN! >>>
    let url = "mysql://yard-api-server:Doa/QYB[raz!dEXP@localhost/yard-api-server";
    let pool = Pool::new(url).expect("DB-Pool Fehler");
    let mut conn = pool.get_conn().expect("DB-Connect Fehler");

    conn.query_map(
        r"SELECT id, uuid, ip_addr, hostname, username, os, version, cpu, memory, last_seen FROM peers",
        |(id, uuid, ip_addr, hostname, username, os, version, cpu, memory, last_seen)| Peer {
            id,
            uuid,
            ip_addr,
            hostname,
            username,
            os,
            version,
            cpu,
            memory,
            last_seen,
        }
    ).expect("Fehler beim Query")
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let stdout = io::stdout();
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    loop {
        let peers = lade_peers_aus_db();

        terminal.draw(|f| {
            let size = f.size();

            let rows: Vec<Row> = peers.iter().map(|peer| {
                Row::new(vec![
                    peer.id.clone(),
                    peer.uuid.clone(),
                    peer.ip_addr.clone().unwrap_or("-".into()),
                    peer.hostname.clone().unwrap_or("-".into()),
                    peer.username.clone().unwrap_or("-".into()),
                    peer.os.clone().unwrap_or("-".into()),
                    peer.version.clone().unwrap_or("-".into()),
                    peer.cpu.clone().unwrap_or("-".into()),
                    peer.memory.clone().unwrap_or("-".into()),
                    peer.last_seen.to_string(),
                ])
            }).collect();

            let table = Table::new(rows)
                .header(Row::new(vec![
                    "ID", "UUID", "IP", "Host", "User", "OS", "Ver", "CPU", "RAM", "Last Seen"
                ]))
                .block(Block::default().title("Peers").borders(Borders::ALL))
                .widths(&[
                    Constraint::Length(10),
                    Constraint::Length(10),
                    Constraint::Length(15),
                    Constraint::Length(15),
                    Constraint::Length(10),
                    Constraint::Length(12),
                    Constraint::Length(8),
                    Constraint::Length(15),
                    Constraint::Length(8),
                    Constraint::Length(20),
                ]);
            f.render_widget(table, size);
        })?;

        // Taste abfragen oder 2 Sekunden warten
        if event::poll(Duration::from_secs(2))? {
            if let Event::Key(key) = event::read()? {
                if key.code == KeyCode::Char('q') {
                    break;
                }
            }
        }
    }
    Ok(())
}
