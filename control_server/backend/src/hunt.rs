use serde::Serialize;
use sqlx::{Row, SqlitePool};
use zedr_protocol::{InventoryAction, PackageManager, PersistenceKind, ProcessAction, SystemEvent};
use utoipa::ToSchema;

use crate::detections::Described;
use crate::error::Result;

const ROW_LIMIT: i64 = 500;
const ENDPOINT_LIMIT: i64 = 200;
const QUERY_LIMIT: usize = 4000;
const DEPTH_LIMIT: usize = 32;
const KINDS: &str = "Start with process, connection, file, detection, package or persistence";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Entity {
    Process,
    Connection,
    File,
    Detection,
    Package,
    Persistence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Text(String),
    Number(i64),
    Flag(bool),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Eq,
    Ne,
    Contains,
    NotContains,
    Gt,
    Ge,
    Lt,
    Le,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    Compare { field: String, op: Op, value: Value, at: usize },
    In { field: String, values: Vec<Value>, at: usize },
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    pub entity: Entity,
    pub filter: Expr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryError {
    pub message: String,
    pub column: usize,
}

fn fail<T>(message: impl Into<String>, column: usize) -> std::result::Result<T, QueryError> {
    Err(QueryError { message: message.into(), column })
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Word(String),
    Text(String),
    Number(i64),
    Symbol(&'static str),
}

fn tokenize(source: &str) -> std::result::Result<Vec<(Token, usize)>, QueryError> {
    let chars: Vec<char> = source.chars().collect();
    let mut tokens = Vec::new();
    let mut at = 0;
    while at < chars.len() {
        let start = at;
        let current = chars[at];
        if current.is_whitespace() {
            at += 1;
        } else if current == '"' || current == '\'' {
            at += 1;
            let mut text = String::new();
            loop {
                match chars.get(at) {
                    None => return fail("This string is never closed", start + 1),
                    Some(next) if *next == current => break,
                    Some(next) => {
                        text.push(*next);
                        at += 1;
                    }
                }
            }
            at += 1;
            tokens.push((Token::Text(text), start + 1));
        } else if current.is_alphanumeric() || current == '_' {
            while chars.get(at).is_some_and(|next| next.is_alphanumeric() || matches!(next, '_' | '.' | '-' | '/' | ':')) {
                at += 1;
            }
            let word: String = chars[start..at].iter().collect();
            if word.chars().all(|digit| digit.is_ascii_digit()) {
                match word.parse() {
                    Ok(number) => tokens.push((Token::Number(number), start + 1)),
                    Err(_) => return fail("This number is too large", start + 1),
                }
            } else {
                tokens.push((Token::Word(word), start + 1));
            }
        } else {
            let pair: String = chars[at..(at + 2).min(chars.len())].iter().collect();
            let symbol = ["!=", "!~", ">=", "<="]
                .into_iter()
                .find(|symbol| *symbol == pair)
                .or_else(|| ["=", "~", ">", "<", "(", ")", ","].into_iter().find(|symbol| symbol.starts_with(current)));
            match symbol {
                Some(symbol) => {
                    at += symbol.len();
                    tokens.push((Token::Symbol(symbol), start + 1));
                }
                None => return fail(format!("Unexpected character {}", current), start + 1),
            }
        }
    }
    Ok(tokens)
}

struct Parser {
    tokens: Vec<(Token, usize)>,
    at: usize,
    end: usize,
    depth: usize,
}

impl Parser {
    fn column(&self) -> usize {
        self.tokens.get(self.at).map(|(_, column)| *column).unwrap_or(self.end)
    }

    fn word(&self, expected: &str) -> bool {
        matches!(self.tokens.get(self.at), Some((Token::Word(word), _)) if word.eq_ignore_ascii_case(expected))
    }

    fn symbol(&self, expected: &str) -> bool {
        matches!(self.tokens.get(self.at), Some((Token::Symbol(symbol), _)) if *symbol == expected)
    }

    fn expression(&mut self) -> std::result::Result<Expr, QueryError> {
        let mut left = self.conjunction()?;
        while self.word("or") {
            self.at += 1;
            left = Expr::Or(Box::new(left), Box::new(self.conjunction()?));
        }
        Ok(left)
    }

    fn conjunction(&mut self) -> std::result::Result<Expr, QueryError> {
        let mut left = self.factor()?;
        while self.word("and") {
            self.at += 1;
            left = Expr::And(Box::new(left), Box::new(self.factor()?));
        }
        Ok(left)
    }

    fn descend(&mut self) -> std::result::Result<(), QueryError> {
        self.depth += 1;
        if self.depth > DEPTH_LIMIT {
            return fail(format!("A query can nest at most {} levels", DEPTH_LIMIT), self.column());
        }
        self.at += 1;
        Ok(())
    }

    fn factor(&mut self) -> std::result::Result<Expr, QueryError> {
        if self.word("not") {
            self.descend()?;
            let inner = self.factor()?;
            self.depth -= 1;
            return Ok(Expr::Not(Box::new(inner)));
        }
        if self.symbol("(") {
            self.descend()?;
            let inner = self.expression()?;
            if !self.symbol(")") {
                return fail("Expected a closing bracket", self.column());
            }
            self.at += 1;
            self.depth -= 1;
            return Ok(inner);
        }

        let at = self.column();
        let field = match self.tokens.get(self.at) {
            Some((Token::Word(word), _)) => word.to_lowercase(),
            _ => return fail("Expected a field name", at),
        };
        self.at += 1;

        if self.word("in") {
            self.at += 1;
            if !self.symbol("(") {
                return fail("Expected a list in brackets after in", self.column());
            }
            self.at += 1;
            let mut values = vec![self.value()?];
            while self.symbol(",") {
                self.at += 1;
                values.push(self.value()?);
            }
            if !self.symbol(")") {
                return fail("Expected a closing bracket", self.column());
            }
            self.at += 1;
            return Ok(Expr::In { field, values, at });
        }

        let op = match self.tokens.get(self.at) {
            Some((Token::Symbol("="), _)) => Op::Eq,
            Some((Token::Symbol("!="), _)) => Op::Ne,
            Some((Token::Symbol("~"), _)) => Op::Contains,
            Some((Token::Symbol("!~"), _)) => Op::NotContains,
            Some((Token::Symbol(">"), _)) => Op::Gt,
            Some((Token::Symbol(">="), _)) => Op::Ge,
            Some((Token::Symbol("<"), _)) => Op::Lt,
            Some((Token::Symbol("<="), _)) => Op::Le,
            _ => return fail("Expected a comparison: =, !=, ~, !~, >, >=, <, <= or in", self.column()),
        };
        self.at += 1;
        Ok(Expr::Compare { field, op, value: self.value()?, at })
    }

    fn value(&mut self) -> std::result::Result<Value, QueryError> {
        let value = match self.tokens.get(self.at) {
            Some((Token::Text(text), _)) => Value::Text(text.clone()),
            Some((Token::Number(number), _)) => Value::Number(*number),
            Some((Token::Word(word), _)) if word.eq_ignore_ascii_case("true") => Value::Flag(true),
            Some((Token::Word(word), _)) if word.eq_ignore_ascii_case("false") => Value::Flag(false),
            Some((Token::Word(word), _)) => Value::Text(word.clone()),
            _ => return fail("Expected a value", self.column()),
        };
        self.at += 1;
        Ok(value)
    }
}

pub fn parse(source: &str) -> std::result::Result<Query, QueryError> {
    let length = source.chars().count();
    if length > QUERY_LIMIT {
        return fail(format!("A query can be at most {} characters", QUERY_LIMIT), QUERY_LIMIT + 1);
    }
    let tokens = tokenize(source)?;
    let mut parser = Parser { tokens, at: 0, end: length + 1, depth: 0 };

    let entity = match parser.tokens.first() {
        Some((Token::Word(word), _)) => match word.to_lowercase().as_str() {
            "process" => Entity::Process,
            "connection" => Entity::Connection,
            "file" => Entity::File,
            "detection" => Entity::Detection,
            "package" => Entity::Package,
            "persistence" => Entity::Persistence,
            _ => return fail(KINDS, 1),
        },
        _ => return fail(KINDS, 1),
    };
    parser.at = 1;

    if !parser.word("where") {
        return fail("Expected where after the kind of record", parser.column());
    }
    parser.at += 1;
    let filter = parser.expression()?;
    if parser.at < parser.tokens.len() {
        return fail("Expected and, or, or the end of the query", parser.column());
    }
    Ok(Query { entity, filter })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Text,
    Number,
    Flag,
    Version,
}

struct Field {
    name: &'static str,
    sql: &'static str,
    kind: Kind,
}

const fn text(name: &'static str, sql: &'static str) -> Field {
    Field { name, sql, kind: Kind::Text }
}

const fn number(name: &'static str, sql: &'static str) -> Field {
    Field { name, sql, kind: Kind::Number }
}

const HOST: [Field; 3] = [text("host", "a.hostname"), text("host.ip", "a.ip_address"), text("host.platform", "a.platform")];

const PROCESS: &[Field] = &[
    text("name", "r.name"),
    text("path", "r.path"),
    text("command", "r.command"),
    number("pid", "r.pid"),
    number("user", "r.uid"),
    number("started", "r.started_at"),
    Field { name: "running", sql: "(r.ended_at IS NULL)", kind: Kind::Flag },
    text("parent.name", "r.parent_name"),
    text("parent.path", "r.parent_path"),
    number("parent.pid", "r.parent_pid"),
    text("grandparent.name", "r.grandparent_name"),
];
const CONNECTION: &[Field] = &[
    text("process.name", "r.process_name"),
    number("pid", "r.pid"),
    text("dest.ip", "r.dest_ip"),
    number("dest.port", "r.dest_port"),
    text("protocol", "r.protocol"),
    number("bytes", "r.bytes"),
    number("time", "r.at"),
];
const FILE: &[Field] = &[
    text("path", "r.path"),
    text("action", "r.action"),
    text("process.name", "r.process_name"),
    number("pid", "r.pid"),
    number("time", "r.at"),
];
const DETECTION: &[Field] = &[
    text("rule", "json_extract(r.data, '$.rule')"),
    text("technique", "json_extract(r.data, '$.technique')"),
    text("level", "json_extract(r.data, '$.level')"),
    text("image", "json_extract(r.data, '$.image')"),
    text("command", "json_extract(r.data, '$.command')"),
    text("parent", "json_extract(r.data, '$.parent')"),
    number("time", "r.timestamp"),
];
const PACKAGE: &[Field] = &[
    text("name", "r.name"),
    Field { name: "version", sql: "r.version", kind: Kind::Version },
    text("manager", "r.manager"),
    text("arch", "r.architecture"),
    text("previous", "r.previous_version"),
    number("time", "r.seen_at"),
];
const PERSISTENCE: &[Field] = &[
    text("kind", "r.kind"),
    text("name", "r.name"),
    text("path", "r.path"),
    text("command", "r.command"),
    text("user", "r.user"),
    Field { name: "enabled", sql: "(r.enabled = 1)", kind: Kind::Flag },
    text("hash", "r.hash"),
    number("time", "r.seen_at"),
];

struct Shape {
    name: &'static str,
    fields: &'static [Field],
    from: &'static str,
    time: &'static str,
    process: &'static str,
    columns: &'static [&'static str],
    cells: &'static [&'static str],
}

fn shape(entity: Entity) -> Shape {
    match entity {
        Entity::Process => Shape {
            name: "process",
            fields: PROCESS,
            from: "hunt_processes r JOIN agents a ON a.id = r.agent_id WHERE 1 = 1",
            time: "r.started_at",
            process: "r.pid || '@' || r.started_at",
            columns: &["process", "parent", "command", "pid", "user"],
            cells: &["r.name", "COALESCE(r.parent_name, '')", "r.command", "r.pid", "r.uid"],
        },
        Entity::Connection => Shape {
            name: "connection",
            fields: CONNECTION,
            from: "hunt_connections r JOIN agents a ON a.id = r.agent_id WHERE 1 = 1",
            time: "r.at",
            process: "CASE WHEN r.process_started_at IS NULL THEN NULL ELSE r.pid || '@' || r.process_started_at END",
            columns: &["process", "destination", "protocol", "bytes"],
            cells: &["COALESCE(r.process_name, '')", "r.dest_ip || ':' || r.dest_port", "r.protocol", "r.bytes"],
        },
        Entity::File => Shape {
            name: "file",
            fields: FILE,
            from: "hunt_files r JOIN agents a ON a.id = r.agent_id WHERE 1 = 1",
            time: "r.at",
            process: "CASE WHEN r.process_started_at IS NULL THEN NULL ELSE r.pid || '@' || r.process_started_at END",
            columns: &["process", "action", "path"],
            cells: &["COALESCE(r.process_name, '')", "r.action", "r.path"],
        },
        Entity::Detection => Shape {
            name: "detection",
            fields: DETECTION,
            from: "events r JOIN agents a ON a.id = r.agent_id WHERE r.event_type = 'detection'",
            time: "r.timestamp",
            process: "json_extract(r.data, '$.pid') || '@' || json_extract(r.data, '$.started_at')",
            columns: &["finding", "technique", "level", "image"],
            cells: &[
                "json_extract(r.data, '$.title')",
                "json_extract(r.data, '$.technique')",
                "json_extract(r.data, '$.level')",
                "json_extract(r.data, '$.image')",
            ],
        },
        Entity::Package => Shape {
            name: "package",
            fields: PACKAGE,
            from: "hunt_packages r JOIN agents a ON a.id = r.agent_id WHERE 1 = 1",
            time: "r.seen_at",
            process: "NULL",
            columns: &["package", "version", "was", "manager", "arch"],
            cells: &["r.name", "r.version", "COALESCE(r.previous_version, '')", "r.manager", "r.architecture"],
        },
        Entity::Persistence => Shape {
            name: "persistence",
            fields: PERSISTENCE,
            from: "hunt_persistence r JOIN agents a ON a.id = r.agent_id WHERE 1 = 1",
            time: "r.seen_at",
            process: "NULL",
            columns: &["item", "kind", "command", "path", "user"],
            cells: &["r.name", "r.kind", "r.command", "r.path", "r.user"],
        },
    }
}

fn lookup(entity: Entity, name: &str, at: usize) -> std::result::Result<&'static Field, QueryError> {
    let shape = shape(entity);
    if let Some(field) = shape.fields.iter().chain(HOST.iter()).find(|field| field.name == name) {
        return Ok(field);
    }
    let known: Vec<&str> = shape.fields.iter().chain(HOST.iter()).map(|field| field.name).collect();
    fail(format!("{} has no field {}. Fields: {}", shape.name, name, known.join(", ")), at)
}

const VERSION_TILDE: u8 = 0x01;
const VERSION_END: u8 = 0x02;
const PRE_RELEASE: [(&str, &str); 4] = [("_alpha", "~alpha"), ("_beta", "~beta"), ("_pre", "~pre"), ("_rc", "~rc")];

fn version_number(key: &mut Vec<u8>, digits: &str) {
    let significant = digits.trim_start_matches('0');
    key.push(significant.len().min(usize::from(u8::MAX)) as u8);
    key.extend_from_slice(significant.as_bytes());
}

/// A text key whose byte order is the order of the versions: numbers by value, a tilde or a pre-release suffix before the release, letters before punctuation, an epoch first
pub fn version_key(version: &str) -> String {
    let trimmed = version.trim();
    let (epoch, rest) = match trimmed.split_once(':') {
        Some((epoch, rest)) if !epoch.is_empty() && epoch.bytes().all(|byte| byte.is_ascii_digit()) => (epoch, rest),
        _ => ("", trimmed),
    };
    let mut rest = rest.to_string();
    for (suffix, ordered) in PRE_RELEASE {
        rest = rest.replace(suffix, ordered);
    }

    let mut key = Vec::new();
    version_number(&mut key, epoch);
    let mut remaining = rest.as_str();
    loop {
        let split = remaining.find(|current: char| current.is_ascii_digit()).unwrap_or(remaining.len());
        for current in remaining[..split].chars() {
            key.push(match current {
                '~' => VERSION_TILDE,
                letter if letter.is_ascii_alphabetic() => letter as u8,
                other if other.is_ascii() => other as u8 | 0x80,
                _ => u8::MAX,
            });
        }
        key.push(VERSION_END);
        remaining = &remaining[split..];
        if remaining.is_empty() {
            break;
        }
        let split = remaining.find(|current: char| !current.is_ascii_digit()).unwrap_or(remaining.len());
        version_number(&mut key, &remaining[..split]);
        remaining = &remaining[split..];
    }
    key.iter().map(|byte| format!("{:02x}", byte)).collect()
}

fn manager_name(manager: PackageManager) -> &'static str {
    match manager {
        PackageManager::Dpkg => "dpkg",
        PackageManager::Apk => "apk",
    }
}

pub fn kind_name(kind: PersistenceKind) -> &'static str {
    match kind {
        PersistenceKind::SystemdUnit => "systemd_unit",
        PersistenceKind::SystemdTimer => "systemd_timer",
        PersistenceKind::Cron => "cron",
        PersistenceKind::ShellProfile => "shell_profile",
        PersistenceKind::AuthorizedKey => "authorized_key",
        PersistenceKind::LdPreload => "ld_preload",
        PersistenceKind::RcLocal => "rc_local",
        PersistenceKind::InitScript => "init_script",
    }
}

fn like(text: &str) -> Value {
    let escaped = text.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_");
    Value::Text(format!("%{}%", escaped))
}

fn compile(entity: Entity, expr: &Expr, binds: &mut Vec<Value>) -> std::result::Result<String, QueryError> {
    match expr {
        Expr::And(left, right) => Ok(format!("({} AND {})", compile(entity, left, binds)?, compile(entity, right, binds)?)),
        Expr::Or(left, right) => Ok(format!("({} OR {})", compile(entity, left, binds)?, compile(entity, right, binds)?)),
        Expr::Not(inner) => Ok(format!("(NOT {})", compile(entity, inner, binds)?)),
        Expr::In { field, values, at } => {
            let at = *at;
            let found = lookup(entity, field, at)?;
            let mut slots = Vec::new();
            for value in values {
                match (found.kind, value) {
                    (Kind::Text | Kind::Version, Value::Text(_)) | (Kind::Number, Value::Number(_)) => binds.push(value.clone()),
                    (Kind::Text | Kind::Version, Value::Number(number)) => binds.push(Value::Text(number.to_string())),
                    _ => return fail(format!("The list for {} mixes values of the wrong kind", found.name), at),
                }
                slots.push("?");
            }
            let collation = if matches!(found.kind, Kind::Text | Kind::Version) { " COLLATE NOCASE" } else { "" };
            Ok(format!("({}{} IN ({}))", found.sql, collation, slots.join(", ")))
        }
        Expr::Compare { field, op, value, at } => {
            let at = *at;
            let found = lookup(entity, field, at)?;
            match (found.kind, value) {
                (Kind::Flag, Value::Flag(wanted)) if matches!(op, Op::Eq | Op::Ne) => {
                    let wanted = *wanted == matches!(op, Op::Eq);
                    Ok(if wanted { found.sql.to_string() } else { format!("(NOT {})", found.sql) })
                }
                (Kind::Flag, _) => fail(format!("{} is true or false, compare it with = or !=", found.name), at),
                (Kind::Number, Value::Number(_)) => {
                    let symbol = match op {
                        Op::Eq => "=",
                        Op::Ne => "!=",
                        Op::Gt => ">",
                        Op::Ge => ">=",
                        Op::Lt => "<",
                        Op::Le => "<=",
                        Op::Contains | Op::NotContains => return fail(format!("{} is a number, ~ works on text", found.name), at),
                    };
                    binds.push(value.clone());
                    Ok(format!("({} {} ?)", found.sql, symbol))
                }
                (Kind::Number, _) => fail(format!("{} is a number", found.name), at),
                (Kind::Text | Kind::Version, Value::Flag(_)) => fail(format!("{} is text", found.name), at),
                (Kind::Text | Kind::Version, value) => {
                    let wanted = match value {
                        Value::Number(number) => number.to_string(),
                        Value::Text(text) => text.clone(),
                        Value::Flag(_) => String::new(),
                    };
                    match op {
                        Op::Eq => {
                            binds.push(Value::Text(wanted));
                            Ok(format!("({} = ? COLLATE NOCASE)", found.sql))
                        }
                        Op::Ne => {
                            binds.push(Value::Text(wanted));
                            Ok(format!("({sql} IS NULL OR {sql} != ? COLLATE NOCASE)", sql = found.sql))
                        }
                        Op::Contains => {
                            binds.push(like(&wanted));
                            Ok(format!("({} LIKE ? ESCAPE '\\')", found.sql))
                        }
                        Op::NotContains => {
                            binds.push(like(&wanted));
                            Ok(format!("({sql} IS NULL OR {sql} NOT LIKE ? ESCAPE '\\')", sql = found.sql))
                        }
                        Op::Gt | Op::Ge | Op::Lt | Op::Le if found.kind == Kind::Version => {
                            let symbol = match op {
                                Op::Gt => ">",
                                Op::Ge => ">=",
                                Op::Lt => "<",
                                _ => "<=",
                            };
                            binds.push(Value::Text(version_key(&wanted)));
                            Ok(format!("({}_key {} ?)", found.sql, symbol))
                        }
                        Op::Gt | Op::Ge | Op::Lt | Op::Le => fail(format!("{} is text, use =, !=, ~ or !~", found.name), at),
                    }
                }
            }
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct HuntEntity {
    pub name: String,
    pub fields: Vec<String>,
}

pub fn entities() -> Vec<HuntEntity> {
    [Entity::Process, Entity::Connection, Entity::File, Entity::Detection, Entity::Package, Entity::Persistence]
        .into_iter()
        .map(|entity| {
            let shape = shape(entity);
            HuntEntity {
                name: shape.name.to_string(),
                fields: shape.fields.iter().chain(HOST.iter()).map(|field| field.name.to_string()).collect(),
            }
        })
        .collect()
}

#[derive(Debug, Serialize, ToSchema)]
pub struct HuntRow {
    pub agent_id: String,
    pub hostname: String,
    pub time: i64,
    pub process: Option<String>,
    pub cells: Vec<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct HuntEndpoint {
    pub agent_id: String,
    pub hostname: String,
    pub matches: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct HuntResult {
    pub entity: String,
    pub columns: Vec<String>,
    pub rows: Vec<HuntRow>,
    pub endpoints: Vec<HuntEndpoint>,
    pub total: i64,
}

fn bound<'q>(sql: &'q str, binds: &[Value]) -> sqlx::query::Query<'q, sqlx::Sqlite, sqlx::sqlite::SqliteArguments<'q>> {
    let mut query = sqlx::query(sql);
    for value in binds {
        query = match value {
            Value::Text(text) => query.bind(text.clone()),
            Value::Number(number) => query.bind(*number),
            Value::Flag(flag) => query.bind(*flag),
        };
    }
    query
}

pub async fn run(pool: &SqlitePool, query: &Query) -> Result<std::result::Result<HuntResult, QueryError>> {
    let shape = shape(query.entity);
    let mut binds = Vec::new();
    let filter = match compile(query.entity, &query.filter, &mut binds) {
        Ok(filter) => filter,
        Err(error) => return Ok(Err(error)),
    };

    let cells: Vec<String> = shape.cells.iter().map(|cell| format!("CAST({} AS TEXT)", cell)).collect();
    let rows_sql = format!(
        "SELECT r.agent_id, a.hostname, {time}, {process}, {cells} FROM {from} AND {filter} ORDER BY {time} DESC LIMIT {limit}",
        time = shape.time,
        process = shape.process,
        cells = cells.join(", "),
        from = shape.from,
        filter = filter,
        limit = ROW_LIMIT,
    );
    let rows = bound(&rows_sql, &binds)
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(|row| HuntRow {
            agent_id: row.get(0),
            hostname: row.get(1),
            time: row.get(2),
            process: row.get(3),
            cells: (0..shape.cells.len()).map(|index| row.get::<Option<String>, _>(4 + index).unwrap_or_default()).collect(),
        })
        .collect();

    let endpoints_sql = format!(
        "SELECT r.agent_id, a.hostname, COUNT(*) FROM {from} AND {filter} GROUP BY r.agent_id, a.hostname ORDER BY COUNT(*) DESC, a.hostname LIMIT {limit}",
        from = shape.from,
        filter = filter,
        limit = ENDPOINT_LIMIT,
    );
    let endpoints: Vec<HuntEndpoint> = bound(&endpoints_sql, &binds)
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(|row| HuntEndpoint { agent_id: row.get(0), hostname: row.get(1), matches: row.get(2) })
        .collect();

    let total = endpoints.iter().map(|endpoint| endpoint.matches).sum();
    Ok(Ok(HuntResult {
        entity: shape.name.to_string(),
        columns: shape.columns.iter().map(|column| column.to_string()).collect(),
        rows,
        endpoints,
        total,
    }))
}

pub async fn index(pool: &SqlitePool, agent_id: &str, event: &SystemEvent, described: Option<&Described>) -> Result<()> {
    match event {
        SystemEvent::Process(process) if matches!(process.action, ProcessAction::Terminate) => {
            sqlx::query("UPDATE hunt_processes SET ended_at = ? WHERE agent_id = ? AND pid = ? AND ended_at IS NULL")
                .bind(process.timestamp as i64)
                .bind(agent_id)
                .bind(process.pid)
                .execute(pool)
                .await?;
        }
        SystemEvent::Process(process) => {
            let Some(described) = described else {
                return Ok(());
            };
            sqlx::query(
                "INSERT OR REPLACE INTO hunt_processes
                 (agent_id, pid, started_at, name, path, command, uid, parent_pid, parent_name, parent_path, grandparent_name)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(agent_id)
            .bind(process.pid)
            .bind(described.started_at as i64)
            .bind(&described.name)
            .bind(&described.path)
            .bind(&described.command)
            .bind(process.uid)
            .bind(process.ppid)
            .bind(&described.parent_name)
            .bind(&described.parent_path)
            .bind(&described.grandparent_name)
            .execute(pool)
            .await?;
        }
        SystemEvent::Network(connection) => {
            sqlx::query(
                "INSERT INTO hunt_connections (agent_id, pid, process_name, process_started_at, dest_ip, dest_port, protocol, bytes, at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(agent_id)
            .bind(connection.pid)
            .bind(described.map(|process| process.name.clone()))
            .bind(described.map(|process| process.started_at as i64))
            .bind(&connection.dest_ip)
            .bind(connection.dest_port)
            .bind(&connection.protocol)
            .bind((connection.bytes_sent + connection.bytes_received) as i64)
            .bind(connection.timestamp as i64)
            .execute(pool)
            .await?;
        }
        SystemEvent::File(file) => {
            sqlx::query(
                "INSERT INTO hunt_files (agent_id, pid, process_name, process_started_at, path, action, at)
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(agent_id)
            .bind(file.pid)
            .bind(described.map(|process| process.name.clone()))
            .bind(described.map(|process| process.started_at as i64))
            .bind(&file.path)
            .bind(format!("{:?}", file.action))
            .bind(file.timestamp as i64)
            .execute(pool)
            .await?;
        }
        SystemEvent::Package(package) if matches!(package.action, InventoryAction::Removed) => {
            sqlx::query("DELETE FROM hunt_packages WHERE agent_id = ? AND manager = ? AND name = ? AND architecture = ?")
                .bind(agent_id)
                .bind(manager_name(package.manager))
                .bind(&package.name)
                .bind(&package.architecture)
                .execute(pool)
                .await?;
        }
        SystemEvent::Package(package) => {
            sqlx::query(
                "INSERT OR REPLACE INTO hunt_packages (agent_id, manager, name, architecture, version, version_key, previous_version, seen_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(agent_id)
            .bind(manager_name(package.manager))
            .bind(&package.name)
            .bind(&package.architecture)
            .bind(&package.version)
            .bind(version_key(&package.version))
            .bind(&package.previous_version)
            .bind(package.timestamp as i64)
            .execute(pool)
            .await?;
        }
        SystemEvent::Persistence(item) if matches!(item.action, InventoryAction::Removed) => {
            sqlx::query("DELETE FROM hunt_persistence WHERE agent_id = ? AND kind = ? AND path = ? AND name = ?")
                .bind(agent_id)
                .bind(kind_name(item.kind))
                .bind(&item.path)
                .bind(&item.name)
                .execute(pool)
                .await?;
        }
        SystemEvent::Persistence(item) => {
            sqlx::query(
                "INSERT OR REPLACE INTO hunt_persistence (agent_id, kind, path, name, command, user, enabled, hash, seen_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(agent_id)
            .bind(kind_name(item.kind))
            .bind(&item.path)
            .bind(&item.name)
            .bind(&item.command)
            .bind(&item.user)
            .bind(item.enabled)
            .bind(&item.hash)
            .bind(item.timestamp as i64)
            .execute(pool)
            .await?;
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compiled(source: &str) -> (String, Vec<Value>) {
        let query = parse(source).unwrap();
        let mut binds = Vec::new();
        let sql = compile(query.entity, &query.filter, &mut binds).unwrap();
        (sql, binds)
    }

    fn rejected(source: &str) -> QueryError {
        match parse(source) {
            Err(error) => error,
            Ok(query) => compile(query.entity, &query.filter, &mut Vec::new()).unwrap_err(),
        }
    }

    #[test]
    fn test_a_process_tree_heuristic_becomes_bound_sql() {
        let (sql, binds) = compiled(r#"process where name = "rundll32.exe" and parent.name in (powershell.exe, "cmd.exe") and not running = false"#);
        assert_eq!(sql, "(((r.name = ? COLLATE NOCASE) AND (r.parent_name COLLATE NOCASE IN (?, ?))) AND (NOT (NOT (r.ended_at IS NULL))))");
        assert_eq!(
            binds,
            vec![Value::Text("rundll32.exe".into()), Value::Text("powershell.exe".into()), Value::Text("cmd.exe".into())]
        );
    }

    #[test]
    fn test_and_binds_tighter_than_or_and_brackets_override() {
        let loose = parse("process where name = a or name = b and pid > 4").unwrap().filter;
        assert!(matches!(loose, Expr::Or(_, right) if matches!(*right, Expr::And(_, _))));
        let grouped = parse("process where (name = a or name = b) and pid > 4").unwrap().filter;
        assert!(matches!(grouped, Expr::And(left, _) if matches!(*left, Expr::Or(_, _))));
    }

    #[test]
    fn test_contains_escapes_the_wildcards_a_user_typed() {
        let (sql, binds) = compiled(r#"process where command ~ "100%_done""#);
        assert_eq!(sql, "(r.command LIKE ? ESCAPE '\\')");
        assert_eq!(binds, vec![Value::Text("%100\\%\\_done%".into())]);
    }

    #[test]
    fn test_backslashes_in_a_windows_path_are_taken_literally() {
        let (_, binds) = compiled(r#"file where path ~ "\users\public\" or path = 'C:\Temp\a "b".dll'"#);
        assert_eq!(binds, vec![Value::Text(r"%\\users\\public\\%".into()), Value::Text(r#"C:\Temp\a "b".dll"#.into())]);
    }

    #[test]
    fn test_a_query_too_long_or_too_deep_is_refused_before_it_is_read() {
        let long = format!("process where name = \"{}\"", "a".repeat(QUERY_LIMIT));
        assert_eq!(rejected(&long).column, QUERY_LIMIT + 1);

        let brackets = format!("process where {}pid = 1{}", "(".repeat(DEPTH_LIMIT + 1), ")".repeat(DEPTH_LIMIT + 1));
        assert!(rejected(&brackets).message.contains("nest"));
        let negations = format!("process where {}running = true", "not ".repeat(DEPTH_LIMIT + 1));
        assert!(rejected(&negations).message.contains("nest"));

        let allowed = format!("process where {}pid = 1{}", "(".repeat(DEPTH_LIMIT), ")".repeat(DEPTH_LIMIT));
        assert!(parse(&allowed).is_ok());
        assert!(parse("process where (pid = 1) and (pid = 2) and not (pid = 3)").is_ok());
    }

    #[test]
    fn test_version_keys_sort_the_way_versions_do() {
        let ascending = [
            ("3.0.9", "3.0.14"),
            ("3.0.13-0ubuntu3", "3.0.14"),
            ("3.0.13-0ubuntu3", "3.0.13-0ubuntu3.5"),
            ("1.1.1n-0+deb11u5", "1.1.1w-0+deb11u1"),
            ("2.0", "1:1.0"),
            ("1.0~rc1", "1.0"),
            ("1.2.3_rc1", "1.2.3"),
            ("1.2.3_alpha2", "1.2.3_beta1"),
            ("1.2.3", "1.2.3_p1"),
            ("1.37.0-r9", "1.37.0-r18"),
            ("3.0.14", "3.0.14-r0"),
            ("1.0", "1.0.0"),
            ("9", "10"),
        ];
        for (lower, higher) in ascending {
            assert!(version_key(lower) < version_key(higher), "{} should sort before {}", lower, higher);
        }
        assert_eq!(version_key("1.01"), version_key("1.1"));
        assert_eq!(version_key(" 2.4.1 "), version_key("2.4.1"));
    }

    #[test]
    fn test_a_version_is_ordered_by_its_key_and_matched_as_text() {
        let (sql, binds) = compiled("package where name = openssl and version < 3.0.14");
        assert_eq!(sql, "((r.name = ? COLLATE NOCASE) AND (r.version_key < ?))");
        assert_eq!(binds, vec![Value::Text("openssl".into()), Value::Text(version_key("3.0.14"))]);

        let (sql, binds) = compiled(r#"package where version = "3.0.13-0ubuntu3" or version ~ ubuntu or version >= 3"#);
        assert_eq!(sql, "(((r.version = ? COLLATE NOCASE) OR (r.version LIKE ? ESCAPE '\\')) OR (r.version_key >= ?))");
        assert_eq!(binds[0], Value::Text("3.0.13-0ubuntu3".into()));
        assert_eq!(binds[2], Value::Text(version_key("3")));

        assert!(rejected("package where name > openssl").message.contains("is text"));
        assert!(rejected("persistence where enabled > 1").message.contains("true or false"));
    }

    #[test]
    fn test_values_never_reach_the_sql_text() {
        let (sql, binds) = compiled(r#"connection where dest.ip = "1.2.3.4'; DROP TABLE agents; --" and dest.port = 443"#);
        assert!(!sql.contains("DROP"));
        assert_eq!(binds[0], Value::Text("1.2.3.4'; DROP TABLE agents; --".into()));
        assert_eq!(binds[1], Value::Number(443));
    }

    #[test]
    fn test_every_kind_of_record_has_host_fields() {
        for source in [
            "process where host = eng-ws-01",
            "connection where host.ip ~ 10.20",
            "file where host.platform = windows",
            "detection where host = eng-ws-01 and level = high",
            "package where host.platform = linux and name = openssl",
            "persistence where host = eng-ws-01 and kind = cron",
        ] {
            assert!(compiled(source).0.contains("a."), "{}", source);
        }
    }

    #[test]
    fn test_mistakes_are_explained_with_where_they_are() {
        assert_eq!(rejected("proces where name = a").message, KINDS);
        assert_eq!(rejected("process name = a"), QueryError { message: "Expected where after the kind of record".into(), column: 9 });
        assert_eq!(rejected("process where name").column, 19);
        assert_eq!(rejected(r#"process where name = "open"#).message, "This string is never closed");
        let unknown = rejected("process where name = a and parent.nam = b");
        assert!(unknown.message.starts_with("process has no field parent.nam. Fields: name, path"));
        assert_eq!(unknown.column, 28, "a mistake found after reading still points at the field it is about");
        assert_eq!(rejected("process where pid = 4 and name > a").column, 27);
        assert_eq!(rejected("process where pid ~ 4").message, "pid is a number, ~ works on text");
        assert_eq!(rejected("process where name > a").message, "name is text, use =, !=, ~ or !~");
        assert_eq!(rejected("process where running = yes").message, "running is true or false, compare it with = or !=");
        assert_eq!(rejected("process where name = a name = b").message, "Expected and, or, or the end of the query");
    }
}
