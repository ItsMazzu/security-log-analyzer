-- Database schema for Security Log Analyzer
-- Stores authentication events for analysis

create table auth_logs (
    id integer primary key autoincrement,
    timestamp text not null,
    username text not null,
    ip_address text not null,
    status text not null
)