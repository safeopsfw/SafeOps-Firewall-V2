-- Initial Threat Categories
-- Predefined threat classification categories

CREATE TABLE IF NOT EXISTS threat_categories (
    id SERIAL PRIMARY KEY,
    category_name VARCHAR(50) NOT NULL UNIQUE,
    description TEXT,
    severity INT DEFAULT 5, -- 1-10 scale
    created_at TIMESTAMP DEFAULT NOW()
);

INSERT INTO threat_categories (category_name, description, severity) VALUES
    ('malware', 'Known malware distribution or C&C', 9),
    ('phishing', 'Phishing websites and domains', 8),
    ('botnet', 'Botnet command and control', 9),
    ('spam', 'Email spam sources', 5),
    ('scanner', 'Port/vulnerability scanners', 6),
    ('brute_force', 'Brute force attack sources', 7),
    ('ddos', 'DDoS attack infrastructure', 8),
    ('tor_exit', 'Tor exit nodes', 4),
    ('vpn', 'VPN service IPs', 3),
    ('proxy', 'Proxy servers', 4)
ON CONFLICT (category_name) DO NOTHING;
