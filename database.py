import sqlite3

def initialize_db():
    conn = sqlite3.connect("alerts.db")
    
    cursor = conn.cursor()

    cursor.execute("""
                   CREATE TABLE IF NOT EXISTS alerts (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   timestamp TEXT,
                   source_ip TEXT,
                   attack_type TEXT,
                   packet_count INTEGER
                   )
                   """)
    conn.commit()
    conn.close()

def save_alerts(timestamp, source_ip, attack_type, packet_count):
    conn = sqlite3.connect("alerts.db")
    cursor = conn.cursor()
    cursor.execute("""
            INSERT INTO alerts (timestamp, source_ip, attack_type, packet_count) VALUES (?, ?, ?, ?)
""",(timestamp, source_ip, attack_type, packet_count))
    conn.commit()
    conn.close()

if __name__ == "__main__":
    initialize_db()
    print("Database created successfully") 


