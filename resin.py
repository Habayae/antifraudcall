import pymysql
import os
import datetime
import json
import psutil
import re
LOG_FILE = "/var/log/asterisk/resin.log"
STATE_FILE = "/var/lib/asterisk/agi-bin/resin.state"
DB_HOST = "localhost"
DB_USER = "freepbxuser"
DB_PASS = "201315@Nh"
DB_NAME = "asteriskcdrdb"
MARK_LIMIT = 5
MAX_BAN_ATTEMPT = 3
RELEASE_TIME_MAP = {
    1: 300,   
    2: 600,   
    3: 900   
}
def write_log(msg):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(f"[{now}] {msg}\n")
def system_boot_time():
    return datetime.datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")
def load_json_file(path, default):
    if os.path.exists(path):
        with open(path, 'r') as f:
            return json.load(f)
    return default
def save_json_file(path, data):
    with open(path, 'w') as f:
        json.dump(data, f)
def get_short_calls(start_time, end_time):
    conn = pymysql.connect(
        host=DB_HOST, user=DB_USER, password=DB_PASS,
        db=DB_NAME, cursorclass=pymysql.cursors.DictCursor
    )
    cur = conn.cursor()
    cur.execute("""
        SELECT src, channel
        FROM cdr
        WHERE disposition = 'ANSWERED'
          AND duration < 5
          AND duration >= 1
          AND calldate BETWEEN %s AND %s
    """, (start_time, end_time))
    results = cur.fetchall()
    conn.close()
    return results
def is_blacklisted(src):
    result = os.popen(f'asterisk -rx "database get blacklist {src}"').read()
    return "Value:" in result
def add_to_blacklist(src):
    uid = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    os.system(f'asterisk -rx "database put blacklist {src} {uid}"')
    write_log(f"{src} | STATUS: BAN | UID: {uid}")
def remove_from_blacklist(src):
    os.system(f'asterisk -rx "database del blacklist {src}"')
    write_log(f"{src} | STATUS: RELEASE")
def main():
    now = datetime.datetime.now()

    state = load_json_file(STATE_FILE, {})
    boot_time = system_boot_time()

    if state.get("start_time") != boot_time:
        write_log("System reboot detected. Resetting state.")
        state = {
            "start_time": boot_time,
            "last_checked": None,
            "callers": {}
        }
    start_time = datetime.datetime.strptime(state["start_time"], "%Y-%m-%d %H:%M:%S")
    last_checked = datetime.datetime.strptime(state["last_checked"], "%Y-%m-%d %H:%M:%S") if state.get("last_checked") else start_time
    end_time = now
    calls = get_short_calls(last_checked, end_time)
    counter = {}

    for call in calls:
        src = call['src']
        channel = call.get('channel', '')
        if src:
            counter[src] = counter.get(src, 0) + 1

    callers = state.get("callers", {})

    for src, count in counter.items():
        record = callers.get(src, {
            "mark": 0, "ban": 0, "release": 0,
            "permanent": False, "ban_time": None
        })

        if record["permanent"]:
            write_log(f"{src} | SKIPPED: Permanently blacklisted")
            continue

        if count >= MARK_LIMIT:
            if not is_blacklisted(src):
                add_to_blacklist(src)
                record["ban"] += 1
                record["ban_time"] = now.strftime("%Y-%m-%d %H:%M:%S")
                write_log(f"{src} | BAN_COUNT: {record['ban']}")
                if record["ban"] >= MAX_BAN_ATTEMPT:
                    record["permanent"] = True
                    write_log(f"{src} | STATUS: PERMANENT_BAN")
            else:
                write_log(f"{src} | Already blacklisted")
        else:
            record["mark"] += 1
            write_log(f"{src} | STATUS: MARK | COUNT: {record['mark']}")

        callers[src] = record
    for src, record in callers.items():
        if record.get("ban_time") and not record.get("permanent"):
            ban_time = datetime.datetime.strptime(record["ban_time"], "%Y-%m-%d %H:%M:%S")
            wait_time = RELEASE_TIME_MAP.get(record["ban"], 0)
            if (now - ban_time).total_seconds() >= wait_time:
                if is_blacklisted(src):
                    remove_from_blacklist(src)
                    record["release"] += 1
                    record["ban_time"] = None
                    write_log(f"{src} | STATUS: RELEASE | RELEASE_COUNT: {record['release']}")
                else:
                    write_log(f"{src} | Release skipped: not in blacklist")
                callers[src] = record
    state["callers"] = callers
    state["last_checked"] = now.strftime("%Y-%m-%d %H:%M:%S")
    save_json_file(STATE_FILE, state)
if __name__ == "__main__":
    main()
