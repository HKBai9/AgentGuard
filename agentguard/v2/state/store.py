"""Short SQLite transactions. Never await model/tool I/O while holding one."""
from contextlib import contextmanager
from pathlib import Path
import sqlite3
from ..common import canonical, strict_loads, new_id, utcnow, RuntimeFault
from ..contracts import Event, LineageEdge, make

DDL = '''
CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS records(session TEXT NOT NULL, kind TEXT NOT NULL, id TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY(session,kind,id));
CREATE TABLE IF NOT EXISTS artifacts(session TEXT NOT NULL, id TEXT NOT NULL, version INTEGER NOT NULL, meta TEXT NOT NULL, PRIMARY KEY(session,id,version));
CREATE TABLE IF NOT EXISTS artifact_status(session TEXT NOT NULL, id TEXT NOT NULL, version INTEGER NOT NULL, released INTEGER NOT NULL DEFAULT 0, revoked INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(session,id,version));
CREATE TRIGGER IF NOT EXISTS immutable_artifacts BEFORE UPDATE ON artifacts BEGIN SELECT RAISE(ABORT, 'immutable artifact'); END;
CREATE TABLE IF NOT EXISTS permits(id TEXT PRIMARY KEY, session TEXT NOT NULL, call_id TEXT NOT NULL, status TEXT NOT NULL, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS claims(session TEXT NOT NULL, call_id TEXT NOT NULL, permit_id TEXT NOT NULL, status TEXT NOT NULL, receipt TEXT, PRIMARY KEY(session,call_id));
CREATE TABLE IF NOT EXISTS quotas(session TEXT NOT NULL, rule_key TEXT NOT NULL, used INTEGER NOT NULL, PRIMARY KEY(session,rule_key));
CREATE TABLE IF NOT EXISTS events(session TEXT NOT NULL, seq INTEGER NOT NULL, data TEXT NOT NULL, PRIMARY KEY(session,seq));
CREATE TABLE IF NOT EXISTS edges(session TEXT NOT NULL, source TEXT NOT NULL, target TEXT NOT NULL, kind TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY(session,source,target,kind));
CREATE TABLE IF NOT EXISTS resource_locks(resource TEXT PRIMARY KEY, session TEXT NOT NULL, call_id TEXT NOT NULL);
'''


class ClosingConnection(sqlite3.Connection):
    def __exit__(self, *args):
        try:
            return super().__exit__(*args)
        finally:
            self.close()


class Store:
    def __init__(self, path):
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self.connect() as conn:
            conn.execute('PRAGMA journal_mode=WAL')
            conn.executescript(DDL)
        self.path.chmod(0o600)

    def connect(self):
        conn = sqlite3.connect(self.path, timeout=15, isolation_level=None, factory=ClosingConnection)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA foreign_keys=ON')
        conn.execute('PRAGMA busy_timeout=15000')
        conn.execute('PRAGMA synchronous=FULL')
        return conn

    @contextmanager
    def transaction(self):
        conn = self.connect()
        try:
            conn.execute('BEGIN IMMEDIATE')
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    def session(self, sid, conn=None):
        if conn is None:
            with self.connect() as cx:
                return self.session(sid, cx)
        row = conn.execute('SELECT data FROM sessions WHERE id=?', (sid,)).fetchone()
        if row is None:
            raise RuntimeFault('SESSION_NOT_FOUND', 404)
        return strict_loads(row['data'])

    def save_session(self, sid, data, conn):
        conn.execute('INSERT INTO sessions VALUES(?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data', (sid, canonical(data)))

    def get(self, sid, kind, key, conn=None):
        if conn is None:
            with self.connect() as cx:
                return self.get(sid, kind, key, cx)
        row = conn.execute('SELECT data FROM records WHERE session=? AND kind=? AND id=?', (sid, kind, key)).fetchone()
        return strict_loads(row['data']) if row else None

    def put(self, sid, kind, key, data, conn, *, replace=False):
        sql = 'INSERT OR REPLACE' if replace else 'INSERT'
        conn.execute(f'{sql} INTO records VALUES(?,?,?,?)', (sid, kind, key, canonical(data)))

    def all(self, sid, kind, conn=None):
        if conn is None:
            with self.connect() as cx:
                return self.all(sid, kind, cx)
        return [strict_loads(r['data']) for r in conn.execute('SELECT data FROM records WHERE session=? AND kind=? ORDER BY rowid', (sid, kind))]

    def event(self, sid, kind, payload=None, conn=None, **bindings):
        if conn is None:
            with self.transaction() as cx:
                return self.event(sid, kind, payload, cx, **bindings)
        # payloads are constructed by the runtime and contain only IDs/codes/counts.
        state = self.session(sid, conn)
        seq = conn.execute('SELECT COALESCE(MAX(seq),0)+1 FROM events WHERE session=?', (sid,)).fetchone()[0]
        event = make(Event, event_id=new_id('event'), session_id=sid, seq=seq, timestamp=utcnow(), event_type=kind,
            turn_id=bindings.get('turn_id'), call_id=bindings.get('call_id'), review_id=bindings.get('review_id'),
            policy_version=state.get('policy_version'), context_version=state.get('context_version'), payload=payload or {})
        conn.execute('INSERT INTO events VALUES(?,?,?)', (sid, seq, canonical(event)))
        return event

    def events(self, sid, after_seq=0, limit=100):
        if not 1 <= limit <= 1000 or after_seq < 0:
            raise RuntimeFault('INVALID_PAGINATION', 422)
        self.session(sid)
        with self.connect() as conn:
            return [Event.model_validate_json(r[0]) for r in conn.execute('SELECT data FROM events WHERE session=? AND seq>? ORDER BY seq LIMIT ?', (sid, after_seq, limit))]

    def add_edge(self, edge, conn=None):
        if conn is None:
            with self.transaction() as cx:
                return self.add_edge(edge, cx)
        conn.execute('INSERT OR IGNORE INTO edges VALUES(?,?,?,?,?)', (edge.session_id, canonical(edge.source_ref), canonical(edge.target_ref), edge.kind, canonical(edge)))

    def edges(self, sid):
        with self.connect() as conn:
            return [LineageEdge.model_validate_json(r[0]) for r in conn.execute('SELECT data FROM edges WHERE session=? ORDER BY rowid', (sid,))]
