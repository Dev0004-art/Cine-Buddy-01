# Auto-detect async mode — uses simple-websocket for native WS support
_async_mode = 'threading'  # force simple-websocket; avoids eventlet on Py 3.13

import os, re, time, secrets, logging
import socket as _sock
from html import escape as he
from flask import Flask, render_template, request, jsonify, send_from_directory, abort
from flask_socketio import SocketIO, join_room as _join_room, emit
from werkzeug.utils import secure_filename

try:
    from dotenv import load_dotenv; load_dotenv()
except ImportError:
    pass

logging.basicConfig(level=logging.INFO)
log = logging.getLogger('cinebuddy')

app = Flask(__name__)
app.config['SECRET_KEY']         = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
app.config['MAX_CONTENT_LENGTH'] = 4 * 1024 * 1024 * 1024

BASE_DIR      = os.path.dirname(os.path.abspath(__file__))
VIDEOS_FOLDER = os.path.join(BASE_DIR, 'videos')
os.makedirs(VIDEOS_FOLDER, exist_ok=True)

ALLOWED_EXTS = frozenset({'.mp4', '.webm', '.mkv', '.avi', '.mov', '.m4v', '.ogv'})

VIDEO_SIGS = [
    (0, b'\x1aE\xdf\xa3'),
    (0, b'RIFF'),
    (0, b'OggS'),
    (4, b'ftyp'),
    (0, b'\x00\x00\x00\x14ftyp'),
    (0, b'\x00\x00\x00\x18ftyp'),
    (0, b'\x00\x00\x00\x1cftyp'),
    (0, b'\x00\x00\x00\x20ftyp'),
]

socketio = SocketIO(
    app,
    async_mode           = _async_mode,
    cors_allowed_origins = '*',
    ping_timeout         = 60,
    ping_interval        = 25,
    logger               = False,
    engineio_logger      = False,
)

rooms = {}

def _blank_room():
    return {
        'users':        [],
        'host_id':      None,
        'video_state':  {'url': '', 'time': 0.0, 'playing': False, 'type': 'none'},
        'play_started': None,
        'created_at':   time.time(),
    }

def _current_time(r):
    """Calculate real current playback position including elapsed time since play started."""
    vs = r['video_state']
    if vs['playing'] and r['play_started'] is not None:
        elapsed = time.time() - r['play_started']
        return vs['time'] + elapsed
    return vs['time']

ROOM_RE = re.compile(r'^[A-Z0-9]{4,8}$')

def _room(v):
    if not isinstance(v, str): return None
    v = v.strip().upper()
    return v if ROOM_RE.match(v) else None

def _user(v):
    if not isinstance(v, str): return 'Anonymous'
    return he(v.strip())[:20] or 'Anonymous'

def _msg(v):
    if not isinstance(v, str): return ''
    return he(v.strip())[:400]

def _safe_url(url):
    if not isinstance(url, str): return False
    if url.startswith('/videos/'):
        tail = url[len('/videos/'):]
        return bool(secure_filename(tail)) and '..' not in tail and '/' not in tail
    return bool(re.match(r'^https://www\.youtube\.com/watch\?v=[A-Za-z0-9_-]{11}', url))

def _magic_ok(fs):
    hdr = fs.read(12); fs.seek(0)
    for off, sig in VIDEO_SIGS:
        if hdr[off:off+len(sig)] == sig: return True
    return False

class _RL:
    def __init__(self): self._s = {}
    def ok(self, sid, ev, limit, window):
        now = time.monotonic(); k = f'{sid}:{ev}'
        hits = [t for t in self._s.get(k, []) if now - t < window]
        if len(hits) >= limit: return False
        self._s[k] = hits + [now]; return True
    def purge(self, sid):
        self._s = {k: v for k, v in self._s.items() if not k.startswith(f'{sid}:')}

_rl = _RL()

@app.after_request
def _sec_headers(resp):
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options']        = 'SAMEORIGIN'
    resp.headers['X-XSS-Protection']       = '1; mode=block'
    resp.headers['Referrer-Policy']        = 'strict-origin-when-cross-origin'
    resp.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' "
          "https://cdn.socket.io "
          "https://cdnjs.cloudflare.com "
          "https://www.youtube.com "
          "https://www.youtube-nocookie.com "
          "https://s.ytimg.com; "
        "frame-src https://www.youtube.com https://www.youtube-nocookie.com; "
        "img-src 'self' data: https://i.ytimg.com https://www.youtube.com https://www.youtube-nocookie.com; "
        "connect-src 'self' wss: ws: https://cdn.socket.io; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; "
        "media-src 'self' blob:;"
    )
    return resp

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/room/<path:room_id>')
def room(room_id):
    rid = _room(room_id)
    if not rid:
        return "Invalid room ID", 400
    return render_template('room.html', room_id=rid)

@app.route('/api/server-info')
def server_info():
    try:
        s = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80)); ip = s.getsockname()[0]; s.close()
    except Exception:
        ip = 'localhost'
    port = int(os.environ.get('PORT', 8080))
    return jsonify({'local_ip': ip, 'port': port, 'local_url': f'http://{ip}:{port}'})

@app.route('/api/videos')
def list_videos():
    try:
        out = []
        for f in sorted(os.listdir(VIDEOS_FOLDER)):
            if os.path.splitext(f.lower())[1] not in ALLOWED_EXTS: continue
            p = os.path.join(VIDEOS_FOLDER, f)
            if not os.path.isfile(p): continue
            out.append({'name': f, 'size_mb': round(os.path.getsize(p) / 1048576, 1)})
        return jsonify(out)
    except Exception:
        return jsonify([])

@app.route('/api/upload', methods=['POST'])
def upload_video():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    f = request.files['file']
    if not f.filename:
        return jsonify({'error': 'Empty filename'}), 400
    ext = os.path.splitext(f.filename.lower())[1]
    if ext not in ALLOWED_EXTS:
        return jsonify({'error': f'Not allowed. Use: {", ".join(sorted(ALLOWED_EXTS))}'}), 415
    if not _magic_ok(f):
        return jsonify({'error': 'File does not look like a valid video'}), 415
    filename = secure_filename(f.filename)
    if not filename:
        return jsonify({'error': 'Bad filename'}), 400
    base, ex = os.path.splitext(filename)
    dest = os.path.join(VIDEOS_FOLDER, filename); c = 1
    while os.path.exists(dest):
        filename = f'{base}_{c}{ex}'; dest = os.path.join(VIDEOS_FOLDER, filename); c += 1
    real = os.path.realpath(dest)
    if not real.startswith(os.path.realpath(VIDEOS_FOLDER) + os.sep):
        return jsonify({'error': 'Bad path'}), 400
    try:
        f.save(real)
    except Exception as e:
        log.error('Upload error: %s', e)
        return jsonify({'error': 'Save failed'}), 500
    return jsonify({'success': True, 'filename': filename,
                    'size_mb': round(os.path.getsize(real) / 1048576, 1)})

@app.route('/api/delete-video', methods=['POST'])
def delete_video():
    data  = request.get_json(silent=True) or {}
    fname = secure_filename(str(data.get('filename', '')))
    if not fname: return jsonify({'error': 'Bad filename'}), 400
    path  = os.path.realpath(os.path.join(VIDEOS_FOLDER, fname))
    if not path.startswith(os.path.realpath(VIDEOS_FOLDER) + os.sep):
        return jsonify({'error': 'Forbidden'}), 403
    if not os.path.isfile(path): return jsonify({'error': 'Not found'}), 404
    try:
        os.remove(path); return jsonify({'success': True})
    except Exception:
        return jsonify({'error': 'Delete failed'}), 500

@app.route('/videos/<path:filename>')
def serve_video(filename):
    safe = secure_filename(filename)
    if not safe or os.path.splitext(safe.lower())[1] not in ALLOWED_EXTS:
        abort(404)
    real = os.path.realpath(os.path.join(VIDEOS_FOLDER, safe))
    if not real.startswith(os.path.realpath(VIDEOS_FOLDER) + os.sep):
        abort(403)
    return send_from_directory(VIDEOS_FOLDER, safe, conditional=True)

def _prune():
    cutoff = time.time() - 43200
    dead = [rid for rid, r in rooms.items() if not r['users'] and r['created_at'] < cutoff]
    for rid in dead:
        del rooms[rid]

@socketio.on('join')
def on_join(data):
    sid = request.sid
    if not _rl.ok(sid, 'join', 5, 30):
        emit('error', {'msg': 'Too many join attempts. Wait a moment.'}); return
    if not isinstance(data, dict): return
    rid  = _room(data.get('room', ''))
    user = _user(data.get('username', ''))
    if not rid:
        emit('error', {'msg': 'Invalid room code.'}); return
    _prune()
    if rid not in rooms:
        if len(rooms) >= 500:
            emit('error', {'msg': 'Server at capacity.'}); return
        rooms[rid] = _blank_room()
    r = rooms[rid]
    if len(r['users']) >= 2:
        emit('error', {'msg': 'Room is full - only 2 people allowed.'}); return
    if any(u['id'] == sid for u in r['users']): return
    _join_room(rid)
    is_host = r['host_id'] is None
    r['users'].append({'id': sid, 'username': user})
    if is_host: r['host_id'] = sid

    # Send live-calculated time so joining user syncs to exact position
    vs = dict(r['video_state'])
    vs['time'] = _current_time(r)

    emit('joined', {
        'role': 'host' if is_host else 'guest',
        'username': user,
        'video_state': vs,
        'room_id': rid,
    })
    emit('peer_joined',
         {'username': user, 'users': [u['username'] for u in r['users']]},
         room=rid, include_self=False)
    emit('update_roster',
         {'users': [u['username'] for u in r['users']]},
         room=rid)

@socketio.on('disconnect')
def on_disconnect():
    sid = request.sid; _rl.purge(sid)
    for rid in list(rooms.keys()):
        r = rooms[rid]
        user = next((u for u in r['users'] if u['id'] == sid), None)
        if not user: continue
        r['users'].remove(user)
        emit('peer_left',     {'username': user['username']}, room=rid)
        emit('update_roster', {'users': [u['username'] for u in r['users']]}, room=rid)
        if sid == r['host_id'] and r['users']:
            r['host_id'] = r['users'][0]['id']
            emit('promoted_to_host', {}, room=r['host_id'])
        if not r['users']: del rooms[rid]
        break

@socketio.on('video_action')
def on_video_action(data):
    sid = request.sid
    if not _rl.ok(sid, 'video', 60, 5): return
    if not isinstance(data, dict): return
    rid = _room(data.get('room', ''))
    if not rid or rid not in rooms: return
    r = rooms[rid]
    if not any(u['id'] == sid for u in r['users']): return

    action = str(data.get('action', ''))[:20]
    raw    = data.get('state', {})
    if not isinstance(raw, dict): return

    # Host-only actions: play, pause, seek, clear
    if action in ('play', 'pause', 'seek', 'clear') and sid != r['host_id']:
        emit('permission_denied', {'msg': 'Only the host can play or pause the video.'})
        return

    # load is allowed by both host and guest (adding videos)

    url   = str(raw.get('url', ''))
    vtype = str(raw.get('type', 'none'))[:10]
    try:    vtime = max(0.0, min(float(raw.get('time', 0.0)), 86400.0))
    except: vtime = 0.0
    vplay = bool(raw.get('playing', False))
    if url and not _safe_url(url): return

    now = time.time()

    # Track server timestamp for live sync calculation
    if action == 'play':
        r['play_started'] = now
        r['video_state']['time'] = vtime
    elif action in ('pause', 'seek', 'load', 'clear'):
        r['play_started'] = None
        r['video_state']['time'] = vtime

    r['video_state'].update({'url': url, 'type': vtype, 'playing': vplay})
    if not url:
        r['video_state']['time'] = 0.0

    out_state = dict(r['video_state'])
    out_state['server_time'] = now

    # Broadcast to OTHER users in the room (sender already applied locally)
    emit('video_action',
         {'action': action, 'state': out_state},
         room=rid, include_self=False)

@socketio.on('request_sync')
def on_request_sync(data):
    sid = request.sid
    if not _rl.ok(sid, 'sync', 10, 10): return
    if not isinstance(data, dict): return
    rid = _room(data.get('room', ''))
    if rid and rid in rooms:
        r = rooms[rid]
        vs = dict(r['video_state'])
        vs['time'] = _current_time(r)  # live calculated position
        vs['server_time'] = time.time()
        emit('video_action', {'action': 'sync', 'state': vs})

@socketio.on('chat')
def on_chat(data):
    sid = request.sid
    if not _rl.ok(sid, 'chat', 20, 10):
        emit('chat_error', {'msg': 'Slow down!'}); return
    if not isinstance(data, dict): return
    rid  = _room(data.get('room', ''))
    msg  = _msg(data.get('message', ''))
    user = _user(data.get('username', ''))
    ts   = str(data.get('ts', ''))[:10]
    if not rid or rid not in rooms or not msg: return
    if not any(u['id'] == sid for u in rooms[rid]['users']): return
    emit('chat', {'username': user, 'message': msg, 'ts': ts}, room=rid)

@socketio.on('rtc_signal')
def on_rtc_signal(data):
    sid = request.sid
    if not _rl.ok(sid, 'rtc', 60, 10): return
    if not isinstance(data, dict): return
    rid = _room(data.get('room', ''))
    if not rid or rid not in rooms: return
    if not any(u['id'] == sid for u in rooms[rid]['users']): return
    emit('rtc_signal', data, room=rid, include_self=False)

if __name__ == '__main__':
    try:
        s = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80)); lan = s.getsockname()[0]; s.close()
    except Exception:
        lan = 'localhost'
    port = int(os.environ.get('PORT', 8080))
    print('\n' + '='*52)
    print(f'  CineBuddy  [{_async_mode} mode]')
    print('='*52)
    print(f'  Videos :  ./videos/')
    print(f'  Local  :  http://localhost:{port}')
    print(f'  WiFi   :  http://{lan}:{port}')
    print('='*52 + '\n')
    socketio.run(app, debug=False, host='0.0.0.0', port=port,
                 allow_unsafe_werkzeug=True)