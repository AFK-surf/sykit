#!/usr/bin/env python3
"""Loopback download origin. A human-operated HTTPS proxy exposes /s/<ticket>."""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import re
import threading
import time
from invitation_store import private_store, prune, read_record


class Downloads(ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self, address, root):
        self.root = private_store(root)
        self.slots = threading.BoundedSemaphore(32)
        self.next_prune = 0
        super().__init__(address, Handler)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()

    def service_actions(self):
        if time.monotonic() >= self.next_prune:
            prune(self.root)
            self.next_prune = time.monotonic() + 30


class Handler(BaseHTTPRequestHandler):
    server_version = 'sykit'
    sys_version = ''
    def setup(self):
        self.request.settimeout(5)
        super().setup()

    def log_message(self, _format, *args):
        pass  # Paths contain bearer tickets: never log them.

    def reply(self, status, body, content_type='text/plain; charset=utf-8', head=False):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store, private')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        if not head:
            self.wfile.write(body)

    def download(self, head=False):
        match = re.fullmatch(r'/s/([A-Za-z0-9_-]{32})', self.path)
        if not match:
            self.reply(404, b'Not found\n', head=head)
            return
        try:
            record = read_record(self.server.root, match[1])
        except (OSError, ValueError):
            self.reply(404, b'Not found\n', head=head)
            return
        if record['expires_at'] <= time.time():
            self.reply(404, b'Not found\n', head=head)
            return
        self.reply(200, record['script'].encode(), 'text/x-shellscript; charset=utf-8', head=head)

    def do_GET(self):
        self.download()

    def do_HEAD(self):
        self.download(head=True)

    def do_POST(self):
        self.reply(405, b'Read-only download service\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', required=True, help='private 0700 store shared with make-session.py')
    parser.add_argument('--port', type=int, default=8787)
    args = parser.parse_args()
    server = Downloads(('127.0.0.1', args.port), args.directory)
    print('Loopback invitation origin on 127.0.0.1:' + str(server.server_port), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
