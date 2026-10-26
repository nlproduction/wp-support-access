#!/usr/bin/env python3
"""Real, disposable WordPress + socket-only MySQL + HTTP cookie tests.

Requires PHP/mysqli, MySQL 8+, Python 3.9+ and a read-only WordPress core tree.
Never reads an existing wp-config.php or opens an existing WordPress database.
"""
import contextlib
import http.cookiejar
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

PACKAGE = Path(__file__).resolve().parents[1]
CORE = Path(os.environ.get('WPSA_WP_CORE', '')).resolve()
if not os.environ.get('WPSA_WP_CORE') or not (CORE / 'wp-settings.php').is_file():
    raise SystemExit('Set WPSA_WP_CORE to a read-only WordPress core tree.')


def check(value, message):
    if not value:
        raise AssertionError(message)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def client():
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), NoRedirect()), jar


def request(opener, url, method='GET', data=None, headers=None):
    encoded = None
    hdr = dict(headers or {})
    if data is not None:
        if hdr.get('Content-Type') == 'application/x-www-form-urlencoded':
            encoded = urllib.parse.urlencode(data).encode()
        else:
            encoded = json.dumps(data).encode()
            hdr['Content-Type'] = 'application/json'
    req = urllib.request.Request(url, data=encoded, headers=hdr, method=method)
    try:
        response = opener.open(req, timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    return response.code, response.headers, response.read().decode('utf-8', errors='replace')


def main():
    processes, handles = [], []
    with tempfile.TemporaryDirectory(prefix='wpsa-test-') as temp:
        root = Path(temp).resolve()
        wp = root / 'wp'
        wp.mkdir()
        (root / 'owned-fixture').write_text(secrets.token_hex(32))
        # PHP resolves __DIR__ through symlinks. Copy core so wp-admin/admin.php
        # cannot follow dirname(__DIR__) into an existing site's wp-load.php.
        for folder in ['wp-admin', 'wp-includes']:
            shutil.copytree(CORE / folder, wp / folder)
        for source in CORE.glob('*.php'):
            if source.name != 'wp-config.php':
                shutil.copy2(source, wp / source.name)
        content = wp / 'wp-content'
        (content / 'plugins').mkdir(parents=True)
        shutil.copytree(PACKAGE, content / 'plugins' / 'wp-support-access',
                        ignore=shutil.ignore_patterns('.git', 'vendor', 'dist', '__pycache__'))
        (content / 'mu-plugins').mkdir()
        theme = content / 'themes' / 'testtheme'
        theme.mkdir(parents=True)
        (theme / 'style.css').write_text('/*\nTheme Name: Disposable test theme\n*/')
        (theme / 'index.php').write_text('<?php echo "Disposable test theme";')
        (content / 'mu-plugins' / 'isolation.php').write_text(
            "<?php add_filter('pre_http_request', static function () { return new WP_Error('offline', 'Test network disabled'); });"
            "add_filter('pre_wp_mail', static function () { return true; });")
        dbdir = root / 'mysql'
        dbdir.mkdir()
        (root / 'mysql-tmp').mkdir()
        sock = root / 'mysql.sock'
        env = dict(os.environ, WPSA_TEST_ROOT=str(root))

        def run(binary, args, timeout=60):
            result = subprocess.run([binary, *map(str, args)], env=env, capture_output=True, text=True, timeout=timeout)
            if result.returncode:
                raise RuntimeError(f'{binary} failed:\n{result.stdout[-3000:]}\n{result.stderr[-3000:]}')
            return result.stdout

        def start(binary, args, log):
            handle = open(root / log, 'w')
            handles.append(handle)
            process = subprocess.Popen([binary, *map(str, args)], env=env, stdout=handle, stderr=handle)
            processes.append(process)
            return process

        def php(command, *args):
            return run('php', [PACKAGE / 'tests' / 'fixture.php', command, *args])

        try:
            dbargs = ['--no-defaults', f'--datadir={dbdir}', '--innodb-buffer-pool-size=32M',
                      '--innodb-redo-log-capacity=32M', '--innodb-log-buffer-size=4M', '--performance-schema=OFF']
            run('mysqld', [*dbargs, '--initialize-insecure', f'--log-error={root}/mysql-init.log'])
            mysql_server = start('mysqld', [*dbargs, '--skip-networking', '--mysqlx=0', f'--socket={sock}',
                                f'--pid-file={root}/mysql.pid', f'--tmpdir={root}/mysql-tmp',
                                f'--log-error={root}/mysql-server.log', '--skip-log-bin', '--max-connections=12',
                                '--table-open-cache=64'], 'database.log')
            mysql = ['--no-defaults', '--protocol=SOCKET', f'--socket={sock}', '--user=root', '--connect-timeout=1']
            for _ in range(120):
                if mysql_server.poll() is not None:
                    raise RuntimeError((root / 'mysql-server.log').read_text())
                try:
                    run('mysql', [*mysql, '--execute=SELECT 1'], timeout=3)
                    break
                except RuntimeError:
                    time.sleep(.1)
            else:
                raise RuntimeError('Disposable MySQL did not start')
            run('mysql', [*mysql, '--execute=CREATE DATABASE support_test CHARACTER SET utf8mb4'])
            with contextlib.closing(socket.socket()) as listener:
                listener.bind(('127.0.0.1', 0))
                port = listener.getsockname()[1]
            origin = f'http://127.0.0.1:{port}'
            config = "<?php\n"
            constants = dict(DB_NAME='support_test', DB_USER='root', DB_PASSWORD='',
                             DB_HOST=f'localhost:{sock}', DB_CHARSET='utf8mb4', DB_COLLATE='',
                             WP_HOME=origin, WP_SITEURL=origin, WP_ENVIRONMENT_TYPE='local')
            for name, value in constants.items():
                config += f'define({json.dumps(name)}, {json.dumps(value)});\n'
            for name in ['AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY',
                         'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT']:
                config += f'define("{name}", "{secrets.token_hex(32)}");\n'
            config += "define('DISABLE_WP_CRON', true); define('WP_DEBUG', true); define('WP_DEBUG_DISPLAY', false);\n"
            config += "define('WP_DEFAULT_THEME', 'testtheme');\n"
            config += "define('DISALLOW_FILE_MODS', true); define('AUTOMATIC_UPDATER_DISABLED', true);\n"
            config += "$table_prefix = 'test_'; if (!defined('ABSPATH')) define('ABSPATH', __DIR__ . '/'); require ABSPATH . 'wp-settings.php';\n"
            (wp / 'wp-config.php').write_text(config)
            print(php('install').strip(), flush=True)
            print(php('contracts').strip(), flush=True)
            server = start('php', ['-S', f'127.0.0.1:{port}', '-t', wp], 'http.log')
            anonymous, _ = client()
            for _ in range(100):
                if server.poll() is not None:
                    raise RuntimeError((root / 'http.log').read_text())
                try:
                    status, _, _ = request(anonymous, origin + '/wp-login.php')
                    if status == 200:
                        break
                except OSError:
                    time.sleep(.1)
            else:
                raise RuntimeError('Disposable PHP did not start')
            endpoint = origin + '/?rest_route=/wp-support-access/v1/grants'
            admin, admin_jar = client()
            request(admin, origin + '/wp-login.php')  # core login test cookie
            status, _, body = request(admin, origin + '/wp-login.php', 'POST',
                                      {'log': 'testadmin', 'pwd': 'disposable-admin-password', 'wp-submit': 'Log In',
                                       'testcookie': '1', 'redirect_to': origin + '/wp-admin/'},
                                      {'Content-Type': 'application/x-www-form-urlencoded'})
            check(status == 302 and len(admin_jar) > 1, 'Real administrator login failed: ' + body[:1000])
            status, _, page = request(admin, origin + '/wp-admin/options-general.php?page=wp-support-access')
            check(status == 200, 'Settings page failed: ' + str(status) + ' ' + page[:300])
            config_match = re.search(r'<script id="wpsa-config" type="application/json">(.*?)</script>', page, re.S)
            check(config_match, 'One-click UI configuration missing')
            ui_config = json.loads(config_match.group(1))
            auth = {'X-WP-Nonce': ui_config['nonce']}
            for verb in ['GET', 'POST', 'DELETE']:
                url = endpoint + ('/' + 'a' * 32 if verb == 'DELETE' else '')
                status, _, _ = request(anonymous, url, verb, {} if verb == 'POST' else None)
                check(status in [401, 403], f'Guest {verb} accepted')
            status, _, _ = request(admin, endpoint, 'POST', {})
            check(status in [401, 403], 'Cookie without nonce can issue')
            status, _, _ = request(admin, endpoint, 'POST', {}, {'X-WP-Nonce': 'wrong'})
            check(status == 403, 'Invalid nonce accepted')
            print('PASS real admin login, settings page, REST guest/cookie/nonce boundaries', flush=True)

            def issue(ttl=3600):
                status, headers, body = request(admin, endpoint, 'POST', {'ttl': ttl, 'label': 'HTTP ticket'}, auth)
                check(status == 201, 'Issue failed: ' + body)
                check('no-store' in headers.get('Cache-Control', ''), 'Creation response may be cached')
                return json.loads(body)

            a, b = issue(), issue()
            support, support_jar = client()
            status, headers, body = request(support, a['url'] + '&redirect_to=http://example.invalid/')
            check(status == 302, 'Magic link failed: ' + body)
            check(headers['Location'] == origin + '/wp-admin/', 'Unsafe redirect: ' + str(headers.get('Location')))
            check(headers.get('Referrer-Policy') == 'no-referrer', 'Login can leak referrer')
            check('no-store' in headers.get('Cache-Control', ''), 'Login may be cached')
            check(any(cookie.name.startswith('wordpress_logged_in') and cookie.has_nonstandard_attr('HttpOnly')
                      for cookie in support_jar), 'No HttpOnly WordPress cookie')
            status, _, _ = request(support, origin + '/wp-admin/')
            check(status == 200, 'Support cookie cannot access WP admin')
            status, _, _ = request(support, origin + '/wp-admin/options-general.php?page=wp-support-access')
            check(status == 403, 'Support can open the grant management UI')
            sessions = json.loads(php('sessions', a['user_id']))
            check(sessions and max(item['expiration'] for item in sessions) <= a['expires_at'], 'Session outlives grant')
            status, _, body = request(admin, endpoint, headers=auth)
            listed = json.loads(body)
            check(status == 200 and a['token'] not in body and 'token_hash' not in body and '"url"' not in body,
                  'List exposes token/hash/URL')
            check(next(g for g in listed if g['id'] == a['id'])['last_used_at'], 'Last used not updated')
            status, _, _ = request(admin, endpoint + '/' + a['id'], 'DELETE', headers=auth)
            check(status == 200, 'HTTP revoke failed')
            status, _, _ = request(support, origin + '/wp-admin/')
            check(status == 302, 'Revoked cookie still accesses WP admin')
            status, _, _ = request(anonymous, a['url'])
            check(status == 403, 'Revoked link works')
            check(not json.loads(php('sessions', a['user_id'])), 'Revoked sessions remain')
            print('PASS magic login, real auth cookies, safe redirect, hash-free listing, session revocation', flush=True)

            expired, _ = client()
            status, _, _ = request(expired, b['url'])
            check(status == 302, 'Second grant fails')
            php('expire', b['id'])
            status, _, _ = request(expired, origin + '/wp-admin/')
            check(status in [302, 403], 'Expired cookie works without cron')
            status, _, _ = request(anonymous, b['url'])
            check(status == 403, 'Expired link works without cron')
            status, _, _ = request(anonymous, a['url'].replace(a['token'], 'a' * 64))
            check(status == 403, 'Forged link works')
            c = issue()
            remaining, _ = client()
            check(request(remaining, c['url'])[0] == 302, 'Pre-deactivation grant fails')
            php('deactivate')
            state = json.loads(php('state'))
            check(int(state['active']) == 0 and int(state['support_users']) == 0, 'Deactivation left active access/accounts')
            check(request(remaining, origin + '/wp-admin/')[0] == 302, 'Deactivated plugin leaves valid session')
            print('PASS expiry before cron, forged links, actual plugin deactivation and account/session cleanup', flush=True)
            print(php('network-install').strip(), flush=True)
            config_path = wp / 'wp-config.php'
            network_config = "define('MULTISITE', true); define('SUBDOMAIN_INSTALL', false);\n"
            network_config += "define('DOMAIN_CURRENT_SITE', '127.0.0.1'); define('PATH_CURRENT_SITE', '/');\n"
            network_config += "define('SITE_ID_CURRENT_SITE', 1); define('BLOG_ID_CURRENT_SITE', 1);\n"
            config_path.write_text(config_path.read_text().replace("$table_prefix = 'test_';", network_config + "$table_prefix = 'test_';"))
            print(php('multisite').strip(), flush=True)
            print('ALL TESTS PASSED (disposable WordPress/MySQL; HTTP, no browser automation)', flush=True)
        except BaseException:
            for name in ['http.log', 'mysql-server.log']:
                log = root / name
                if log.exists():
                    print(f'--- {name} ---\n{log.read_text()[-5000:]}')
            raise
        finally:
            for process in reversed(processes):
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
            for handle in handles:
                handle.close()


if __name__ == '__main__':
    main()
