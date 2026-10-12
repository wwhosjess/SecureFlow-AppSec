"""Observe the synthetic loopback scan; never change scanner policy or alerts."""
import gzip
import json
import shutil
from pathlib import Path


def zap_pre_shutdown(zap):
    out = Path('/zap/wrk')
    seen = set()
    with gzip.open(out / 'http-messages.jsonl.gz', 'wt', encoding='utf-8') as stream:
        def save(messages):
            for message in messages:
                if not isinstance(message, dict) or 'id' not in message:
                    raise ValueError('Invalid ZAP message response')
                if message['id'] not in seen:
                    stream.write(json.dumps(message) + '\n')
                    seen.add(message['id'])
        start = 0
        while True:
            page = zap.core.messages(baseurl='http://127.0.0.1:5050', start=start, count=500)
            save(page)
            if len(page) < 500:
                break
            start += len(page)
        for scan in zap.ascan.scans:
            ids = [str(i) for i in zap.ascan.messages_ids(scan['id']) if str(i) not in seen]
            for start in range(0, len(ids), 100):
                save(zap.core.messages_by_id(','.join(ids[start:start + 100])))
    (out / 'diagnostics.json').write_text(json.dumps({
        'status': 'completed', 'message_count': len(seen),
        'zap_version': zap.core.version, 'zap_home': zap.core.zap_home_path,
        'active_scans': zap.ascan.scans,
        'network_stats': zap.stats.stats(keyprefix='stats.network.'),
    }, indent=2), encoding='utf-8')
    # Keep rotated debug logs too; never copy the ZAP home (contains private keys).
    for log in Path(zap.core.zap_home_path).glob('zap.log*'):
        shutil.copyfile(log, out / ('internal-' + log.name))
