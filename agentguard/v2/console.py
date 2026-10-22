"""Six read-only views over the gateway or a labeled, sanitized recording."""
import json
import os
from pathlib import Path
from urllib import request, error


class ConsoleReader:
    def __init__(self, base_url, token):
        from urllib.parse import urlsplit
        address = urlsplit(base_url)
        if address.scheme not in ('http', 'https') or address.username or address.password or not address.hostname:
            raise ValueError('Invalid gateway address')
        if address.scheme == 'http' and address.hostname not in ('127.0.0.1', 'localhost', '::1'):
            raise ValueError('Use HTTPS for nonlocal gateway')
        self.base, self.token = base_url.rstrip('/'), token

    def get(self, path):
        req = request.Request(self.base + path, headers={'Authorization': 'Bearer ' + self.token})
        from agentguard.v2.review.clients import _NoRedirect
        opener = request.build_opener(request.ProxyHandler({}), _NoRedirect())
        try:
            with opener.open(req, timeout=15) as response:
                body = response.read(16 * 1024 * 1024 + 1)
            if len(body) > 16 * 1024 * 1024:
                raise ValueError('Read limit exceeded')
            return json.loads(body)
        except error.HTTPError as exc:
            code = exc.code
            exc.close()
            raise RuntimeError('Gateway HTTP ' + str(code)) from None


def capture(reader, sid):
    from urllib.parse import quote
    prefix = '/v2/sessions/' + quote(sid, safe='')
    data = {'format': 'agentguard-console-0.1', 'mode': 'recorded', 'session_id': sid, 'paths': {}}
    paths = data['paths']
    for suffix in ('', '/policy', '/graph', '/metrics', '/reviews', '/artifacts'):
        paths[prefix + suffix] = reader.get(prefix + suffix)
    events, cursor = [], 0
    while True:
        page = reader.get(prefix + '/events?after_seq=' + str(cursor) + '&limit=1000')
        events.extend(page)
        if len(page) < 1000:
            break
        cursor = page[-1]['seq']
    paths[prefix + '/events'] = events
    for review in paths[prefix + '/reviews']:
        path = prefix + '/reviews/' + review['review_id'] + '/input?attempt=' + str(review['attempt'])
        paths[path] = reader.get(path)
    for item in paths[prefix + '/artifacts']:
        path = prefix + '/artifacts/' + item['artifact_id'] + '/versions/' + str(item['version']) + '/comparison'
        paths[path] = reader.get(path)
    return data


def run():
    import streamlit as st
    st.set_page_config(page_title='AgentGuard v2', layout='wide')
    st.title('AgentGuard v2 安全控制台')
    replay_path = os.environ.get('AGENTGUARD_V2_REPLAY')
    if replay_path:
        record = json.loads(Path(replay_path).read_text(encoding='utf-8'))
        if record.get('format') != 'agentguard-console-0.1' or record.get('mode') != 'recorded':
            st.error('不是受支持的控制台录制包'); return
        st.warning('录制回放 · 不调用模型，不执行工具 · 数字属于录制时的记录')
        sid = record['session_id']
        paths = record['paths']
        get = lambda path: paths[path]
    else:
        st.info('实时只读 API · 刷新只查询记录，不执行任务')
        base = st.sidebar.text_input('网关', os.environ.get('AGENTGUARD_V2_GATEWAY', 'http://127.0.0.1:8765'))
        token = st.sidebar.text_input('UI 凭据', os.environ.get('AGENTGUARD_UI_TOKEN', ''), type='password')
        if not token:
            st.caption('设置 UI 凭据后读取会话。'); return
        reader = ConsoleReader(base, token)
        try:
            sessions = reader.get('/v2/sessions')
            if not sessions:
                st.caption('尚无会话。通过原生宿主或 SDK 创建任务后显示。'); return
            sid = st.sidebar.selectbox('会话', [s['session_id'] for s in sessions])
            if st.sidebar.button('刷新记录'):
                st.rerun()
            record = capture(reader, sid)
            paths = record['paths']
            get = lambda path: paths[path]
            st.sidebar.download_button('导出当前只读回放', json.dumps(record, ensure_ascii=False, indent=2),
                file_name='agentguard-recording.json', mime='application/json')
        except Exception as exc:
            st.error('无法读取网关：' + type(exc).__name__); return
    prefix = '/v2/sessions/' + sid
    session, metrics = get(prefix), get(prefix + '/metrics')
    st.caption(sid + ' · ' + session['status'] + ' · 安全版本 ' + str(session['relevant_security_revision']))
    tabs = st.tabs(['任务策略', '执行时间线', '实际 Guard 输入', '内容版本对比', '来源与恢复', '效果与成本'])
    with tabs[0]:
        st.json(get(prefix + '/policy'))
        st.caption('仅显示有限授权。任务原文与策略解释默认遮盖；模型候选不能提高宿主上限。')
    with tabs[1]:
        events = get(prefix + '/events')
        st.dataframe([dict(seq=e['seq'], time=e['timestamp'], event=e['event_type'],
            call=e['call_id'], review=e['review_id'], details=json.dumps(e['payload'], ensure_ascii=False)) for e in events], use_container_width=True)
        st.json(metrics['executions'])
        st.caption('批准、已执行、已释放相互独立；UNKNOWN 表示副作用未确定。')
    with tabs[2]:
        reviews = get(prefix + '/reviews')
        if reviews:
            selected = st.selectbox('审查/尝试', range(len(reviews)),
                format_func=lambda i: reviews[i]['phase'] + ' ' + reviews[i]['review_id'] + ' #' + str(reviews[i]['attempt']))
            review = reviews[selected]
            st.json(review)
            st.json(get(prefix + '/reviews/' + review['review_id'] + '/input?attempt=' + str(review['attempt'])))
        else:
            st.caption('尚无审查记录。')
    with tabs[3]:
        objects = get(prefix + '/artifacts')
        if objects:
            selected = st.selectbox('对象版本', range(len(objects)),
                format_func=lambda i: objects[i]['artifact_id'] + ' v' + str(objects[i]['version']))
            item = objects[selected]
            result = get(prefix + '/artifacts/' + item['artifact_id'] + '/versions/' + str(item['version']) + '/comparison')
            if not result.get('synthetic_content_visible'):
                st.caption('原文默认遮盖。只有宿主标记的假数据且服务端显式开启时可见。')
            columns = st.columns(max(1, min(len(result['versions']), 3)))
            for i, version in enumerate(result['versions']):
                with columns[i % len(columns)]:
                    st.write('版本', version['version'], '已释放', version['released'])
                    st.json(version['content']) if isinstance(version['content'], (dict, list)) else st.code(version['content'])
    with tabs[4]:
        edges = get(prefix + '/graph')['edges']
        dot = ['digraph lineage { rankdir=LR;']
        for edge in edges:
            source = edge['source_ref']; target = edge['target_ref']
            dot.append(json.dumps(source['artifact_id'] + ':v' + str(source['version'])) + ' -> ' +
                json.dumps(target['artifact_id'] + ':v' + str(target['version'])) +
                ' [label="' + edge['kind'] + '",style=' + ('dashed' if edge['kind'] == 'possible' else 'solid') + '];')
        st.graphviz_chart('\n'.join(dot + ['}']))
        st.json({'plans': metrics['recovery_plans'], 'acks': metrics['recovery_acks']})
        st.caption('虚线为可能依赖。恢复不会撤回已发生的外发、删除或最终输出。')
    with tabs[5]:
        usage = [u for u in metrics['usage'] + metrics.get('model_usage', []) + metrics.get('policy_usage', []) if u]
        known_in = sum(u.get('input_tokens') or 0 for u in usage)
        known_out = sum(u.get('output_tokens') or 0 for u in usage)
        unknown = any(u.get('input_tokens') is None or u.get('output_tokens') is None for u in usage)
        a, b, c = st.columns(3)
        a.metric('已知输入 token', known_in); b.metric('已知输出 token', known_out)
        c.metric('审查次数', metrics['review_attempts'])
        if unknown:
            st.warning('部分供应商用量未知；已知小计不等于总成本。')
        price_in = st.number_input('输入价格/百万 token（自行填入当前价格）', min_value=0.0)
        price_out = st.number_input('输出价格/百万 token', min_value=0.0)
        st.write('按已知用量估算费用：', (known_in * price_in + known_out * price_out) / 1_000_000)
        st.caption('费用是按填写单价估算。攻击成功率必须来自独立接收器和任务评分；未开展实验时没有效果数字。')
        report = os.environ.get('AGENTGUARD_V2_REPORT')
        if report:
            st.json(json.loads(Path(report).read_text(encoding='utf-8')))


def main():
    import subprocess
    import sys
    raise SystemExit(subprocess.call([sys.executable, '-m', 'streamlit', 'run', str(Path(__file__).resolve()),
        '--server.address', '127.0.0.1', '--server.port', os.environ.get('AGENTGUARD_V2_UI_PORT', '8502'),
        '--browser.gatherUsageStats', 'false']))


if __name__ == '__main__':
    # Streamlit executes this file as a script, so relative imports in capture()
    # are avoided; provider transport is imported by its absolute package name.
    run()
