"""Recompute JSON/Markdown/CSV reports from saved independent run outcomes."""
import argparse
import csv
import json
from pathlib import Path
from .scoring import report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory'); parser.add_argument('--input-price',type=float); parser.add_argument('--output-price',type=float)
    args=parser.parse_args()
    root=Path(args.directory)
    rows=json.loads((root/'runs.json').read_text(encoding='utf-8'))
    manifest=json.loads((root/'manifest.json').read_text(encoding='utf-8'))
    modes={r['mode'] for r in rows}
    if len(modes)>1 or (modes and manifest['mode'] not in modes):
        raise ValueError('Do not mix scripted and live outcomes')
    valid=[r for r in rows if r.get('comparable',True)]
    result=report(valid,input_price=args.input_price,output_price=args.output_price)
    result.update(manifest=manifest,mode=manifest['mode'],model_effectiveness_measured=manifest['mode']=='live',
                  excluded_noncomparable=len(rows)-len(valid))
    (root/'report.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    with (root/'runs.csv').open('w',encoding='utf-8-sig',newline='') as handle:
        fields=['case_id','variant','mode','split','task_success','attack_success','unknown','unauthorized_send','latency_ms','executed_calls','comparable','error']
        writer=csv.DictWriter(handle,fields,extrasaction='ignore'); writer.writeheader(); writer.writerows(rows)
    lines=['# AgentGuard evaluation','', 'Mode: '+manifest['mode'], '',
        '| Variant | Normal success | Attack success | Known attack denominator | p50 / p95 ms |',
        '|---|---:|---:|---:|---:|']
    for name,item in result['groups'].items():
        normal=item['normal_success']; attack=item['attack_success']; latency=item['latency_ms']
        lines.append(f"| {name} | {normal['rate']} | {attack['rate']} | {attack['denominator']} | {latency['p50']} / {latency['p95']} |")
    lines+=['','Unknown outcomes and excluded tasks remain in runs.json. Scripted runs do not measure model effectiveness.']
    (root/'report.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')


if __name__=='__main__':
    main()
