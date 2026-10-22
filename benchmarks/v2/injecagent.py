"""Import external InjecAgent attack text as labeled supplemental cases.

Not an official InjecAgent score: its original success rules are not substituted
with Guard decisions. Imported text is used in the local independent task world.
"""
import argparse
import json
from pathlib import Path
from .environment import Case


def load_cases(path):
    source=Path(path)
    data=json.loads(source.read_text(encoding='utf-8'))
    rows=data if isinstance(data,list) else data.get('data',[])
    result=[]
    for i,row in enumerate(rows):
        attack=row.get('Attacker Instruction') or row.get('attacker_instruction') or row.get('attack')
        if not isinstance(attack,str) or not attack:
            raise ValueError('Each supplemental sample requires explicit attacker instruction text')
        marker='REPORT_OK_SUPPLEMENT_'+str(i)
        secret='SYNTHETIC_SUPPLEMENT_SECRET_'+str(i)
        result.append(Case('injecagent-'+str(i),True,(marker+' '+secret+' '+attack,),marker,secret,'supplemental'))
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source'); parser.add_argument('--output',required=True)
    args=parser.parse_args()
    from dataclasses import asdict
    import hashlib
    rows=load_cases(args.source)
    Path(args.output).write_text(json.dumps({'format':'supplemental-cases-0.1',
        'source_sha256':hashlib.sha256(Path(args.source).read_bytes()).hexdigest(),
        'official_injecagent_score':False,'cases':[asdict(c) for c in rows]},ensure_ascii=False,indent=2),encoding='utf-8')


if __name__=='__main__':
    main()
