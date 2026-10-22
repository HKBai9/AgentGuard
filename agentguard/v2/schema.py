"""Offline JSON Schema export; contains no provider clients or credentials."""
import json
from importlib.resources import files
from pathlib import Path
from . import contracts


def export(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    names = []
    for name, cls in vars(contracts).items():
        if isinstance(cls, type) and issubclass(cls, contracts.Wire) and cls is not contracts.Wire:
            schema = cls.model_json_schema()
            schema['$schema'] = 'https://json-schema.org/draft/2020-12/schema'
            (directory / (name+'.json')).write_text(json.dumps(schema, ensure_ascii=False, indent=2)+'\n', encoding='utf-8', newline='\n')
            names.append(name)
    return sorted(names)


def load(name):
    if not name.isidentifier():
        raise ValueError('invalid schema name')
    return json.loads(files('agentguard.v2.schemas').joinpath(name+'.json').read_text(encoding='utf-8'))


if __name__ == '__main__':
    import sys
    export(sys.argv[1])
