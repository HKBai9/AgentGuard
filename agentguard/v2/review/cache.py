"""Bounded analysis cache. No execution permits or release capabilities."""
from collections import OrderedDict
from copy import deepcopy
from time import monotonic
from ..common import digest


class AnalysisCache:
    def __init__(self, capacity=256, ttl_seconds=300):
        if capacity < 1 or ttl_seconds <= 0:
            raise ValueError('Invalid cache limits')
        self.capacity, self.ttl = capacity, ttl_seconds
        self._items = OrderedDict()

    @staticmethod
    def key(request, *, model, destination_id, prompt_version):
        data = deepcopy(request)
        data.pop('review_id', None)
        # Byte count changes with the new review identifier; it is packaging
        # metadata, not an authorization or semantic input. Selection is bound.
        data.pop('budget_used', None)
        return digest({'request': data, 'model': model, 'destination': destination_id, 'prompt': prompt_version})

    def get(self, key):
        item = self._items.get(key)
        if not item:
            return None
        if monotonic() - item[0] >= self.ttl:
            self._items.pop(key, None)
            return None
        self._items.move_to_end(key)
        return deepcopy(item[1])

    def put(self, key, analysis):
        self._items[key] = (monotonic(), deepcopy(analysis))
        self._items.move_to_end(key)
        while len(self._items) > self.capacity:
            self._items.popitem(last=False)

    def clear_session(self, session_id):
        for key, (_, value) in list(self._items.items()):
            if value.get('session_id') == session_id:
                del self._items[key]
