"""Safe errors: never include provider bodies, prompts, or source content."""


class GuardError(Exception):
    def __init__(self, reason_code: str, *, usage=None):
        self.reason_code = reason_code
        self.usage = usage
        super().__init__(reason_code)


class ContractUnavailable(RuntimeError):
    pass
