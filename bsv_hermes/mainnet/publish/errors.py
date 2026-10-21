"""Stable, non-sensitive error codes only."""
class PublishError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)
