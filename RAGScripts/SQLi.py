class SQLInjectionScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.target = None

    def run(self):