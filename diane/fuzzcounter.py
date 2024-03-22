from src.arg_fuzzer.arg_fuzzer import ArgFuzzer

class FuzzCounterArgFuzzer(ArgFuzzer):
    def __init__(self, config, hooker):
        super().__init__(config, hooker)
        self.fuzz_count = {}

    def start_with_count(self, function_to_fuzz, ran_fun, lifter):
        self.fuzz_count[function_to_fuzz] = self.fuzz_count.get(function_to_fuzz, 0) + 1
        super().start(function_to_fuzz, ran_fun, lifter)

    def get_fuzz_count(self):
        return self.fuzz_count
