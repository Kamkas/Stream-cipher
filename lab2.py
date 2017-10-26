import sys
import datetime


class StreamCipherUtil:
    def __init__(self, input_file, output_file, key):
        self.key = key
        self.output_file = output_file
        self.input_file = input_file
        self.exec_time = None
        self.text_len = 0
        self.bit_stream = self._pm_rand()
        self.bit_len = 8

    @staticmethod
    def progress_bar(count, total, suffix=''):
        bar_len = 60
        filled_len = int(round(bar_len * count / float(total)))
        percents = round(100.0 * count / float(total), 1)
        bar = '=' * filled_len + '-' * (bar_len - filled_len)
        sys.stdout.write('[%s] %s%s ...%s\r' % (bar, percents, '%', suffix))
        sys.stdout.flush()

    def _pm_rand(self):
        IA = 16807
        IM = 2147483647
        a = (2 ** 31 - 1) // 2
        prev_value = IA * self.hash_key() % IM
        next_value = 0
        while True:
            next_value = IA * prev_value % IM
            prev_value = next_value
            if next_value < a + 1:
                yield '0'
            else:
                yield '1'

    def gen_custom_prng_bit_seq(self):
        bit_seq = ""
        for index in range(self.bit_len):
            bit_seq += next(self.bit_stream)
        return int(bit_seq, 2)

    def crypt_stream(self, text_stream):
        start = datetime.datetime.now()
        for index, ch in enumerate(text_stream):
            yield chr(ord(ch) ^ self.gen_custom_prng_bit_seq())
        stop = datetime.datetime.now()
        self.exec_time = stop - start

    def hash_key(self):
        import hashlib
        return int(hashlib.sha256(str(self.key).encode('utf-16')).hexdigest(), 16) % (2 ** 31 - 1)

    def read_from_file(self):
        text = ""
        with open(self.input_file, 'r', newline='') as f:
            text = f.read()
            f.close()
        return text

    def write_to_file(self, text):
        with open(self.output_file, 'w', newline='') as f:
            for ch in text:
                f.write(ch)
                self.text_len += 1
            f.close()


if __name__ == '__main__':
    s1 = StreamCipherUtil(key=[ord(ch) for ch in "улгтуивтвмбд-41"], input_file="lin_dec",
                          output_file="dec")
    s2 = StreamCipherUtil(key=[ord(ch) for ch in "улгтуивтвмбд-41"], input_file="dec",
                          output_file="loutput")

    s1.write_to_file(s1.crypt_stream(s1.read_from_file()))
    s2.write_to_file(s2.crypt_stream(s2.read_from_file()))
