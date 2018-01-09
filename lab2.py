import sys
import datetime
import os

class StreamCipherUtil:
    def __init__(self, input_file, output_file, key):
        self.key = key
        self.output_file = output_file
        self.input_file = input_file
        self.exec_time = None
        self.text_len = 0
        self.bit_stream = self._pm_rand()
        self.bit_len = 8
        self.file_text_len = os.stat(self.input_file).st_size

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
        for ch in text_stream:
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
            for index, ch in enumerate(text):
                f.write(ch)
                self.progress_bar(index, self.file_text_len)
                self.text_len += 1
            f.close()

if __name__ == '__main__':
    print("RC4 Encryption/Decryption utility.\n")
    while True:
        try:
            mode = int(input("Choose mode: \n1. Encryption\n2. Decryption\nEnter mode: "))
            input_filename = input("Enter input filename: ")
            output_filename = input("Enter output filename: ")
            key = input("Enter key [0-9a-zA-Zа-яА-Я]: ")
            s = StreamCipherUtil(key=[ord(ch) for ch in key], input_file=input_filename,
                         output_file=output_filename)
            data_stream = s.read_from_file()
            new_data_stream = None
            if mode is 1:
                new_data_stream = s.crypt_stream(data_stream)
            elif mode is 2:
                new_data_stream = s.crypt_stream(data_stream)
            s.write_to_file(new_data_stream)
            print("\nTime {0} chars/ms".format((s.exec_time.seconds*10**6+s.exec_time.microseconds)/s.text_len))
        except KeyboardInterrupt:
            print("\nQuit utility.Bye!\n")
            break
        except ValueError as e:
            print("\nError occured! {0}\n".format(e.args))