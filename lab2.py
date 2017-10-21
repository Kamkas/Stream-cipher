import sys
import datetime


class StreamCipherUtil:
    def __init__(self, input_file, output_file, key):
        self.key = key
        self.output_file = output_file
        self.input_file = input_file
        self.exec_time = None
        self.text_len = 0

    @staticmethod
    def progress_bar(count, total, suffix=''):
        bar_len = 60
        filled_len = int(round(bar_len * count / float(total)))
        percents = round(100.0 * count / float(total), 1)
        bar = '=' * filled_len + '-' * (bar_len - filled_len)
        sys.stdout.write('[%s] %s%s ...%s\r' % (bar, percents, '%', suffix))
        sys.stdout.flush()

    def init_s_block(self):
        s_block = list(range(256))
        index_j = 0
        for index_i in range(256):
            index_j = (index_j + s_block[index_i % len(self.key)]) % 256
            s_block[index_i], s_block[index_j] = s_block[index_j], s_block[index_i]
        return s_block

    def pseudo_rand_gen(self, s_block):
        index_i, index_j = 0, 0
        while True:
            index_i = (index_i + 1) % 256
            index_j = (index_j + s_block[index_i]) % 256
            s_block[index_i], s_block[index_j] = s_block[index_j], s_block[index_i]
            yield ((s_block[s_block[index_i]] + s_block[index_j]) % 256)

    def encrypt(self, text):
        block = self.init_s_block()
        key_stream = self.pseudo_rand_gen(block)
        start = datetime.datetime.now()
        for index, ch in enumerate(text):
            yield chr(ord(ch) ^ next(key_stream))
        stop = datetime.datetime.now()
        self.exec_time = stop - start

    def decrypt(self, encrypt_text):
        block = self.init_s_block()
        key_stream = self.pseudo_rand_gen(block)
        start = datetime.datetime.now()
        for index, ch in enumerate(encrypt_text):
            yield chr(ord(ch) ^ next(key_stream))
        stop = datetime.datetime.now()
        self.exec_time = stop - start

    def read_from_file(self):
        with open(self.input_file, 'r') as f:
            text = f.read()
            f.close()
            return text

    def write_to_file(self, text):
        with open(self.output_file, 'w') as f:
            for ch in text:
                f.write(ch)
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
            if mode is 1:
                new_data_stream = s.encrypt(data_stream)
            elif mode is 2:
                new_data_stream = s.decrypt(data_stream)
            s.write_to_file(new_data_stream)
            print("Time {0} chars/ms".format((s.exec_time.seconds*10**6+s.exec_time.microseconds)/s.text_len))
        except KeyboardInterrupt:
            print("\nQuit utility.Bye!\n")
            break
        except ValueError as e:
            print("\nError occured! {0}\n".format(e.args))