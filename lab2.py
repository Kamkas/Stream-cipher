import sys
import datetime

class StreamCipherUtil:
    def __init__(self, input_file, output_file, key):
        self.key = key
        self.output_file = output_file
        self.input_file = input_file

    @staticmethod
    def progress_bar(count, total, suffix=''):
        bar_len = 60
        filled_len = int(round(bar_len * count / float(total)))
        percents = round(100.0 * count / float(total), 1)
        bar = '=' * filled_len + '-' * (bar_len - filled_len)

        sys.stdout.write('[%s] %s%s ...%s\r' % (bar, percents, '%', suffix))
        sys.stdout.flush()

    def init_s_block(self):
        s_block = [num for num in range(256)]
        index_j = 0
        for index_i in range(256):
            index_j = (index_j + s_block[index_i % len(self.key)]) % 256
            s_block[index_i], s_block[index_j] = s_block[index_j], s_block[index_i]
        return s_block

    def pseudo_rand_gen(self, text_len, s_block):
        keystream = list()
        index_i, index_j = 0, 0
        for index_k in range(text_len):
            index_i = (index_i + 1) % 256
            index_j = (index_j + s_block[index_i]) % 256
            s_block[index_i], s_block[index_j] = s_block[index_j], s_block[index_i]
            keystream.append((s_block[s_block[index_i]] + s_block[index_j]) % 256)
        return keystream

    def encrypt(self, text):
        block = self.init_s_block()
        key_stream = self.pseudo_rand_gen(len(text), block)
        encrypt_text = [chr(ord(ch) ^ key_stream[index]) for index, ch in enumerate(text)]
        return encrypt_text

    def decrypt(self, encrypt_text):
        text = self.encrypt(encrypt_text)
        return text

    def read_from_file(self):
        text = ""
        with open(self.input_file, 'r') as f:
            text = f.read()
            f.close()
        return text

    def write_to_file(self, text):
        with open(self.output_file, 'w') as f:
            f.write(text)
            f.close()


if __name__ == '__main__':
    s = StreamCipherUtil(key = [ord(ch) for ch in "s6df8s8d6f8s7d68sd68fs6d78s"], input_file="lin_dec", output_file="output")
    orig_text = s.read_from_file()
    enc_t = s.encrypt(orig_text)
    text = s.decrypt(enc_t)
    s.write_to_file("".join(text))