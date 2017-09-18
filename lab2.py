import sys
import datetime

class StreamCipherUtil():
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

    def init_s_block(self, key):
        print_progress = StreamCipherUtil()
        s_block_arr = list()
        print("Start initialize S-block ...")
        for index in range(2 ** 8 - 1):
            s_block_arr.append(index)
            print_progress.progress_bar(index, 2 ** 8 - 1)
        print("Done!")
        index_j = 0
        print("Start swap elements ...")
        for index in range(2 ** 8 - 1):
            index_j = (index_j + key[index % len(key)] + s_block_arr[index]) % 2 ** 8
            s_block_arr[index], s_block_arr[index_j] = s_block_arr[index_j], s_block_arr[index]
            print_progress.progress_bar(index, 2 ** 8 - 1)
        print("Done!")
        return s_block_arr

    @staticmethod
    def gen_pseudo_random_k(s_block_arr):
        print("Starting generate pseudo-random K word ...")
        index_i, index_j = 0, 0
        while True:
            index_i = (index_i + 1) % 2 ** 8
            index_j = (index_j + s_block_arr[index_i]) % 2 ** 8
            s_block_arr[index_i], s_block_arr[index_j] = s_block_arr[index_j], s_block_arr[index_i]
            k = s_block_arr[(s_block_arr[index_i] + s_block_arr[index_j]) % 2 ** 8]
            print("Done!")
            yield k

    def rc4_encrypt(self, text, key):
        print("Starting RC4 Encryption ...")
        key = [ord(ch) for ch in key]
        key_stream = self.gen_pseudo_random_k(self.init_s_block(key))
        # [ord(ch) ^ next(key_stream) for ch in text]
        start = datetime.datetime.now()
        decrypt_text = [ord(ch) ^ next(key_stream) for ch in text]
        stop = datetime.datetime.now()
        print("Done!")
        print("Speed RC4 Encryption is %d char\\/mcs" % (len(text) / (stop.microsecond - start.microsecond)))
        return decrypt_text

    def rc4_decrypt(self, decrypt_text, key):
        print("Starting RC4 Decryption ...")
        key = [ord(ch) for ch in key]
        key_stream = self.gen_pseudo_random_k(self.init_s_block(key))
        # [ord(ch) ^ next(key_stream) for ch in text]
        start = datetime.datetime.now()
        text = [chr(value ^ next(key_stream)) for value in decrypt_text]
        stop = datetime.datetime.now()
        print("Done!")
        print("Speed RC4 Decryption is %d char\\/mcs" % (len(decrypt_text) / (stop.microsecond - start.microsecond)))
        return text

    def read_from_file(self):
        text = ""
        with open(self.input_file, 'r') as f:
            text = f.read()
            f.close()
        return text

    def write_to_file(self, text):
        with open(self.output_file, 'w+') as f:
            f.write(text)
            f.close()


if __name__ == '__main__':
    