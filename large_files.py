def line_by_line():
    with open('large_file.txt', 'r') as file:
        for line in file:
            process(line)
            
def read_file_in_chunks(file_path, chunk_size=1024):
    with open(file_path, 'r') as file:
        while True:
            chunk = file.read(chunk_size)
            if not chunk:
                break
            process(chunk)
            
def buffering():
    
    with open('large_file.txt', 'rb', buffering=10 * 1024 * 1024) as file:  # 10 Мб буфер
        for line in file:
            process(line)
            
from mmap import mmap

def mapping():
    with open('large_file.txt', 'r') as file:
        with mmap(file.fileno(), length=0, access=mmap.ACCESS_READ) as mm:
            for line in mm:
                process(line.decode('utf-8'))
            
#using_lazy_generators
def generate_lines(file_path):
    with open(file_path, 'r') as file:
        for line in file:
            yield line
def run():
    for line in generate_lines('large_file.txt'):
        process(line)
    
def read_batches(file_path, batch_size=5):
    with open(file_path, 'r') as file:
        batch = []
        for line in file:
            batch.append(line.strip())
            if len(batch) == batch_size:
                yield batch
                batch = []
        if batch:
            yield batch

def batch_example():
    for batch in read_batches('cars.txt'):
        process_batch(batch)