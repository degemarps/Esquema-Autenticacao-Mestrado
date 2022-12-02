import psutil
import time

def bytes_to_mega(value):
  return f'{value / 1024 / 1024: .2f}MB'

while True:
  memory = bytes_to_mega(psutil.virtual_memory().used)
  cpu = psutil.cpu_percent()

  with open('results.txt', 'a') as file:
    file.write(f'{memory} - {cpu}\n')
  
  time.sleep(0.5)