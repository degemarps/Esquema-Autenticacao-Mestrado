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

# psutil.net_io_counters(pernic=True)

# psutil.cpu_times()
# scputimes(user=17411.7, nice=77.99, system=3797.02, idle=51266.57, iowait=732.58, irq=0.01, softirq=142.43, steal=0.0, guest=0.0, guest_nice=0.0)

# >>> psutil.net_io_counters()
# snetio(bytes_sent=14508483, bytes_recv=62749361, packets_sent=84311, packets_recv=94888, errin=0, errout=0, dropin=0, dropout=0)
# >>>
# >>> psutil.net_io_counters(pernic=True)
# {'lo': snetio(bytes_sent=547971, bytes_recv=547971, packets_sent=5075, packets_recv=5075, errin=0, errout=0, dropin=0, dropout=0),
# 'wlan0': snetio(bytes_sent=13921765, bytes_recv=62162574, packets_sent=79097, packets_recv=89648, errin=0, errout=0, dropin=0, dropout=0)}

# >>> mem = psutil.virtual_memory()
# >>> mem
# svmem(total=10367352832, available=6472179712, percent=37.6, used=8186245120, free=2181107712, active=4748992512, inactive=2758115328, buffers=790724608, cached=3500347392, shared=787554304, slab=199348224)