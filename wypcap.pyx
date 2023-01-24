cdef extern from 'pcap.h':
  ctypedef struct pcap_if_t:
    pcap_if_t *next
    char *name
    char *description

cdef extern from 'pcap.h':
  int pcap_findalldevs (pcap_if_t **devs, char *errbuf)
  void pcap_freealldevs (pcap_if_t *devs)

def findalldevs ():
  cdef pcap_if_t *devs
  cdef pcap_if_t *cur
  cdef char ebuf[256]

  status = pcap_findalldevs(&devs, ebuf)
  if status:
    raise OSError(ebuf)
  cur = devs

  ret = []
  while True:
    ret.append((str(cur.name.decode()), str(cur.description.decode())))
    if not cur.next:
      break
    cur = cur.next
  
  pcap_freealldevs(devs)

  return ret
