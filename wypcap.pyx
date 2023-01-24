ctypedef unsigned int u_int
ctypedef unsigned char u_char

cdef extern from 'pcap.h':
  cdef int PCAP_OPENFLAG_PROMISCUOUS

cdef extern from 'pcap.h':
  ctypedef struct pcap_if_t:
    pcap_if_t *next
    char *name
    char *description

cdef extern from 'pcap.h':
  int pcap_findalldevs (pcap_if_t **devs, char *errbuf)
  void pcap_freealldevs (pcap_if_t *devs)
  void *pcap_create (const char *, char *);
  int pcap_activate (void *p)
  void *pcap_open (const char *source, int snaplen, int flags, int read_timeout, void *auth, char *errbuf)
  void *pcap_open_live (const char *, int, int, int, char *)
  int pcap_set_snaplen (void *pcap_id, int snaplen)
  int pcap_set_promisc (void *pcap_id, int promisc)
  int pcap_set_timeout (void *pcap_id, int ms)
  int pcap_sendpacket (void *pcap_id, const u_char *buf, int size)

cdef class pcap:
  cdef void *pcap_id
  cdef char *name
  cdef char errbuf[256]

  def __init__ (self, name, snaplen=65535, promisc=True, timeout_ms=0):
    self.pcap_id = pcap_create(name.encode(), self.errbuf)
    pcap_set_snaplen(self.pcap_id, snaplen)
    pcap_set_promisc(self.pcap_id, promisc)
    pcap_set_timeout(self.pcap_id, timeout_ms)
    pcap_activate(self.pcap_id)

    # self.pcap_id = pcap_open_live(name.encode(), snaplen, promisc, timeout_ms, self.errbuf)
    # self.pcap_id = pcap_open(name.encode('utf-8'), snaplen, PCAP_OPENFLAG_PROMISCUOUS, timeout_ms, NULL, self.errbuf)
    if self.pcap_id == NULL:
      raise OSError
  
  def sendpacket (self, buf):
    ret = pcap_sendpacket(self.pcap_id, buf, <int>len(buf))
    if ret == -1:
      raise OSError
    return len(buf)

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
