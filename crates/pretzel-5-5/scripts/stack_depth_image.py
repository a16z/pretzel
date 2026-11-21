"""Read arm64 Mach-O chained pointers without executing the image.

Only little-endian MH_MAGIC_64, DYLD_CHAINED_PTR_64_OFFSET and import format 1
are admitted. Unsupported encodings fail closed. The full image hash and every
instruction byte in the debugger inventory must agree before data is used.
"""
import hashlib
import struct
from pathlib import Path


class MachO:
    def __init__(self, path, image):
        self.data=Path(path).read_bytes()
        if hashlib.sha256(self.data).hexdigest()!=image['binary_sha256']:
            raise ValueError('Mach-O and instruction inventory hashes differ')
        self.sections=[];self.segments=[];self.fixups={};fix=None
        if self.unpack('<II',0)!=(0xfeedfacf,0x100000c):
            raise ValueError('Expected little-endian arm64 Mach-O')
        offset=32
        for _ in range(self.unpack('<I',16)[0]):
            cmd,size=self.unpack('<II',offset)
            if size<8:raise ValueError('Invalid load command')
            if cmd==0x19:
                name,address,n,fileoff,filesize=self.unpack('<16sQQQQ',offset+8)
                self.segments.append((address,n,fileoff,filesize))
                for j in range(self.unpack('<I',offset+64)[0]):
                    sec,seg,a,n,o=self.unpack('<16s16sQQI',offset+72+j*80)
                    self.sections.append(dict(name=seg.rstrip(b'\0').decode()+','+sec.rstrip(b'\0').decode(),address=a,size=n,offset=o))
            elif cmd==0x80000034:fix=self.unpack('<II',offset+8)
            offset+=size
        self.base=min(a for a,n,o,z in self.segments if z and o==0)
        for f in image['functions']:
            for ins in f['instructions']:
                if self.read(ins['address'],4).hex()!=ins['bytes']:
                    raise ValueError('Instruction bytes differ at '+hex(ins['address']))
        if fix is None:raise ValueError('No chained fixups')
        start,length=fix
        version,starts,imports,symbols,count,fmt,symfmt=self.unpack('<7I',start)
        if version or fmt!=1 or symfmt:raise ValueError('Unsupported chained fixups header')
        names=[]
        for j in range(count):
            word=self.unpack('<I',start+imports+4*j)[0]
            off=start+symbols+(word>>9)
            end=self.data.index(b'\0',off,start+length)
            names.append(self.data[off:end].decode())
        st=start+starts;nseg=self.unpack('<I',st)[0]
        for relative in self.unpack('<'+'I'*nseg,st+4):
            if not relative:continue
            entry=st+relative
            size,page,kind,segoff,maxptr,npage=self.unpack('<IHHQIH',entry)
            if kind!=6:raise ValueError('Unsupported chained pointer format')
            for p,head in enumerate(self.unpack('<'+'H'*npage,entry+22)):
                if head==0xffff:continue
                if head&0x8000:raise ValueError('Multi-start page unsupported')
                address=self.base+segoff+p*page+head;seen=set()
                while True:
                    if address in seen or not self.base+segoff+p*page<=address<self.base+segoff+(p+1)*page:
                        raise ValueError('Invalid chained pointer walk')
                    seen.add(address);word=int.from_bytes(self.read(address,8),'little')
                    record=dict(word=hex(word),pointer_format=kind)
                    if word>>63:
                        ordinal=word&0xffffff
                        if ordinal>=len(names) or ((word>>24)&0x7ffffff):raise ValueError('Unsupported bind ordinal/addend')
                        record['import']=names[ordinal]
                    else:
                        if (word>>36)&0x7fff:raise ValueError('Nonzero high/reserved pointer bits')
                        record['target']=self.base+(word&((1<<36)-1))
                    self.fixups[address]=record
                    step=(word>>51)&0xfff
                    if not step:break
                    address+=step*4

    def unpack(self,fmt,offset):return struct.unpack_from(fmt,self.data,offset)

    def read(self,address,size):
        for a,n,o,z in self.segments:
            if a<=address and address+size<=a+z:return self.data[o+address-a:o+address-a+size]
        raise ValueError('Address outside file-backed segments: '+hex(address))

    def section(self,address,size=8):
        return next((s for s in self.sections if s['address']<=address and address+size<=s['address']+s['size']),None)

    def pointer(self,address):
        if address not in self.fixups:raise ValueError('Pointer has no chained fixup: '+hex(address))
        return self.fixups[address]
