#mitmdump addon script to decode apple ios connections
import avro.schema
from avro.datafile import DataFileReader, DataFileWriter
from avro.io import DatumReader, DatumWriter
import io

from mitmproxy import http
import zlib
import gzip
import subprocess
from codecs import encode, decode
from google.protobuf.internal.decoder import _DecodeVarint32
import operator
import tarfile
from Crypto.Cipher import AES
import base64

def gunzip_string(the_body):
    proc = subprocess.Popen('gunzip',stdout=subprocess.PIPE, 
    stdin=subprocess.PIPE, stderr=subprocess.DEVNULL)
    proc.stdin.write(the_body)
    proc.stdin.close()
    body = proc.stdout.read()
    proc.wait()
    return body

def decode_avro(content):
    print("unzipping avro")
    #buf=zlib.decompress(content,32 + zlib.MAX_WBITS)
    buf=gunzip_string(content)
    #print(buf)
    print("header: ",int.from_bytes(buf[0:8],'little',signed=True),"(should be -3654979820883293071)")
    bytes_reader = io.BytesIO(buf[8:])
    decoder = avro.io.BinaryDecoder(bytes_reader)
    f = open('addon/schema.json', 'r')
    schema = avro.schema.parse(f.read())
    f.close()
    reader = DatumReader(schema)
    while True:
        try:
            print(reader.read(decoder))
        except:
            break

def decode_aes(buf):
    #qihoo
    #key="[B@a6318c2".encode("utf-8")
    #IV="[B@229f210".encode("utf-8")
    #cipher = AES.AESCipher(key, AES.MODE_CBC, IV)
    #plaintext = cipher.decrypt(buf)
    #print(plaintext)

    # avast
    #key = base64.b64decode("d8Pvct+Vak9QiajoRQHyXZsulQyCYpCEEKgoyn47ASQ=");
    #key=base64.b64decode("VDVbq2icEliWOjCkThgrWzoTjuLIvapY6ith1lnlbig=");
    #test8.mitm, logcat14.txt
    #key=base64.b64decode("BUuWxsim/NI0O9+B7iKUeLN2+cR+vQENAkz8y6RM0vg=")
    #key=base64.b64decode("9I4upHsmJP8jdJ2wQYyXFhPYr7jq8j4ctIpjCF3KF3Q=")
    #test9.mitm, logcat15.txt
    key=base64.b64decode("fgg1gMXiYKg9wLsFkJRbtJSe9ljlSuhcMx4t19gzcqY=")
    key=base64.b64decode("yTf0bUv6x9xlEEp83XTE/w87VYvdktdZ9uwyD52HBts=")
    #test14.mitm, logcat21.txt
    key=base64.b64decode("w/wS9tfjoa8EJq3JgZYZowm6k0aVtaoiq6vur6hEvxY=");
    IV=buf[0:16]
    cipher = AES.AESCipher(key, AES.MODE_CBC, IV) #AES/CBC/PKCS5Padding
    plaintext = cipher.decrypt(buf[16:-20])
    print("plaintext:",plaintext)
    print(plaintext[-1])
    plaintext = plaintext[0:-plaintext[-1]]
    print(plaintext)
    print(decode_pb(plaintext))
    #pos = 0
    #buf =plaintext
    #while (pos<len(buf)):
    #    res = decode_pb(buf[pos:len(buf)])
     #   if (res.find("Failed")>=0):
     #       pos = pos+1
     #       continue
     #   print(res)
     #   break


def decode_tar(bytes):
   f = open('/tmp/bytes', 'wb')
   f.write(bytes)
   f.close()
   try:
       fp=tarfile.open('/tmp/bytes','r')
       print(fp.getnames())
   except Exception as e:
       print(e)

def decode_pb(bytes):
   f = open('/tmp/bytes', 'wb')
   f.write(bytes)
   f.close()
   try:
      return subprocess.check_output("cat /tmp/bytes | protoc --decode_raw",shell=True,stderr=subprocess.STDOUT, text=True)
   except:
      return "Failed"

def GetHumanReadable(size,precision=2):
    suffixes=['B','KB','MB','GB','TB']
    suffixIndex = 0
    while size > 1024:
        suffixIndex += 1 #increment the index of the suffix
        size = size/1024.0 #apply the division
    return "%.*f%s"%(precision,size,suffixes[suffixIndex])

class PrintTrace:

    response_content_sum=0
    request_content_sum=0
    request_dict_sum={}
    start_timestamp=-1

    def response(self,flow:http.HTTPFlow):

       #print(flow.request)
       #exit()
       #print("timestamp %s"%(flow.request.timestamp_start))
       #buf=zlib.decompress(flow.request.raw_content,32 + zlib.MAX_WBITS)
       #print(buf)
       #f = open('temp.gz', 'w+b')
       #f.write(flow.request.raw_content)
       #f.close
       #with gzip.open('temp.gz', 'rb') as f:
    #       print(f.read())
    #   return

       #print("%g !\http{%s}! %s"%(flow.request.timestamp_start,flow.request.method,flow.request.pretty_url))
       print("!\http{%s}! %s"%(flow.request.method,flow.request.pretty_url))
       #return

       # settings for androi
       exclude_resp=[]
       exclude_req=[] #["Accept-Encoding","Connection","Host","Content-Encoding","Content-Length","Content-Type","Accept","x-wap-profile","accept-encoding","content-length","content-type","cache-control","date","Content-type","Accept-encoding"]
       bold=["x-goog-device-auth"]
       req=flow.request.path.split("?")
       req=req[0]
       if req not in self.request_dict_sum:
           self.request_dict_sum[req]=0
       for q in flow.request.query:
           self.request_content_sum+=len(flow.request.query[q])
           self.request_dict_sum[req]+=len(flow.request.query[q])
       first=True
       for h in flow.request.headers:
           self.request_content_sum+=len(flow.request.headers[h])
           self.request_dict_sum[req]+=len(flow.request.headers[h])
           if h in exclude_req:
               continue
           if (h in ["User-Agent","user-agent"]) and ("Mozilla" in flow.request.headers[h] or "okhttp" in flow.request.headers[h] or "Dalvik" in flow.request.headers[h]):
               continue
           if h in bold:
               if h == "cookie" or h == "Cookie":
                   sstr="   !\\textbf{%s}!: %s"%(h,flow.request.headers[h])
               else:
                   sstr="   %s: !\\textbf{\\url{%s}}!"%(h,flow.request.headers[h])
           else:
               sstr="   %s: %s"%(h,flow.request.headers[h])
           if first:
               print("Headers")
               first=False
           print(sstr)
       if flow.request.method=="POST":
           try:
               if (flow.request.pretty_url == "https://telemetry.api.swiftkey.com/v1/bark-logs"):
                   decode_avro(flow.request.raw_content)
               elif (flow.request.pretty_url == "https://snippetdata.api.swiftkey.com/v1/sk-snippet-data"):
                   decode_avro(flow.request.raw_content)
               else:
                   print(flow.request.content.decode('ascii'))
               #decode_aes(flow.request.content)
           except Exception as e:
               print(e)
               buf=flow.request.content
               #decode_aes(buf)
               pb = decode_pb(buf)
               if pb == "Failed":
                   # see if it decodes as a protobuf array
                   pos = 0
                   while (pos<len(buf)):
                       msg_len, new_pos = _DecodeVarint32(buf[pos:len(buf)], 0)
                       pos = pos+new_pos
                       print("Decoding message of length "+str(msg_len)+" ("+str(pos)+","+str(len(buf))+")")
                       bytes = buf[pos:(pos+msg_len)]
                       res = decode_pb(bytes)
                       if (res.find("Failed")>=0): break
                       print(res)
                       pos = pos+msg_len
                   if res.find("Failed")>=0:
                       # last ditch try
                       pb_start = buf.find(b'\x08')
                       print("Trying protobuf again with pb_start=",pb_start)
                       pb = decode_pb(buf[pb_start:len(buf)])
               if pb == "Failed":
                   print("POST body:")
                   print(buf)
               print("POST body decoded as protobuf:"); print(pb)
           self.request_content_sum += len(flow.request.content)
           self.request_dict_sum[req]+=len(flow.request.content)
       if flow.response.content==None:
           size=0
       else:
           pb=decode_pb(flow.response.content)
           print(pb)
           size=len(flow.response.content)
       self.response_content_sum+=size
       if self.start_timestamp<0:
           self.start_timestamp=flow.request.timestamp_start
       print("<<< HTTP %d, %s"%(flow.response.status_code,GetHumanReadable(size)) )
       # print stats in volume of content sent/received
       #print("Content to date: %d/%d, elapsed secs %d"%(self.request_content_sum,self.response_content_sum,flow.request.timestamp_start-self.start_timestamp))
       #print("data_sent,%d,%d,%d"%(self.request_content_sum,self.response_content_sum,flow.request.timestamp_start-self.start_timestamp))
       #print(sorted(self.request_dict_sum.items(), key=operator.itemgetter(1)))
       #for req in self.request_dict_sum:
       #   print("%s %d"%(req,self.request_dict_sum[req]))
       for h in flow.response.headers:
           if h in ["X-Apple-Set-Cookie","Set-Cookie"]:
               print(" !\\textbf{%s}!: %s"%(h,flow.response.headers[h]))

addons=[PrintTrace()]