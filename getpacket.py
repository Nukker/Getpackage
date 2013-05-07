#-*-coding:utf-8-*-
import socket
import struct
import json

IP_ADDRESS = '221.238.24.104'

HOST = socket.gethostbyname(socket.gethostname())
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
s.bind((HOST, 0))
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

def decodeIpHeader(packet):
    """ 解抓raw socket抓到的packet数据包IP层头部放置到mapRet字典中
    数据有如下:
    
    version
    headerLen
    serviceType
    totalLen
    id
    fragOff
    ttl
    protocol
    checksum
    srcAddr
    dstAddr
    data
    """
    mapRet = {}
    mapRet["version"] = (int(ord(packet[0][0])) & 0xF0)>>4      #去除高4位
    mapRet["headerLen"] = (int(ord(packet[0][0])) & 0x0F)<<2    #乘4
    mapRet["serviceType"] = hex(int(ord(packet[0][1])))         #十六进制打出来
    mapRet["totalLen"] =  socket.ntohs(struct.unpack('H',packet[0][2:4])[0])
    mapRet["identification"] = "0x%02x%02x" % ((int( ord(packet[0][4]) )) , (int( ord(packet[0][5]))))
    mapRet["id"] = int(ord(packet[0][6]) & 0xE0)>>5             #去除高5位
    mapRet["fragOff"] = (int(ord(packet[0][6]) & 0x1F) + int(ord(packet[0][7])))
    mapRet["ttl"] = int(ord(packet[0][8]))
    mapRet["protocol"] = int(ord(packet[0][9]))
    mapRet["checkSum"] = "0x%02x%02x" % (int(ord(packet[0][10])),int(ord(packet[0][11])))  #十六进制打出来
    mapRet["srcaddr"] = "%d.%d.%d.%d" % (int(ord(packet[0][12])),int(ord(packet[0][13])),int(ord(packet[0][14])), int(ord(packet[0][15])))
    mapRet["dstaddr"] = "%d.%d.%d.%d" % (int(ord(packet[0][16])),int(ord(packet[0][17])),int(ord(packet[0][18])), int(ord(packet[0][19])))
    mapRet["data"] = packet[0][mapRet["headerLen"]:mapRet["totalLen"]]
    return mapRet

def decodeTcpHeader(packet):
    """解抓raw socket抓到的packet数据包TCP层头部放置到mapRet字典中
    数据有如下:

    srcPort
    dstPort
    sequenceNum
    ackNum
    headerLen
    flags
    WinSize
    checksum
    Urgentpoint
    data
    """
    mapRet = {}
    mapRet['srcport'] = int(ord(packet[0])) + int(ord(packet[1]))
    mapRet['dstport'] = int(ord(packet[2])) + int(ord(packet[3]))
    mapRet['sequenceNum'] = struct.unpack(">I",packet[4:8])[0]
    mapRet['ackNum'] = struct.unpack(">I",packet[8:12])[0]
    mapRet['headerLen'] = (int(ord(packet[12])) & 0xF0)>>2   #右移4位左移2位→右移2位
    mapRet['flags'] = struct.unpack("B",packet[13])[0] & 0x3F
#   mapRet['URG'] = int(ord(packet[0][33])) & 0x20
#   mapRet['ACK'] = int(ord(packet[0][33])) & 0x10
#   mapRet['RST'] = int(ord(packet[0][33])) & 0x04
#   mapRet['SYN'] = int(ord(packet[0][33])) & 0x02
#   mapRet['FIN'] = int(ord(packet[0][33])) & 0x01
    mapRet['WinSize'] = struct.unpack(">H", packet[14:16])[0]
    mapRet['checkSum'] =  struct.unpack(">H", packet[16:18])[0]
    mapRet['Urgentpoint'] = struct.unpack(">H", packet[18:20])[0]
    mapRet['data'] = packet[mapRet['headerLen']:]
    return mapRet
        
def decodesendHttpdata(data):
    '''自定义过滤规则获得需要处理的数据
    返回一组字典收集各项对应的数据
    目标的处理数据是:发包数据
    '''
    mapRet = {}
    Tempdata = data.split('\r\n')
    start_pos = Tempdata[0].index('?')
    end_pos = Tempdata[0].index('HTTP')
    Tempdata1 = Tempdata[0][start_pos + 1:end_pos - 1].split('&')
    for element in Tempdata1:
        key = element.split('=')[0]
        value = element.split('=')[1]
        mapRet[key] = value
    
    return mapRet
    
def decoderevHttpdata(data):
    '''自定义过滤规则获得需要处理的数据
    返回一串String
    目标的处理数据:收包数据
    '''
    return data.split('\r\n')[5]

def inputdata(data):
    '''格式化顺序输出欲输出的数据
    返回一个字符串
    '''
    result = u"客户端发送日志：\n"
    f = file("data.json")
    mapRet = json.load(f)
    mapHttpTmp = decodesendHttpdata(data)
    if mapHttpTmp['gs'] in mapRet:
        result += mapHttpTmp['gs'] + '->'
        for (k,v) in mapHttpTmp.items():
            for (key,value) in mapRet[mapHttpTmp['gs']].items():
                if key == k:                    #对比
                    result +=  "%s: %s " %(k,v)
                    if type(mapRet[mapHttpTmp['gs']][key]) == dict:         #若mapRet[mapHttpTmp['gs']][key] 的值不再是字典就直接输出了
                        if mapRet[mapHttpTmp['gs']][key].has_key(v):
                            result +="(%s) \t" %mapRet[mapHttpTmp['gs']][key][v]
                        else:
                            result += '(Undefined)' + '\t'
                    else:
                        result += "(%s) \t" %mapRet[mapHttpTmp['gs']][key]
    else:
        result += u'未在json文件中定义此类文件'
    return result
    f.close()
        
        
while True:
    buf = s.recvfrom(65565)
    if len(buf) == 0:
        s.close
    else:
        mapIpTmp = decodeIpHeader(buf)
        if mapIpTmp['totalLen'] < 40:
            pass
            #print '非TCP的数据包就不抓了'
        else:
            mapTcpTmp = decodeTcpHeader(mapIpTmp['data'])
            if mapIpTmp['dstaddr'] == IP_ADDRESS and mapTcpTmp['headerLen'] + mapIpTmp['headerLen'] != mapIpTmp['totalLen']:
                print inputdata(mapTcpTmp['data'])

                '''  for test
                for k,v in mapHttpTmp.items():
                    print k , '\t:\t' , v
                print '\n'
                '''
            if mapIpTmp['srcaddr'] == '221.238.24.104' and mapTcpTmp['headerLen'] + mapIpTmp['headerLen'] != mapIpTmp['totalLen']:
                mapHttpTmp = decoderevHttpdata(mapTcpTmp['data'])            
                print u'\n服务器返回:'
                print mapHttpTmp + '\n\n\n'

s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)