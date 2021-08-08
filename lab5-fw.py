import sys
import time

rule_file_name=sys.argv[1]
pkt_file_name=sys.argv[2]

rule_dict={}

class Rule:
    def __init__(self):
        self.num = ""
        self.src_ip_address = ""
        self.dst_ip_address = ""
        self.src_port_range=""
        self.dst_port_range=""
        self.protocol=""
        self.data=""

    def set(self,num,src_ip_address,dst_ip_address,src_port_range,dst_port_range,protocol,data):
        self.num=num
        self.src_ip_address=src_ip_address
        self.dst_ip_address=dst_ip_address
        self.src_port_range=src_port_range
        self.dst_port_range=dst_port_range
        self.protocol=protocol
        self.data=data



rule_count=0
valid_rule_count=0

fd=open(rule_file_name,'r')
lines=fd.readlines()


for l in lines:
    #print("l: ",l)

    if(l=="BEGIN\n"):
        #print("beg: ",l)
        rule_count+=1
        flag=True
        num = ""
        src_ip_address = ""
        dst_ip_address = ""
        src_port_range=""
        dst_port_range=""
        protocol=""
        data=""
        continue

    elif(l=="END\n"):
        if flag==True:
            #print("num: ",num)
            #print("src_ip_address: ",src_ip_address)
            valid_rule_count+=1
            r=Rule()
            r.set(num,src_ip_address,dst_ip_address,src_port_range,dst_port_range,protocol,data)
            rule_dict[num]=r
        continue


    ind=l.index(":")
    ind2=ind
    ind+=2
    y=l[ind:len(l)-1]
    #print("y: ",y,":: ",end="")
    x=l[:ind2]
    #print("x: ",x)
    # print(x)
    # print(y)
    # print("")

    if x=="NUM":
        #print("NUMMM22: ",y)
        num=y

    elif x=="SRC IP ADDR":
        src_ip_address=y

    elif x=="DEST IP ADDR":
        dst_ip_address=y

    elif x=="SRC PORT":
        src_port_range=y
        ii=src_port_range.index("-")
        p1=src_port_range[:ii]
        p2=src_port_range[ii+1:]
        p1=int(p1)
        p2=int(p2)

        if (p1==0 and p2==0):
            continue

        if ((p1<1 or p1>65535) or (p2<1 or p2>65535)):
            flag=False
        if p1>p2:
            flag=False


    elif x=="DEST PORT":
        dst_port_range=y
        ii=dst_port_range.index("-")
        p1=dst_port_range[:ii]
        p2=dst_port_range[ii+1:]
        p1=int(p1)
        p2=int(p2)

        if p1==0 and p2==0:
            continue

        if ((p1<1 or p1>65535) or (p2<1 or p2>65535)):
            flag=False
        if p1>p2:
            flag=False

    elif x=="PROTOCOL":
        protocol=y

    elif x=="DATA":
        data=y

print("A total of ",rule_count," rules were read; ",valid_rule_count," valid rules are stored.")

# for key in rule_dict:
#     print("key: ",key)
#     print(rule_dict[key].num)
#     print(rule_dict[key].src_port_range)
#     print(rule_dict[key].dst_port_range)
#     print(rule_dict[key].data)
#     print("----------------")

def decimalToBinary(n):
    return bin(n).replace("0b", "")

def get_bin(ip):
    #print("ip: ",ip)
    ss=""
    i=0
    tmp=""

    for j in range(0,len(ip)):
        if ip[j]==".":
            i=j
            break
        tmp+=ip[j]

    tmp=int(tmp)
    xx=str(decimalToBinary(tmp))

    xx=xx.zfill(8)
    #print("xx1: ",xx)
    ss+=xx

    tmp=""

    for j in range(i+1,len(ip)):
        if ip[j]==".":
            i=j
            break
        tmp+=ip[j]

    tmp=int(tmp)
    xx=str(decimalToBinary(tmp))
    xx=xx.zfill(8)
    #print("xx2: ",xx)
    ss+=xx

    tmp=""

    for j in range(i+1,len(ip)):
        if ip[j]==".":
            i=j
            break
        tmp+=ip[j]

    tmp=int(tmp)
    xx=str(decimalToBinary(tmp))
    xx=xx.zfill(8)
    #print("xx3: ",xx)
    ss+=xx

    tmp=ip[i+1:]
    tmp=int(tmp)
    xx=str(decimalToBinary(tmp))
    xx=xx.zfill(8)
    #print("xx4: ",xx)
    ss+=xx

    return ss

def ip_in_range(s1,s2):    # (pkt_ip_address,rule_ip_address)
    if s2=="0.0.0.0/0":
        return True
    i=s2.index("/")
    pre=s2[i+1:]
    pre=int(pre)
    ip=s2[:i]

    ss=get_bin(ip)
    #print("ss_orig: ",ss)
    ss2=ss

    s3=ss[:pre]
    s4=ss2[:pre]
    #print("pre: ",pre)

    for kk in range(pre,len(ss)):
        s3+="0"
    for kk in range(pre,len(ss)):
        s4+="1"

    ss=s3
    ss2=s4

    ss3=get_bin(s1)

    # print("ss1: ",ss)
    # print("ss2: ",ss2)
    # print("ss3: ",ss3)

    if((ss3>=ss) and (ss3<=ss2)):
        return True
    return False


pkt_count=0
valid_pkt_count=0

fd=open(pkt_file_name,'r')
lines=fd.readlines()

tot_time=0

for l in lines:
    #print("l: ",l)
    if(l=="BEGIN\n"):
        #print("beg: ",l)
        pkt_count+=1
        flag=True
        num = ""
        src_ip_address = ""
        dst_ip_address = ""
        src_port=""
        dst_port=""
        protocol=""
        data=""
        continue

    elif(l=="END\n"):
        if flag==True:
            valid_pkt_count+=1
            rule_list=[]
            st=time.time()
            for key in rule_dict:
                r=rule_dict[key]
                flag2=True
                sr2=r.src_ip_address
                sr3=r.dst_ip_address
                t1=ip_in_range(src_ip_address,sr2)
                t2=ip_in_range(dst_ip_address,sr3)
                if(t1==False or t2==False):
                    #print("t1 or t2 wrong")
                    continue

                p=r.src_port_range
                id=p.index("-")
                p1=p[:id]
                p2=p[id+1:]
                p1=int(p1)
                p2=int(p2)
                src_port=int(src_port)
                if(not(p1==0 and p2==0)):
                    if(not(src_port>=p1 and src_port<=p2)):
                        #print("src port wrong")
                        continue

                p=r.dst_port_range
                id=p.index("-")
                p1=p[:id]
                p2=p[id+1:]
                p1=int(p1)
                p2=int(p2)
                dst_port=int(dst_port)
                if(not(p1==0 and p2==0)):
                    if(not(dst_port>=p1 and dst_port<=p2)):
                        #print("dst port wrong")
                        continue

                if(protocol!=r.protocol):
                    #print("protocol wrong")
                    continue

                if(data.count(r.data)>0):
                    #print("data wrong")
                    rule_list.append(int(r.num))

            en=time.time()
            tot_time+=(en-st)*1000000

            rule_list.sort()
            print("Packet number ",num," matches ",len(rule_list)," rule(s): ",end="");
            ff=False
            for i in range(0,len(rule_list)):
                if(i==0):
                    ff=True
                    print(rule_list[i],end="")
                else:
                    print(", ",rule_list[i],end="")

            if ff==True:
                print(".",end="")
            print("")

        elif flag==False:
            print("Packet number ",num," is invalid.")

        continue


    ind=l.index(":")
    ind2=ind
    ind+=2
    y=l[ind:len(l)-1]
    #print("y: ",y,":: ",end="")
    x=l[:ind2]
    #print("x: ",x)
    # print(x)
    # print(y)
    # print("")

    if x=="NUM":
        #print("NUMMM22: ",y)
        num=y

    elif x=="SRC IP ADDR":
        src_ip_address=y

    elif x=="DEST IP ADDR":
        dst_ip_address=y

    elif x=="SRC PORT":
        src_port=y
        p1=int(src_port)

        if(p1<0 or p1>65535):
            flag=False


    elif x=="DEST PORT":
        dst_port=y
        p1=int(dst_port)

        if(p1<0 or p1>65535):
            flag=False

    elif x=="PROTOCOL":
        protocol=y

    elif x=="DATA":
        data=y


print("A total of ",pkt_count," packet(s) were read from the file and processed. Bye.")
print("Average time taken per packet: ",tot_time/pkt_count," microseconds.")
