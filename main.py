from flask import Flask, redirect, url_for, render_template, request
import nmap
from flask import Flask, render_template
from flask import request, jsonify, Response
from checkPort import check_port, check_range
import csv
import json

app = Flask(__name__)

@app.route("/", methods=["POST", "GET"])
def home():
    if request.method == "POST":
        value = request.form.getlist('scan') 
        print(value)
        print(len(value))
        if len(value)<2:
            if value[0]=='scan os':
                return redirect(url_for('scanos'))
            elif value[0]=='scan port': 
                return render_template('index.html')
            else :
                  return redirect(url_for('scanfw'))


        elif len(value)>=2:

            if (value[0]=='scan port') and (value[1]=='scan os') :
                return render_template("index.html")




      
    return render_template("home1.html")
    


@app.route("/scanos", methods=["POST", "GET"])
def scanos():
    if request.method == "POST":
        address= request.form["nm"]
        print(type(address))
        scanner = nmap.PortScanner()
        os_results=scanner.scan(address, arguments="-O")['scan'][address]['osmatch']
        if len(os_results)!=0:
            print(os_results)
            value=os_results
            print(value[0]["name"])
            return render_template('result.html', value =os_results)
        return render_template("index1.html")
        
    else:
        return render_template("index1.html")
@app.route("/scanfw", methods=["POST", "GET"])
def scanfw():
  
    def check_existence(L,L2):
                for i in range(len(L)):
                    for j in range(len(L2)):
                        if(L2[j] == L[i][j]):
                            return True

    def put_element(L, L2,L3):
            if len(L)==0 :
                for i in range(0,len(L2)):
                    tup=list()
                    service = L3["scan"][addrss]["tcp"][L2[i]]["name"]
                    tup = [L2[i], service]
                    L.append(tup)
            else :
                for i in range(0, len(L2)):
                    if ( not check_existence(L,L2)):
                        tup = list()
                        service = L3["scan"][addrss]["tcp"][L2[i]]["name"]
                        tup = [L2[i], service]
                        L.extend(tup)

    def put_elementUDP(L, L2,L3):
            if len(L)==0 :
                for i in range(0,len(L2)):
                    tup=list()
                    service = L3["scan"][addrss]["udp"][L2[i]]["name"]
                    tup = [L2[i], service]
                    L.append(tup)
                    print(L)
            else :
                for i in range(0, len(L2)):
                    if (not check_existence(L,L2)):
                        tup = list()
                        service = L3["scan"][addrss]["udp"][L2[i]]["name"]
                        tup = [L2[i], service]
                        L.append(tup)
                        print(L)
    def check_status_TCP(L,rslt):
            if len(L) !=0:
                    for i in range(0,len(L)):
                        if(rslt["scan"][addrss]["tcp"][L[i]]["state"] =="open|filtered" or rslt["scan"][addrss]["tcp"][L[i]]["state"] =="filtered"):
                            return True
                    else:
                        return False
    def check_status_UDP(L,rslt):
            if len(L) !=0:
                    for i in range(0,len(L)):
                        if(rslt["scan"][addrss]["udp"][L[i]]["state"] =="open|filtered" or rslt["scan"][addrss]["udp"][L[i]]["state"] =="filtered"):
                            return True
                    else :
                        return False
    def ifscan(resultat,addrss):
        #print(resultat["scan"][addrss])
        #print("keys",resultat["scan"][addrss].keys())
        if("tcp" in resultat["scan"][addrss].keys()):
            #print("ok")
            return True

    if request.method == "POST":
        addrss= request.form["nm"]
        print((addrss))
        scanner = nmap.PortScanner()
        open_port = []
        op1=op3=op4=list()
        #addr=input()
        check1=check4=check3=False
    
        resultat = scanner.scan(addrss, '1-1000', ' -sT -T4 ')
        print(resultat)
        #resultat2 = scanner.scan(addrss, '1-1000', ' -vv -sU -sT -n -r -T4')
        #print(resultat2)
        resultat3 = scanner.scan(addrss, '1-1000', ' -Pn -T4 ')
        print(resultat3)
        resultat4 = scanner.scan(addrss, '1-1000', ' -sC -T4 ')
        print(resultat4)
        if(ifscan(resultat,addrss)== True):
            op1 = list(resultat["scan"][addrss]["tcp"].keys())
            put_element(open_port, op1,resultat)
            check1=check_status_TCP(op1,resultat)
        #op2 = list(resultat2["scan"][addrss]["udp"].keys())
        #put_elementUDP(open_port, op2,resultat2)
        if(ifscan(resultat3,addrss)):
            op3 = list(resultat3["scan"][addrss]["tcp"].keys())
            put_element(open_port, op3,resultat3)
            check3=check_status_TCP(op3,resultat3)
        if(ifscan(resultat4,addrss)):
            op4 = list(resultat4["scan"][addrss]["tcp"].keys())
            put_element(open_port, op4,resultat4)
            check4=check_status_TCP(op4,resultat4)
        #check2=check_status_UDP(op2,resultat2)
        
            
        #print(open_port)
        #if (check1==False  and check3==False and check4==False ):
        #if (check1 == False and check2==False and check3 == False and check4 == False):
            #if(open_port !=[]):
                #f.write(json.dumps(open_port))
        #else :
            #f.write(json.dumps("Firewall is ON"))
        
        if(op1==[] or op3==[] or op4==[]) or (check1==True  or check3==True or check4==True ):
            print("ok")

            #if (check1==True or check2==True or check3==True or check4==True):
            stat="Firewall is ON"
            print("ok2")
            return render_template("scan.html" ,value =stat)
        else :
            print(open_port)
            print("t3ada lena")
            return render_template("scanf.html" ,value =json.dumps(open_port))
    else:
        print("no lena")
        return render_template("index1.html")
     
            

@app.route('/check-port')
def checkPort():

    # Get request data
    domain = request.args.get('domain')
    port = int(request.args.get('port'))

    # Check if port is open
    isOpen = check_port(domain, port)

    return Response(str(isOpen), mimetype='text/plain')
@app.route('/scanftp', methods=["POST", "GET"])
def scanftp():
    if request.method == "POST":
        address= request.form["nm"]
        print(address)
        scanner = nmap.PortScanner()
        resultat=scanner.scan(address, arguments='-sV -p 21 -T5 --script=ftp-anon')
        print(resultat)
        if len(resultat["scan"]["192.168.10.50"]["tcp"][21])==8:

       
            return render_template('scanftp1.html', value =resultat)

        else : 
            return render_template('scanftp1.html', value =resultat)

    return render_template("index1.html")
@app.route('/scanssl', methods=["POST", "GET"])
def scanssl():
    if request.method == "POST":
        address= request.form["nm"]
        print(address)
        scanner = nmap.PortScanner()
        resultat=scanner.scan(address, arguments='-p443 --script ssl-cert')
        print(resultat)
        #rs={"nmap": {"command_line": "nmap -oX - -p443 --script ssl-cert 192.168.10.50", "scaninfo": {"tcp": {"method": "syn", "services": "443"}}, "scanstats": {"timestr": "Thu May  5 17:56:12 2022", "elapsed": "13.59", "uphosts": "1", "downhosts": "0", "totalhosts": "1"}}, "scan": {"192.168.10.50": {"hostnames": [{"name": "", "type": ""}], "addresses": {"ipv4": "192.168.10.50", "mac": "08:00:27:B2:EA:8D"}, "vendor": {"08:00:27:B2:EA:8D": "Oracle VirtualBox virtual NIC"}, "status": {"state": "up", "reason": "arp-response"}, "tcp": {"443": {"state": "open", "reason": "syn-ack", "name": "https", "product": "", "version": "", "extrainfo": "", "conf": "3", "cpe": "", "script": {"ssl-cert": "Subject: commonName=www.gte2.com/organizationName=ENISO/stateOrProvinceName=Sousse/countryName=TN\nIssuer: commonName=www.gte2.com/organizationName=ENISO/stateOrProvinceName=Sousse/countryName=TN\nPublic Key type: rsa\nPublic Key bits: 2048\nSignature Algorithm: sha256WithRSAEncryption\nNot valid before: 2022-04-17T20:07:41\nNot valid after:  2023-04-17T20:07:41\nMD5:   17e0 63a8 a679 b895 1d16 5d2d 7567 1e49\nSHA-1: 6e1c 7574 aa94 6f4f 60c0 9abc 3310 44ce d43b 5881"}}}}}}
        return render_template('scanssl.html', value =resultat)

    return render_template("index1.html")
@app.route('/scanssh', methods=["POST", "GET"])
def scanssh():
    if request.method == "POST":
        address= request.form["nm"]
        print(address)
        scanner = nmap.PortScanner()
        resultat=scanner.scan(address, arguments='-p 22 --script ssh-auth-methods --script-args="ssh.user=<username>"')         
        print(resultat)
        #rs={"nmap": {"command_line": "nmap -oX - -p 22 --script ssh-auth-methods --script-args=ssh.user=<username> 192.168.10.50", "scaninfo": {"tcp": {"method": "syn", "services": "22"}}, "scanstats": {"timestr": "Thu May  5 17:56:26 2022", "elapsed": "13.62", "uphosts": "1", "downhosts": "0", "totalhosts": "1"}}, "scan": {"192.168.10.50": {"hostnames": [{"name": "", "type": ""}], "addresses": {"ipv4": "192.168.10.50", "mac": "08:00:27:B2:EA:8D"}, "vendor": {"08:00:27:B2:EA:8D": "Oracle VirtualBox virtual NIC"}, "status": {"state": "up", "reason": "arp-response"}, "tcp": {"22": {"state": "open", "reason": "syn-ack", "name": "ssh", "product": "", "version": "", "extrainfo": "", "conf": "3", "cpe": "", "script": {"ssh-auth-methods": "\n  Supported authentication methods: \n    publickey\n    password"}}}}}}
        return render_template('scanssh.html', value =resultat)

    return render_template("index1.html")    



@app.route('/check-ports')
def checkPorts():

    # Get request data
    domain = request.args.get('domain')
    port_start = int(request.args.get('port_start'))
    port_end = int(request.args.get('port_end')) + 1

    # Check if range of port is open
    ports_list = check_range(domain, port_start, port_end)

    return Response(json.dumps(ports_list), mimetype='application/json')

@app.route('/ports-info')
def portsInfo():

    csv_file = open('portMap/main-ports.csv', 'r')
    csv_lines = csv_file.readlines()

    dic = {}
    for x in csv_lines:
        x = x.split(',')
        dic.update(
            {
                x[0]: {
                    "protocol": x[1],
                    "tcp/udp": x[2],
                    "description": x[3]
                }
            }
        )

    return Response(json.dumps(dic), mimetype='text/plain')

@app.route('/Home')
def Home():
    
    return render_template('index.html')

if __name__ == "__main__":
    app.run(debug=True)