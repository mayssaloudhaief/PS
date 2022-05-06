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
            else :
                return render_template('index.html')
        elif len(value)>=2:

            if (value[0]=='scan port') and (value[1]=='scan os') :
                return render_template("index.html")




      
    return render_template("home1.html")
    


@app.route("/scanos", methods=["POST", "GET"])
def scanos():
    if request.method == "POST":
        address= request.form["nm"]
        print(address)
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
        rs={"nmap": {"command_line": "nmap -oX - -sV -p 21 -T5 --script=ftp-anon 192.168.10.50", "scaninfo": {"tcp": {"method": "syn", "services": "21"}}, "scanstats": {"timestr": "Thu May  5 17:55:59 2022", "elapsed": "13.76", "uphosts": "1", "downhosts": "0", "totalhosts": "1"}}, "scan": {"192.168.10.50": {"hostnames": [{"name": "", "type": ""}], "addresses": {"ipv4": "192.168.10.50", "mac": "08:00:27:B2:EA:8D"}, "vendor": {"08:00:27:B2:EA:8D": "Oracle VirtualBox virtual NIC"}, "status": {"state": "up", "reason": "arp-response"}, "tcp": {"21": {"state": "open", "reason": "syn-ack", "name": "ftp", "product": "vsftpd", "version": "3.0.3", "extrainfo": "", "conf": "10", "cpe": "cpe:/a:vsftpd:vsftpd:3.0.3", "script": {"ftp-anon": "Anonymous FTP login allowed (FTP code 230)"}}}}}}
        return render_template('scanftp.html', value =rs)

    return render_template("index1.html")
@app.route('/scanssl', methods=["POST", "GET"])
def scanssl():
    if request.method == "POST":
        address= request.form["nm"]
        print(address)
        scanner = nmap.PortScanner()
        resultat=scanner.scan('address', arguments='-p443 --script ssl-cert')
        print(resultat)
        rs={"nmap": {"command_line": "nmap -oX - -p443 --script ssl-cert 192.168.10.50", "scaninfo": {"tcp": {"method": "syn", "services": "443"}}, "scanstats": {"timestr": "Thu May  5 17:56:12 2022", "elapsed": "13.59", "uphosts": "1", "downhosts": "0", "totalhosts": "1"}}, "scan": {"192.168.10.50": {"hostnames": [{"name": "", "type": ""}], "addresses": {"ipv4": "192.168.10.50", "mac": "08:00:27:B2:EA:8D"}, "vendor": {"08:00:27:B2:EA:8D": "Oracle VirtualBox virtual NIC"}, "status": {"state": "up", "reason": "arp-response"}, "tcp": {"443": {"state": "open", "reason": "syn-ack", "name": "https", "product": "", "version": "", "extrainfo": "", "conf": "3", "cpe": "", "script": {"ssl-cert": "Subject: commonName=www.gte2.com/organizationName=ENISO/stateOrProvinceName=Sousse/countryName=TN\nIssuer: commonName=www.gte2.com/organizationName=ENISO/stateOrProvinceName=Sousse/countryName=TN\nPublic Key type: rsa\nPublic Key bits: 2048\nSignature Algorithm: sha256WithRSAEncryption\nNot valid before: 2022-04-17T20:07:41\nNot valid after:  2023-04-17T20:07:41\nMD5:   17e0 63a8 a679 b895 1d16 5d2d 7567 1e49\nSHA-1: 6e1c 7574 aa94 6f4f 60c0 9abc 3310 44ce d43b 5881"}}}}}}
        return render_template('scanssl.html', value =rs)

    return render_template("index1.html")
@app.route('/scanssh', methods=["POST", "GET"])
def scanssh():
    if request.method == "POST":
        address= request.form["nm"]
        print(address)
        scanner = nmap.PortScanner()
        resultat=scanner.scan('address', arguments='-p 22 --script ssh-auth-methods --script-args="ssh.user=<username>"')         
        print(resultat)
        rs={"nmap": {"command_line": "nmap -oX - -p 22 --script ssh-auth-methods --script-args=ssh.user=<username> 192.168.10.50", "scaninfo": {"tcp": {"method": "syn", "services": "22"}}, "scanstats": {"timestr": "Thu May  5 17:56:26 2022", "elapsed": "13.62", "uphosts": "1", "downhosts": "0", "totalhosts": "1"}}, "scan": {"192.168.10.50": {"hostnames": [{"name": "", "type": ""}], "addresses": {"ipv4": "192.168.10.50", "mac": "08:00:27:B2:EA:8D"}, "vendor": {"08:00:27:B2:EA:8D": "Oracle VirtualBox virtual NIC"}, "status": {"state": "up", "reason": "arp-response"}, "tcp": {"22": {"state": "open", "reason": "syn-ack", "name": "ssh", "product": "", "version": "", "extrainfo": "", "conf": "3", "cpe": "", "script": {"ssh-auth-methods": "\n  Supported authentication methods: \n    publickey\n    password"}}}}}}
        return render_template('scanssh.html', value =rs)

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