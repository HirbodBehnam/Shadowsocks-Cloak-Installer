#!/bin/bash
function GetRandomPort(){
    echo "Installing lsof package. Please wait."
    yum -y -q install lsof
    local RETURN_CODE
    RETURN_CODE=$?
    if [ $RETURN_CODE -ne 0 ]; then
        echo "$(tput setaf 3)Warning!$(tput sgr 0) lsof package did not installed successfully. The randomized port may be in use."
    fi
    PORT=$((RANDOM % 16383 + 49152))
    if lsof -Pi :$PORT -sTCP:LISTEN -t >/dev/null ; then
        GetRandomPort
    fi
}
if [[ "$EUID" -ne 0 ]]; then #Check root
    echo "Please run this script as root"
    exit 1
fi
if [ -d "/etc/shadowsocks-libev" ]; then
    echo "Looks like you have installed shadowsocks. Choose an option below:"
    echo "1) Show Connection Info"
    echo "2) Regenerate Firewall Rules"
    echo "3) Uninstall Shadowsocks"
    read -r -p "Please enter a number: " OPTION
    distro=$(awk -F= '/^NAME/{print $2}' /etc/os-release)
    cd /etc/shadowsocks-libev || exit 2
    PORT=$(jq -r '.server_port' < 'config.json')
    case $OPTION in
        1)
            cipher=$(jq -r '.method' < 'config.json')
            Password=$(jq -r '.password' < 'config.json')
            PUBLIC_IP="$(curl https://api.ipify.org -sS)"
            CURL_EXIT_STATUS=$?
            if [ $CURL_EXIT_STATUS -ne 0 ]; then
                PUBLIC_IP="YOUR_IP"
            fi
            ckauid=$(jq -r '.AdminUID' < 'ckconfig.json')
            ckpub=$(cat ckpublickey.txt)
            echo "Your Server IP: $PUBLIC_IP"
            echo "Password:       $Password"
            echo "Port:           $PORT"
            echo "Encryption:     $cipher"
            echo "Cloak UID (Admin ID): $ckauid"
            echo "Cloak Private Key:    $ckpv"
            echo "Cloak Public Key:     $ckpub"
            echo "Cloak Server Name:    Use the domain of $ckwebaddr,if untouched use bing.com"
            echo "Cloak TicketTimeHint: Leave default(3600)"
            echo "Cloak NumConn:        4 or more"
            echo "Cloak MaskBrowser:    firewall or chrome"
            echo "Also read more about these arguments at https://github.com/cbeuw/Cloak#client"
            echo
            echo "Download cloak client for android from https://github.com/cbeuw/Cloak-android/releases"
            echo "Download cloak client for PC from https://github.com/cbeuw/Cloak/releases"
            echo
            echo
            echo
            ckpub=${ckpub::-1}
            ckpub+="\\="
            ckauid=${ckauid::-1}
            ckauid+="\\="
            SERVER_BASE64=$(printf "%s" "$cipher:$Password" | base64)
            SERVER_CLOAK_ARGS="ck-client;UID=$ckauid;PublicKey=$ckpub;ServerName=bing.com;TicketTimeHint=3600;MaskBrowser=chrome;NumConn=4"
            SERVER_CLOAK_ARGS=$(printf "%s" "$SERVER_CLOAK_ARGS" | curl -Gso /dev/null -w %{url_effective} --data-urlencode @- "" | cut -c 3-) #https://stackoverflow.com/a/10797966/4213397
            SERVER_BASE64="ss://$SERVER_BASE64@$PUBLIC_IP:$PORT?plugin=$SERVER_CLOAK_ARGS"
            qrencode -t ansiutf8 "$SERVER_BASE64"
            echo
            echo
            echo "Or just use this string: $SERVER_BASE64"
        ;;
        2)
        if [[ $distro =~ "CentOS" ]]; then
            echo "firewall-cmd --add-port=$PORT/tcp"
            echo "firewall-cmd --permanent --add-port=$PORT/tcp"
        elif [[ $distro =~ "Ubuntu" ]]; then
            echo "ufw allow $PORT/tcp"
        elif [[ $distro =~ "Debian" ]]; then
            echo "iptables -A INPUT -p tcp --dport $PORT --jump ACCEPT"
            echo "iptables-save"
        fi
        ;;
        3)
            read -r -p "I still keep some packages like \"qrencode\". Do want to uninstall Shadowsocks?(y/n) " OPTION
            if [ "$OPTION" == "n" ] | [ "$OPTION" == "N" ]; then
                exit 0
            fi
            systemctl stop shadowsocks-libev
            systemctl disable shadowsocks-libev
            rm -f /etc/systemd/system/shadowsocks-server.service
            if [[ $distro =~ "CentOS" ]]; then
                yum -y remove shadowsocks-libev
                firewall-cmd --remove-port="$PORT"/tcp
                firewall-cmd --permanent --remove-port="$PORT"/tcp
            elif [[ $distro =~ "Ubuntu" ]]; then
                apt-get -y purge shadowsocks-libev
                ufw delete allow "$PORT"/tcp
            elif [[ $distro =~ "Debian" ]]; then
                apt-get -y purge shadowsocks-libev
                iptables -D INPUT -p tcp --dport "$PORT" --jump ACCEPT
                iptables-save > /etc/iptables/rules.v4 
            fi
            rm -rf /etc/shadowsocks-libev
            rm -f /usr/local/bin/ck-server
            echo "Done"
        ;;
    esac
    exit 0
fi
ciphers=(rc4-md5 aes-128-gcm aes-192-gcm aes-256-gcm aes-128-cfb aes-192-cfb aes-256-cfb aes-128-ctr aes-192-ctr aes-256-ctr camellia-128-cfb camellia-192-cfb camellia-256-cfb bf-cfb chacha20-ietf-poly1305 xchacha20-ietf-poly1305 salsa20 chacha20 chacha20-ietf)
num_regex='^[0-9]+$'
clear
echo "Shadowsocks with Cloak installer by Hirbod Behnam"
echo "Source at https://github.com/HirbodBehnam/ShadowsocksCloakInstall"
echo "Shadowsocks-libev at https://github.com/shadowsocks/shadowsocks-libev"
echo "Cloak at https://github.com/cbeuw/Cloak"
echo
echo
#Get port
read -r -p "Please enter a port to listen on it. 443 is recommended. Enter -1 for a random port: " -e -i 443 PORT 
if [[ $PORT -eq -1 ]] ; then #Check random port
    GetRandomPort
    echo "I've selected $PORT as your port."
fi
if ! [[ $PORT =~ $num_regex ]] ; then #Check if the port is valid
    echo "$(tput setaf 1)Error:$(tput sgr 0) The input is not a valid number"
    exit 1
fi
if [ "$PORT" -gt 65535 ] ; then
    echo "$(tput setaf 1)Error:$(tput sgr 0): Number must be less than 65536"
    exit 1
fi
#Get password
read -r -p "Enter a password for shadowsocks. Leave blank for a random password: " Password
if [ "$Password" == "" ]; then
    Password=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1) #https://gist.github.com/earthgecko/3089509
    echo "$Password was chosen."
fi
#Get cipher
echo
for (( i = 0 ; i < ${#ciphers[@]}; i++ )); do
    echo "$((i+1))) ${ciphers[$i]}"
done
read -r -p "Enter the number of cipher you want to use: " -e -i 15 cipher
if [ "$cipher" -lt 1 ] || [ "$cipher" -gt 18 ]; then
    echo "$(tput setaf 1)Error:$(tput sgr 0) Invalid option"
    exit 1
fi
cipher=${ciphers[$cipher-1]}
#Get DNS server
echo 
echo "1) Cloudflare"
echo "2) Google"
echo "3) OpenDNS"
echo "4) Custom"
read -r -p "Which DNS server you want to use? " -e -i 1 dns
case $dns in
    '1')
    dns="1.1.1.1"
    ;;
    '2')
    dns="8.8.8.8"
    ;;
    '3')
    dns="208.67.222.222"
    ;;
    '4')
    read -r -p "Please enter your dns server address(One IP only): " -e -i "1.1.1.1" dns
    ;;
    *)
    echo "$(tput setaf 1)Error:$(tput sgr 0) Invalid option"
    exit 1
    ;;
esac
#Set redirect ip for cloak; Just like https://gist.github.com/cbeuw/37a9d434c237840d7e6d5e497539c1ca#file-shadowsocks-ck-release-sh-L165
echo -e "Please enter a redirection IP for Cloak (leave blank to set it to 204.79.197.200:443 of bing.com): "
read -r -p "" ckwebaddr
[ -z "$ckwebaddr" ] && ckwebaddr="204.79.197.200:443"
#Check arch
arch=$(uname -m)
case $arch in
    "i386"|"i686")
    ;;
    "x86_64")
    arch=2
    ;;
    *)
    if [[ "$arch" =~ "armv" ]]; then
        arch=${arch:4:1}
        if [ "$arch" -gt 7 ]; then
            arch=4
        else 
            arch=3
        fi
    else 
        arch=0
    fi
    ;;
esac
if [ "$arch" == "0" ]; then
    arch=1
    echo "$(tput setaf 3)Warning!$(tput sgr 0) Cannot automatically determine architecture."
fi
echo "1) 386"
echo "2) amd64"
echo "3) arm"
echo "4) arm64"
read -r -p "Select your architecture: " -e -i $arch arch
case $arch in
    1)
    arch="amd64"
    ;;
    2)
    arch="386"
    ;;
    3)
    arch="arm"
    ;;
    4)
    arch="arm64"
    ;;
    *)
    echo "$(tput setaf 1)Error:$(tput sgr 0) Invalid option"
    exit 1
    ;;
esac
#Install shadowsocks
distro=$(awk -F= '/^NAME/{print $2}' /etc/os-release)
if [[ $distro =~ "CentOS" ]]; then
    yum -y install dnf epel-release
	dnf -y install 'dnf-command(copr)'
	dnf -y copr enable librehat/shadowsocks
	yum -y update
	yum -y install shadowsocks-libev wget jq qrencode curl firewalld
    firewall-cmd --add-port="$PORT"/tcp
    firewall-cmd --permanent --add-port="$PORT"/tcp
elif [[ $distro =~ "Ubuntu" ]]; then
    if [[ $(lsb_release -r -s) =~ "18" ]] || [[ $(lsb_release -r -s) =~ "19" ]]; then 
        apt update
        apt -y install shadowsocks-libev wget jq qrencode curl ufw
    else
        apt-get install software-properties-common -y
        add-apt-repository ppa:max-c-lv/shadowsocks-libev -y
        apt-get update
        apt-get -y install shadowsocks-libev wget jq qrencode curl ufw
    fi
    ufw allow "$PORT"/tcp
elif [[ $distro =~ "Debian" ]]; then
    ver=$(cat /etc/debian_version)
    ver="${ver:0:1}"
    if [ "$ver" == "8" ]; then
        sh -c 'printf "deb [check-valid-until=no] http://archive.debian.org/debian jessie-backports main\n" > /etc/apt/sources.list.d/jessie-backports.list' #https://unix.stackexchange.com/a/508728/331589
        echo "Acquire::Check-Valid-Until \"false\";" >> /etc/apt/apt.conf
        apt-get update
        apt -y -t jessie-backports install shadowsocks-libev
    elif [ "$ver" == "9" ]; then
        sh -c 'printf "deb http://deb.debian.org/debian stretch-backports main" > /etc/apt/sources.list.d/stretch-backports.list'
        apt update
        apt -t stretch-backports install shadowsocks-libev
    else
        echo "Your debian is too old!"
        exit 2
    fi
    apt -y install wget jq qrencode curl iptables-persistent iptables
    #Firewall
    iptables -A INPUT -p tcp --dport "$PORT" --jump ACCEPT
    iptables-save > /etc/iptables/rules.v4  
else
    echo "Your system is not supported (yet)"
    exit 2
fi
#Install cloak https://gist.github.com/cbeuw/37a9d434c237840d7e6d5e497539c1ca#file-shadowsocks-ck-release-sh-L118
url=$(wget -O - -o /dev/null https://api.github.com/repos/cbeuw/Cloak/releases/latest | grep "/ck-server-linux-$arch-" | grep -P 'https(.*)[^"]' -o)
wget -O ck-server "$url"
chmod +x ck-server
mv ck-server /usr/local/bin
#Setup shadowsocks config
rm -f /etc/shadowsocks-libev/config.json
echo "{
    \"server\":\"0.0.0.0\",
    \"server_port\":$PORT,
    \"password\":\"$Password\",
    \"timeout\":60,
    \"method\":\"$cipher\",
    \"nameserver\":\"$dns\",
    \"plugin\":\"ck-server\",
    \"plugin_opts\":\"/etc/shadowsocks-libev/ckconfig.json\"
}">>/etc/shadowsocks-libev/config.json
ckauid=$(ck-server -u) #https://gist.github.com/cbeuw/37a9d434c237840d7e6d5e497539c1ca#file-shadowsocks-ck-release-sh-L139
IFS=, read ckpub ckpv <<< $(ck-server -k)
echo "{
    \"WebServerAddr\":\"$ckwebaddr\",
    \"PrivateKey\":\"$ckpv\",
    \"AdminUID\":\"$ckauid\",
    \"DatabasePath\":\"/etc/shadowsocks-libev/userinfo.db\"
}">>/etc/shadowsocks-libev/ckconfig.json
echo "$ckpub" >> /etc/shadowsocks-libev/ckpublickey.txt
chmod 777 /etc/shadowsocks-libev
#Service
rm /etc/systemd/system/shadowsocks-server.service
echo "[Unit]
Description=Shadowsocks-libev Server Service
Documentation=man:shadowsocks-libev(8)
After=network.target network-online.target 

[Service]
Type=simple
User=root
Group=root
LimitNOFILE=32768
ExecStart=/usr/bin/ss-server
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target" >> /etc/systemd/system/shadowsocks-server.service
systemctl daemon-reload
systemctl stop shadowsocks-libev
systemctl disable shadowsocks-libev
systemctl start shadowsocks-server
systemctl enable shadowsocks-server
#Show keys server and...
PUBLIC_IP="$(curl https://api.ipify.org -sS)"
CURL_EXIT_STATUS=$?
if [ $CURL_EXIT_STATUS -ne 0 ]; then
  PUBLIC_IP="YOUR_IP"
fi
clear
echo "Your Server IP: $PUBLIC_IP"
echo "Password:       $Password"
echo "Port:           $PORT"
echo "Encryption:     $cipher"
echo "Cloak UID (Admin ID): $ckauid"
echo "Cloak Private Key:    $ckpv"
echo "Cloak Public Key:     $ckpub"
echo "Cloak Server Name:    Use the domain of $ckwebaddr,if untouched use bing.com"
echo "Cloak TicketTimeHint: Leave default(3600)"
echo "Cloak NumConn:        4 or more"
echo "Cloak MaskBrowser:    firewall or chrome"
echo "Rerun the script to get these configs again"
echo "Also read more about these arguments at https://github.com/cbeuw/Cloak#client"
echo
echo "Download cloak client for android from https://github.com/cbeuw/Cloak-android/releases"
echo "Download cloak client for PC from https://github.com/cbeuw/Cloak/releases"
echo
echo
echo
SERVER_BASE64=$(printf "%s" "$cipher:$Password" | base64)
ckpub=${ckpub::-1}
ckpub+="\\="
ckauid=${ckauid::-1}
ckauid+="\\="
SERVER_CLOAK_ARGS="ck-client;UID=$ckauid;PublicKey=$ckpub;ServerName=bing.com;TicketTimeHint=3600;MaskBrowser=chrome;NumConn=4"
SERVER_CLOAK_ARGS=$(printf "%s" "$SERVER_CLOAK_ARGS" | curl -Gso /dev/null -w %{url_effective} --data-urlencode @- "" | cut -c 3-) #https://stackoverflow.com/a/10797966/4213397
SERVER_BASE64="ss://$SERVER_BASE64@$PUBLIC_IP:$PORT?plugin=$SERVER_CLOAK_ARGS"
qrencode -t ansiutf8 "$SERVER_BASE64"
echo
echo
echo "Or just use this string: $SERVER_BASE64"