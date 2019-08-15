#!/bin/bash
num_regex='^[0-9]+$'
function GetRandomPort(){
    local __resultvar=$1
    if ! [ "$INSTALLED_LSOF" == true ]; then
        echo "Generating random port please wait..."
        if [[ $distro =~ "CentOS" ]]; then
            yum -y -q install lsof
        elif [[ $distro =~ "Ubuntu" ]] || [[ $distro =~ "Debian" ]]; then
            apt-get -y install lsof > /dev/null
        fi
        local RETURN_CODE
        RETURN_CODE=$?
        if [ $RETURN_CODE -ne 0 ]; then
            echo "$(tput setaf 3)Warning!$(tput sgr 0) lsof package did not installed successfully. The randomized port may be in use."
        else
            INSTALLED_LSOF=true
        fi
    fi
    local PORTL=$((RANDOM % 16383 + 49152))
    if lsof -Pi :$PORTL -sTCP:LISTEN -t >/dev/null ; then
        GetRandomPort __resultvar
    fi
    eval "$__resultvar"="$PORTL"
}
function GenerateProxyBook(){
    PROXY_BOOK=""
    for method in "${!proxyBook[@]}"
    do
        PROXY_BOOK+='"'
        PROXY_BOOK+=$method
        PROXY_BOOK+='":"'
        PROXY_BOOK+=${proxyBook[$method]}
        PROXY_BOOK+='" , ' 
    done
    PROXY_BOOK=${PROXY_BOOK::${#PROXY_BOOK}-2}
}
function WriteClientFile(){
echo "{
	\"ProxyMethod\":\"$ckmethod\",
	\"EncryptionMethod\":\"$ckcrypt\",
	\"UID\":\"$ckbuid\",
	\"PublicKey\":\"$ckpub\",
	\"ServerName\":\"$ckwebaddr\",
	\"NumConn\":4,
	\"BrowserSig\":\"chrome\"
}" >> "$ckclient_name.json"
}
function ListAllUIDs(){
    #At first list all of the unrestricted users
    mapfile -t UIDS < <(jq -r '.BypassUID[]' ckserver.json)
    #Remove the UID used for admin panel
    for value in "${UIDS[@]}"
    do
        [[ $value != "$ckaauid" ]] && new_array+=("$value")
    done
    UIDS=("${new_array[@]}")
    unset new_array
    #Now list all of the restricted users
    GetRandomPort LOCAL_PANEL_PORT
    ck-client -s 127.0.0.1 -p $PORT -a "$(jq -r '.AdminUID' ckserver.json)" -l "$LOCAL_PANEL_PORT" -c ckadminclient.json & #The & will make this to run in background
    RESTRICTED_UIDS=$(curl http://127.0.0.1:$LOCAL_PANEL_PORT/admin/users -sS)
    kill $!
    wait $! 2>/dev/null
    mapfile -t UIDS_2 < <(jq -r '.[].UID?' <<< "$RESTRICTED_UIDS")
    UIDS=("${UIDS[@]}" "${UIDS_2[@]}") #Merge them
}
function ShowConnectionInfo(){
    echo "Your Server IP: $PUBLIC_IP"
    echo "Password:       $Password"
    echo "Port:           $PORT"
    echo "Encryption:     $cipher"
    echo "Cloak Proxy Method:   shadowsocks"
    echo "Cloak UID:            $ckuid"
    echo "Cloak Public Key:     $ckpub"
    echo "Cloak Encryption:     plain"
    echo "Cloak Server Name:    Use anything you want (Defualt bing.com)"
    echo "Cloak NumConn:        4 or more"
    echo "Cloak MaskBrowser:    firefox or chrome"
    echo "Also read more about these arguments at https://github.com/cbeuw/Cloak#client"
    echo
    echo "Download cloak client for android from https://github.com/cbeuw/Cloak-android/releases"
    echo "Download cloak client for PC from https://github.com/cbeuw/Cloak/releases"
    echo
    echo
    echo
    ckpub=$(echo "$ckpub" | sed -r 's/=/\\=/g')
    ckuid=$(echo "$ckuid" | sed -r 's/=/\\=/g')
    SERVER_BASE64=$(printf "%s" "$cipher:$Password" | base64)
    SERVER_CLOAK_ARGS="ck-client;UID=$ckuid;PublicKey=$ckpub;ServerName=bing.com;BrowserSig=chrome;NumConn=4;ProxyMethod=shadowsocks;EncryptionMethod=plain"
    SERVER_CLOAK_ARGS=$(printf "%s" "$SERVER_CLOAK_ARGS" | curl -Gso /dev/null -w %{url_effective} --data-urlencode @- "" | cut -c 3-) #https://stackoverflow.com/a/10797966/4213397
    SERVER_BASE64="ss://$SERVER_BASE64@$PUBLIC_IP:$PORT?plugin=$SERVER_CLOAK_ARGS"
    qrencode -t ansiutf8 "$SERVER_BASE64"
    echo
    echo
    echo "Or just use this string: $SERVER_BASE64"
}
if [[ "$EUID" -ne 0 ]]; then #Check root
    echo "Please run this script as root"
    exit 1
fi
distro=$(awk -F= '/^NAME/{print $2}' /etc/os-release)
if [ -d "/etc/cloak" ]; then
    clear
    echo "Looks like you have installed Cloak. Choose an option below:"
    echo "1) Add User"
    echo "2) Remove User"
    echo "3) Show UIDs"
    echo "4) Show Connections for Shadowsocks Users"
    echo "5) Change Forwarding Rules"
    echo "6) Regenerate Firewall Rules"
    echo "7) Uninstall Cloak"
    read -r -p "Please enter a number: " OPTION
    cd /etc/cloak || exit 2
    source ckport.txt
    case $OPTION in
        #Add user
        1)
            ckbuid=$(ck-server -u)
            read -r -p "Do you want to restrict this user?(y/n): " -e -i "n" OPTION
            if [[ "$OPTION" == "y" ]] || [[ "$OPTION" == "Y" ]]; then
                read -r -p "How many simultaneous users can connect to this UID? " CAP
                read -r -p "Choose the max download bandwidth of user (In Megabyte/s): " DownRate
                read -r -p "Choose the max upload bandwidth of user (In Megabyte/s): " UpRate
                read -r -p "Choose the max download quota of user (In Megabytes): " DownCredit
                read -r -p "Choose the max upload quota of user (In Megabytes): " UpCredit
                read -r -p "How many days this client is valid: " ValidDays
                Now=$(date +%s)
                ValidDays=$((ValidDays * 86400))
                ValidDays=$((ValidDays + Now))
                DownRate=$((DownRate * 1048576))
                UpRate=$((UpRate * 1048576))
                DownCredit=$((DownCredit * 1048576))
                UpCredit=$((UpCredit * 1048576))
                GetRandomPort LOCAL_PANEL_PORT
                ck-client -s 127.0.0.1 -p $PORT -a "$(jq -r '.AdminUID' ckserver.json)" -l "$LOCAL_PANEL_PORT" -c ckadminclient.json & #The & will make this to run in background
                ckencoded=$(echo "$ckbuid" | tr '+' '-' | tr '/' '_') #Encode just like https://github.com/cbeuw/Cloak-panel/blob/master/script/endpoint.js#L38
                curl -d "UserInfo={\"UID\":\"$ckbuid\",\"SessionsCap\":$CAP,\"UpRate\":$UpRate,\"DownRate\":$DownRate,\"UpCredit\":$UpCredit,\"DownCredit\":$DownCredit,\"ExpiryTime\":$ValidDays}" -X POST "http://127.0.0.1:$LOCAL_PANEL_PORT/admin/users/$ckencoded"
                kill $!
                wait $! 2>/dev/null
            else
                conf=$(jq --arg key "$ckbuid" '.BypassUID += [$key]' < ckserver.json)
                rm ckserver.json
                echo "$conf" >> ckserver.json
            fi
            echo "Ok here is the UID: $ckbuid"
            read -r -p "Do you want me to generate a config file for it?(y/n) " -e -i "n" OPTION
            if [[ "$OPTION" == "y" ]] || [[ "$OPTION" == "Y" ]]; then
                echo "1) plain"
                echo "2) aes-gcm"
                echo "3) chacha20-poly1305"
                read -r -p "Which encryption method you want to use?[1~3]: " -e -i 2 OPTION
                case $OPTION in
                    2)
                        ckcrypt="aes-gcm"
                    ;;
                    3)
                        ckcrypt="chacha20-poly1305"
                    ;;
                    *)
                        ckcrypt="plain"
                    ;;
                esac
                mapfile -t OPTIONS < <(jq -r '.ProxyBook | keys[]' ckserver.json)
                #Remove the admin one
                for value in "${OPTIONS[@]}"
                do
                    [[ $value != "LForPanel" ]] && new_array+=("$value")
                done
                OPTIONS=("${new_array[@]}")
                unset new_array
                #Show values
                COUNTER=1
                for i in "${OPTIONS[@]}"
                do
                    echo "$COUNTER) $i"
                    COUNTER=$((COUNTER + 1))
                done
                read -r -p "Choose one of the forward rules to create the client file based on it. You can of course change ProxyMethod for your client by just chaning it in client config file. Choose one by number:" OPTION
                OPTION=$((OPTION - 1))
                ckmethod=${OPTIONS[OPTION]}
                read -r -p "Choose a file name for the client file: " ckclient_name
                ckpub=$(jq '.PublicKey' ckadminclient.json)
                WriteClientFile
                if [[ "$ckmethod" == "shadowsocks" ]]; then
                    ShowConnectionInfo
                fi
                echo "Sample file saved at /etc/cloak/$ckclient_name.json"
            else
                echo "Ok one more here is your UDID: $ckbuid"
                echo "You can list it again later with running this script again."
            fi
            systemctl restart cloak-server
            echo "Done"
        ;;
        #Remove user
        2)
            ListAllUIDs
            clear
            COUNTER=1
            for i in "${UIDS[@]}"
            do
                echo "$COUNTER) $i"
                COUNTER=$((COUNTER + 1))
            done
            read -r -p "Which UID you want to revoke?(Choose by number) " OPTION
            UID_TO_REMOVE=${UIDS[OPTION]}
            #Check if the user is in unrestricted users
            mapfile -t UIDS < <(jq -r '.BypassUID[]' ckserver.json)
            for i in "${UIDS[@]}"
            do
                if [[ "$i" == "$UID_TO_REMOVE" ]]; then
                    UNRESTRICTED_UID=true
                    break
                fi
            done
            if [[ $UNRESTRICTED_UID == true ]];then
                conf=$(jq --arg key "$UID_TO_REMOVE" '.BypassUID -= [$key]' < ckserver.json)
                rm ckserver.json
                "$conf" >> ckserver.json
            else
                ckencoded=$(echo "$UID_TO_REMOVE" | tr '+' '-' | tr '/' '_') #Encode just like https://github.com/cbeuw/Cloak-panel/blob/master/script/endpoint.js#L38
                ck-client -s 127.0.0.1 -p $PORT -a "$(jq -r '.AdminUID' ckserver.json)" -l "$LOCAL_PANEL_PORT" -c ckadminclient.json & #The & will make this to run in background
                RESTRICTED_UIDS=$(curl -X "DELETE" "http://127.0.0.1:$LOCAL_PANEL_PORT/admin/users/$UID_TO_REMOVE" -sS)
                kill $!
                wait $! 2>/dev/null
            fi
            systemctl restart cloak-server
            echo "Done"
        ;;
        #Show UIDs
        3)
            #At first list all of the unrestricted users
            mapfile -t UIDS < <(jq -r '.BypassUID[]' ckserver.json)
            delete=("$ckaauid")
            UIDS=( "${UIDS[@]/$delete}" )
            #Now print all of the other users
            echo
            GetRandomPort LOCAL_PANEL_PORT
            ck-client -s 127.0.0.1 -p $PORT -a "$(jq -r '.AdminUID' ckserver.json)" -l "$LOCAL_PANEL_PORT" -c ckadminclient.json & #The & will make this to run in background
            RESTRICTED_UIDS=$(curl "http://127.0.0.1:$LOCAL_PANEL_PORT/admin/users" -sS)
            kill $!
            wait $! 2>/dev/null
            mapfile -t UIDS_2 < <(jq -r '.[].UID?' <<< "$RESTRICTED_UIDS")
            clear
            echo "Here are the list of unrestricted users:"
            for i in "${UIDS[@]}"
            do
                echo "$i"
            done
            echo
            echo "Now here are restricted users:"
            echo
            for i in "${UIDS_2[@]}"
            do
                echo "$i"
            done
        ;;
        #Show connections for shadowsocks
        4)
            ListAllUIDs
            clear
            COUNTER=1
            for i in "${UIDS[@]}"
            do
                echo "$COUNTER) $i"
                COUNTER=$((COUNTER + 1))
            done
            read -r -p "Which UID you want to see it's link?(Choose by number) " OPTION
            OPTION=$((OPTION - 1))
            ckuid=${UIDS[OPTION]}
            ckpub=$(jq -r '.PublicKey' ckadminclient.json)
            ckwebaddr=$(jq -r '.RedirAddr' ckserver.json)
            PUBLIC_IP="$(curl https://api.ipify.org -sS)"
            CURL_EXIT_STATUS=$?
            if [ $CURL_EXIT_STATUS -ne 0 ]; then
                PUBLIC_IP="YOUR_IP"
            fi
            cipher=$(jq -r '.method' < '/etc/shadowsocks-libev/config.json')
            Password=$(jq -r '.password' < '/etc/shadowsocks-libev/config.json')
            clear
            ShowConnectionInfo
        ;;
        #Change forwarding rules
        5)
            echo "What do you want to do?"
            echo "1) Add a rule"
            echo "2) Delete a rule"
            read -r -p "Choose by number: " OPTION
            if [[ "$OPTION" == 1 ]];then
                read -r -p "Where the traffic should be forwarded?(For example 127.0.0.1:6252) " ADDRESS
                read -r -p "What should this be called? Clients must use this name as \"ProxyMethod\" on their computers: " METHOD
                conf=$(jq -r --arg "$METHOD" "$ADDRESS" '.ProxyBook += {$k}' ckserver.json)
                rm ckserver.json
                echo "$conf" >> ckserver.json
            elif [[ "$OPTION" == 2 ]];then
                mapfile -t Rules < <(jq --arg k "$METHOD" --arg v "$ADDRESS" '.ProxyBook[$k] = $v' ckserver.json )
                COUNTER=1
                for i in "${Rules[@]}"
                do
                    echo "$COUNTER) $i"
                    COUNTER=$((COUNTER + 1))
                done
                read -r -p "Which UID you want to see it's link?(Choose by number) " OPTION
                if [[ "$OPTION" == 1 ]];then
                    echo "This is a reserved rule for this script and usermanagment. Cannot delete it."
                    exit
                fi
                OPTION=$((OPTION - 1))
                OPTION=${Rules[OPTION]}
                conf=$(jq --arg k "$OPTION" 'del(.ProxyBook[$k])' ckserver.json)
                rm ckserver.json
                echo "$conf" >> ckserver.json
            fi
            systemctl restart cloak-server
            echo "Done"
        ;;
        #Firewall rules
        6)
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
        #Uninstal cloak
        7)
            read -r -p "I will also uninstall shadowsocks. But I will keep some packages like jq. Continue?(y/n) " OPTION
            if [ "$OPTION" == "y" ] || [ "$OPTION" == "Y" ]; then
                systemctl stop shadowsocks-libev
                systemctl disable shadowsocks-libev
                systemctl stop cloak-server
                systemctl disable cloak-server
                rm /etc/systemd/system/cloak-server.service
                systemctl daemon-reload
                if [[ $distro =~ "CentOS" ]]; then
                    yum -y remove shadowsocks-libev
                    firewall-cmd --remove-port="$PORT"/tcp
                    firewall-cmd --permanent --remove-port="$PORT"/tcp
                elif [[ $distro =~ "Ubuntu" ]]; then
                    apt-get -y remove shadowsocks-libev
                    ufw delete allow "$PORT"/tcp
                elif [[ $distro =~ "Debian" ]]; then
                    apt-get -y remove shadowsocks-libev
                    iptables -D INPUT -p tcp --dport "$PORT" --jump ACCEPT
                    iptables-save > /etc/iptables/rules.v4
                fi
                rm -rf /etc/shadowsocks-libev
                rm -rf /etc/cloak
                rm -f /usr/local/bin/ck-server
                rm -f /usr/local/bin/ck-client
                echo "Done"
                echo "Please reboot the server for a clean uninstall."
            fi
        ;;
    esac
    exit
fi
clear
echo "Cloak installer by Hirbod Behnam"
echo "Cloak at https://github.com/cbeuw/Cloak"
echo "Source at https://github.com/HirbodBehnam/Shadowsocks-Cloak-Installer"
echo "Shadowsocks-libev at https://github.com/shadowsocks/shadowsocks-libev"
echo
echo
#Get port
read -r -p "Please enter a port to listen on it. 443 is recommended. Enter -1 for a random port: " -e -i 443 PORT 
if [[ $PORT -eq -1 ]] ; then #Check random port
    GetRandomPort PORT
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
    arch="386"
    ;;
    2)
    arch="amd64"
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
declare -A proxyBook
#Setup shadowsocks itself
read -r -p "Do you want to install Shadowsocks with Cloak plugin?(y/n) " -e -i "y" OPTION
if [[ $OPTION == "y" ]] || [[ $OPTION == "Y" ]]; then
    SHADOWSOCKS=true
    ciphers=(rc4-md5 aes-128-gcm aes-192-gcm aes-256-gcm aes-128-cfb aes-192-cfb aes-256-cfb aes-128-ctr aes-192-ctr aes-256-ctr camellia-128-cfb camellia-192-cfb camellia-256-cfb bf-cfb chacha20-ietf-poly1305 xchacha20-ietf-poly1305 salsa20 chacha20 chacha20-ietf)
    #Get password
    read -r -p "Enter a password for shadowsocks. Leave blank for a random password: " Password
    if [ "$Password" == "" ]; then
        Password=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1) #https://gist.github.com/earthgecko/3089509
        echo "$Password was chosen."
    fi
    #Get cipher
    default_cipher=15
    if [[ $distro =~ "Debian" ]]; then
        ver=$(cat /etc/debian_version)
        ver="${ver:0:1}"
        if [ "$ver" == "8" ]; then
            default_cipher=2
            ciphers=(rc4-md5 aes-128-cfb aes-192-cfb aes-256-cfb aes-128-ctr aes-192-ctr aes-256-ctr bf-cfb camellia-128-cfb camellia-192-cfb camellia-256-cfb salsa20 chacha20)
        fi
    fi
    echo
    for (( i = 0 ; i < ${#ciphers[@]}; i++ )); do
        echo "$((i+1))) ${ciphers[$i]}"
    done
    read -r -p "Enter the number of cipher you want to use: " -e -i $default_cipher cipher
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
    read -r -p "Which DNS server you want to use? " -e -i 1 ss_dns
    case $ss_dns in
        '1')
            ss_dns="1.1.1.1"
        ;;
        '2')
            ss_dns="8.8.8.8"
        ;;
        '3')
            ss_dns="208.67.222.222"
        ;;
        '4')
            read -r -p "Please enter your dns server address(One IP only): " -e -i "1.1.1.1" ss_dns
        ;;
        *)
            echo "$(tput setaf 1)Error:$(tput sgr 0) Invalid option"
            exit 1
        ;;
    esac
    GetRandomPort SS_PORT
    proxyBook+=(["shadowsocks"]="127.0.0.1:$SS_PORT")
fi
#Setup other stuff
read -r -p "Do you want add a custom rule to Cloak?(y/n) " -e -i "n" OPTION
if [[ $OPTION == "y" ]] || [[ $OPTION == "Y" ]]; then
    echo "If you want to install Openvpn I recommend you to use this script:"
    echo "https://github.com/angristan/openvpn-install"
    echo "At first install it with that script. Then patch the config file according to this: https://github.com/cbeuw/Cloak/wiki/Underlying-proxy-configuration-guides#openvpn"
    echo "If you want to configure Tor with Cloak read here: https://github.com/cbeuw/Cloak/wiki/Underlying-proxy-configuration-guides#tor"
    echo "If you have not installed the Openvpn or Tor yet, you can either choose a port for them here and install them later, or Ctrl+C here and go install them, then re-run the script again."
    echo
    while true; do
        read -r -p "Where the traffic should be forwarded?(For example 127.0.0.1:6252) " ADDRESS
        read -r -p "What should this be called? Clients must use this name as \"ProxyMethod\" on their computers: " METHOD
        proxyBook+=(["$METHOD"]="$ADDRESS")
        read -r -p "Do you want add another custom rule to Cloak?(y/n) " -e -i "n" OPTION
        if [[ $OPTION == "n" ]] || [[ $OPTION == "N" ]]; then
            break
        fi
    done
fi
if [[ ${#proxyBook[@]} == 0 ]]; then
    echo "Cannot forward nothing. Please at least choose one rule."
    exit 1
fi
#Install some stuff
if [[ $distro =~ "CentOS" ]]; then
    yum -y install epel-release
    yum -y install wget jq curl
else
    apt-get -y install wget jq curl
fi
#Install cloak
url=$(wget -O - -o /dev/null https://api.github.com/repos/cbeuw/Cloak/releases/latest | grep "/ck-server-linux-$arch-" | grep -P 'https(.*)[^"]' -o)
wget -O ck-server "$url"
chmod +x ck-server
mv ck-server /usr/local/bin
#Install cloak client for post install management
url=$(wget -O - -o /dev/null https://api.github.com/repos/cbeuw/Cloak/releases/latest | grep "/ck-client-linux-$arch-" | grep -P 'https(.*)[^"]' -o)
wget -O ck-client "$url"
chmod +x ck-client
mv ck-client /usr/local/bin
#Ok lets talk about this:
Local_Address_Book_For_Admin="LForPanel"
#This is a id created for proxy book to make local admin connection though this script. Also the forwarding address will be 127.0.0.1:65536; This port does not exist so it points out to nowhere and can be only used for admin panel
proxyBook+=(["$Local_Address_Book_For_Admin"]="127.0.0.1:65536")
GenerateProxyBook #Generate json style proxy book
#Download and install Cloak
mkdir /etc/cloak
cd /etc/cloak || exit 1
ckauid=$(ck-server -u)
ckaauid=$(ck-server -u) #This is only used by this script for admin panel
ckbuid=$(ck-server -u)
IFS=, read ckpub ckpv <<< $(ck-server -k)
echo "{
  \"ProxyBook\": {
    $PROXY_BOOK
  },
  \"BypassUID\": [
    \"$ckaauid\",
    \"$ckbuid\"
  ],
  \"RedirAddr\": \"$ckwebaddr\",
  \"PrivateKey\": \"$ckpv\",
  \"AdminUID\": \"$ckauid\",
  \"DatabasePath\": \"userinfo.db\"
}" >> ckserver.json
echo "PORT=$PORT
ckaauid=\"$ckaauid\"" >> ckport.txt
echo "{
	\"ProxyMethod\":\"$Local_Address_Book_For_Admin\",
	\"EncryptionMethod\":\"plain\",
	\"UID\":\"$ckaauid\",
	\"PublicKey\":\"$ckpub\",
	\"ServerName\":\"www.bing.com\",
	\"NumConn\":1,
	\"BrowserSig\":\"chrome\"
}" >> ckadminclient.json
ckcrypt="aes-gcm" #Play it safe
for ckmethod in "${!proxyBook[@]}"
do
    if [[ "$ckmethod" == "$Local_Address_Book_For_Admin" ]]; then
        continue
    fi
    ckclient_name=$ckmethod
    if [[ "$ckmethod" == "shadowsocks" ]]; then
        ckcrypt="plain"
        WriteClientFile
        ckcrypt="aes-gcm"
    else
        WriteClientFile
    fi
done
#Create service for Cloak
rm /etc/systemd/system/cloak-server.service
echo "[Unit]
Description=Cloak Server Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
LimitNOFILE=32768
ExecStart=/usr/local/bin/ck-server -c ckserver.json -p $PORT
WorkingDirectory=/etc/cloak

[Install]
WantedBy=multi-user.target" >> /etc/systemd/system/cloak-server.service
systemctl daemon-reload
systemctl start cloak-server
systemctl enable cloak-server
#setup firewall
if [[ $distro =~ "CentOS" ]]; then
    SETFIREWALL=true
    if ! yum -q list installed firewalld &>/dev/null; then
        echo
        read -r -p "Looks like \"firewalld\" is not installed Do you want to install it?(y/n) " -e -i "y" OPTION
        OPTION="$(echo $OPTION | tr '[A-Z]' '[a-z]')"
        case $OPTION in
        "y"|"Y")
            yum -y install firewalld
            systemctl enable firewalld
        ;;
        *)
            SETFIREWALL=false
        ;;
        esac
    fi
    if [ "$SETFIREWALL" = true ]; then
        systemctl start firewalld
        firewall-cmd --zone=public --add-port="$PORT"/tcp
        firewall-cmd --runtime-to-permanent
    fi
elif [[ $distro =~ "Ubuntu" ]]; then
    if dpkg --get-selections | grep -q "^ufw[[:space:]]*install$" >/dev/null; then
        ufw allow "$PORT"/tcp
    else
        echo
        read -r -p "Looks like \"UFW\"(Firewall) is not installed Do you want to install it?(y/n) " -e -i "y" OPTION
        case $OPTION in
        "y"|"Y")
            apt-get install ufw
            ufw allow ssh
            ufw allow "$PORT"/tcp
        ;;
        esac
    fi
    #Use BBR on user will
    if ! [ "$(sysctl -n net.ipv4.tcp_congestion_control)" = "bbr" ]; then
        echo
        read -r -p "Do you want to use BBR?(y/n) " -e -i "y" OPTION
        case $OPTION in
        "y"|"Y")
            echo 'net.core.default_qdisc=fq' | tee -a /etc/sysctl.conf
            echo 'net.ipv4.tcp_congestion_control=bbr' | tee -a /etc/sysctl.conf
            sysctl -p
        ;;
        esac
    fi
elif [[ $distro =~ "Debian" ]]; then
    apt-get -y install iptables-persistent iptables
    iptables -A INPUT -p tcp --dport "$PORT" --jump ACCEPT
    iptables-save > /etc/iptables/rules.v4  
fi
#Install and setup shadowsocks
if [[ "$SHADOWSOCKS" == true ]]; then
    if [[ $distro =~ "CentOS" ]]; then
        yum -y install yum-utils
        yum-config-manager --add-repo https://copr.fedorainfracloud.org/coprs/librehat/shadowsocks/repo/epel-7/librehat-shadowsocks-epel-7.repo
        yum -y install shadowsocks-libev haveged qrencode
    elif [[ $distro =~ "Ubuntu" ]]; then
        if [[ $(lsb_release -r -s) =~ "18" ]] || [[ $(lsb_release -r -s) =~ "19" ]]; then 
            apt update
            apt -y install shadowsocks-libev haveged qrencode
        else
            apt-get install software-properties-common -y
            add-apt-repository ppa:max-c-lv/shadowsocks-libev -y
            apt-get update
            apt-get -y install shadowsocks-libev haveged qrencode
        fi
    elif [[ $distro =~ "Debian" ]]; then
        ver=$(cat /etc/debian_version)
        ver="${ver:0:1}"
        if [ "$ver" == "8" ]; then
            sh -c 'printf "deb [check-valid-until=no] http://archive.debian.org/debian jessie-backports main\n" > /etc/apt/sources.list.d/jessie-backports.list' #https://unix.stackexchange.com/a/508728/331589
            echo "Acquire::Check-Valid-Until \"false\";" >> /etc/apt/apt.conf
            apt-get update
            apt -y -t jessie-backports install shadowsocks-libev haveged qrencode
        elif [ "$ver" == "9" ]; then
            sh -c 'printf "deb http://deb.debian.org/debian stretch-backports main" > /etc/apt/sources.list.d/stretch-backports.list'
            apt update
            apt -t stretch-backports install shadowsocks-libev haveged qrencode
        else
            echo "Your debian is too old!"
            exit 2
       fi
    else
        echo "Your system is not supported"
        exit 2
    fi
    #Start haveged
    systemctl start haveged
    systemctl enable haveged
    #Config shadowsocks
    rm -f /etc/shadowsocks-libev/config.json
    echo "{
    \"server\":\"127.0.0.1\",
    \"server_port\":$SS_PORT,
    \"password\":\"$Password\",
    \"timeout\":60,
    \"method\":\"$cipher\",
    \"nameserver\":\"$ss_dns\"
}">>/etc/shadowsocks-libev/config.json
    systemctl daemon-reload
    systemctl restart shadowsocks-libev
    systemctl enable shadowsocks-libev
    #Show keys server and...
    PUBLIC_IP="$(curl https://api.ipify.org -sS)"
    CURL_EXIT_STATUS=$?
    if [ $CURL_EXIT_STATUS -ne 0 ]; then
      PUBLIC_IP="YOUR_IP"
    fi
    clear
    ckuid="$ckbuid"
    ShowConnectionInfo
fi
echo "Some sample client files with no restrictions are available at /etc/cloak"
echo "Installing Done!"
