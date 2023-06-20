#!/bin/bash
clear

gcc exercise_1.c -o exercise_1 -lcrypto

if [[ -z $1 ]]; then
    input="Oikonomoy Vasileios"
else
    input="$1"
fi

./exercise_1 "$input" "$(cat public_key.txt)" "$(cat modulo.txt)" "$(cat signature.txt)" "$(cat hash.txt)"

# printf "\nActivity 6\nSite: www.gsis.gr\n"

# printf "openssl s_client -connect www.gsis.gr:443 -showcerts:\n\n"
# openssl s_client -connect www.gsis.gr:443 -showcerts

# #modulo
# printf "\nopenssl x509 -in c1.pem -noout -modulus \n"
# openssl x509 -in c1.pem -noout -modulus 

# #pulbic key
# printf "\nopenssl x509 -in c1.pem -text -noout\n"
# openssl x509 -in c1.pem -text -noout

# #Signature
# printf "\nopenssl x509 -in c0.pem -text -noout\n"
# openssl x509 -in c0.pem -text -noout

# printf "\nopenssl asn1parse -i -in c0.pem\n"
# openssl asn1parse -i -in c0.pem

# #Certificate
# printf "\nopenssl asn1parse -i -in c0.pem -strparse 4 -out c0_body.bin -noout\n"
# openssl asn1parse -i -in c0.pem -strparse 4 -out c0_body.bin -noout

# printf "\nsha256sum c0_body.bin\n"
# sha256sum c0_body.bin