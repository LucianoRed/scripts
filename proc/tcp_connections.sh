#!/bin/bash

# Mapeamento dos códigos de estado TCP para nomes legíveis
declare -A TCP_STATES=(
  ["01"]="ESTABLISHED"
  ["02"]="SYN_SENT"
  ["03"]="SYN_RECV"
  ["04"]="FIN_WAIT1"
  ["05"]="FIN_WAIT2"
  ["06"]="TIME_WAIT"
  ["07"]="CLOSE"
  ["08"]="CLOSE_WAIT"
  ["09"]="LAST_ACK"
  ["0A"]="LISTEN"
  ["0B"]="CLOSING"
  ["0C"]="NEW_SYN_RECV"
)

# Contar e exibir os estados das conexões TCP
echo "Estado das conexões TCP:"
awk '{print $4}' /proc/net/tcp | tail -n +2 | sort | uniq -c | while read count state; do
  echo "$count ${TCP_STATES[$state]:-UNKNOWN} ($state)"
done
