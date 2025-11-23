#!/usr/bin/env bash
set -euo pipefail

# Binário do oc
OC_BIN="${OC_BIN:-oc}"

# Diretório de saída
OUT_DIR="${1:-./oc-security-report}"
mkdir -p "$OUT_DIR"

echo "Usando oc: $OC_BIN"
echo "Saída em: $OUT_DIR"
echo

# Função pra decidir se um namespace é "de sistema"
is_system_ns() {
  case "$1" in
    kube-*|openshift-*|default|kube|kube-system)
      return 0 ;;  # é sistema
    *)
      return 1 ;;  # não é
  esac
}

###############################################
# 1) Coleta pods com runAsUser fixo / privilegiados
###############################################

echo "Coletando pods com runAsUser fixo ou privilegiados..."

$OC_BIN get pods --all-namespaces -o json | jq '
  [
    .items[]
    | select(
        (.metadata.namespace | test("^(kube-|openshift-)") | not)
        and (.metadata.namespace != "default")
      )
    | select(
        ((.metadata.labels["openshift.io/build.name"] // "") == "")
        and ((.metadata.annotations["openshift.io/build.name"] // "") == "")
        and ((.metadata.name | test("-build$")) | not)
      )
    | . as $pod
    | ($pod.spec.securityContext.runAsUser // null) as $podUser
    | $pod.spec.containers[]
    | . as $c
    | ($c.securityContext.runAsUser // $podUser // null) as $user
    | ($c.securityContext.privileged // false) as $priv
    | select($user != null or $priv == true)
    | {
        namespace: $pod.metadata.namespace,
        pod: $pod.metadata.name,
        container: $c.name,
        image: $c.image,
        runAsUser: $user,
        privileged: $priv
      }
  ]
' > "$OUT_DIR/pods.json"

echo "  -> Pods salvos em $OUT_DIR/pods.json"

# CSV de pods
jq -r '
  (["namespace","pod","container","image","runAsUser","privileged"]),
  (.[] | [
    .namespace,
    .pod,
    .container,
    .image,
    (if .runAsUser == null then "" else (.runAsUser|tostring) end),
    (if .privileged then "true" else "false" end)
  ])
  | @csv
' "$OUT_DIR/pods.json" > "$OUT_DIR/pods.csv"

echo "  -> CSV de pods em $OUT_DIR/pods.csv"
echo

###############################################
# 2) Coleta namespaces com acesso a SCC anyuid/privileged
#    e pods em namespaces com anyuid
###############################################

echo "Verificando namespaces (ignora kube-*, openshift-*, default)..."

# Arquivos temporários para linhas JSON (JSON Lines)
NS_JSONL="$OUT_DIR/namespaces.jsonl"
PODS_JSONL="$OUT_DIR/anyuid-pods.jsonl"
: > "$NS_JSONL"
: > "$PODS_JSONL"

# Loop pelos namespaces
for ns in $($OC_BIN get ns -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}'); do
  if is_system_ns "$ns"; then
    continue
  fi

  # Checa SCC
  anyuid="$($OC_BIN auth can-i use securitycontextconstraints/anyuid \
              --as=system:serviceaccount:${ns}:default -n "$ns" 2>/dev/null || echo "no")"
  priv="$($OC_BIN auth can-i use securitycontextconstraints/privileged \
              --as=system:serviceaccount:${ns}:default -n "$ns" 2>/dev/null || echo "no")"

  [[ "$anyuid" == "yes" ]] || anyuid="no"
  [[ "$priv" == "yes" ]] || priv="no"

  # Se tiver permissão especial, salva no JSONL de namespaces
  if [[ "$anyuid" == "yes" || "$priv" == "yes" ]]; then
    jq -n --arg ns "$ns" --arg any "$anyuid" --arg prv "$priv" \
      '{namespace:$ns,anyuid:$any,privileged:$prv}' >> "$NS_JSONL"
  fi

  # Se for anyuid, varre os pods para pegar o UID real
  if [[ "$anyuid" == "yes" ]]; then
    # Pega lista de pods
    for pod in $($OC_BIN get pods -n "$ns" -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null || true); do
      # Pega JSON do pod
      pod_json="$($OC_BIN get pod "$pod" -n "$ns" -o json 2>/dev/null || echo '{}')"
      if [[ "$pod_json" == "{}" ]]; then continue; fi

      # Itera containers
      echo "$pod_json" | jq -r '.spec.containers[]?.name' | while IFS= read -r cname; do
        [[ -z "$cname" ]] && continue
        
        # Executa comando para pegar UID
        uid_val="$($OC_BIN exec -n "$ns" "$pod" -c "$cname" -- sh -c 'id -u 2>/dev/null || whoami 2>/dev/null' 2>/dev/null || echo "")"
        
        # Limpa UID (mantém só números)
        if [[ "$uid_val" =~ ^[0-9]+$ ]]; then
          run_uid="$uid_val"
        else
          run_uid=""
        fi

        # Gera linha JSON para o pod/container
        if [[ -n "$run_uid" ]]; then
          jq -n --arg ns "$ns" --arg pod "$pod" --arg cname "$cname" --arg runuid "$run_uid" \
            '{namespace:$ns,pod:$pod,container:$cname,runUid:($runuid|tonumber)}' >> "$PODS_JSONL"
        else
          jq -n --arg ns "$ns" --arg pod "$pod" --arg cname "$cname" \
            '{namespace:$ns,pod:$pod,container:$cname,runUid:null}' >> "$PODS_JSONL"
        fi
      done
    done
  fi
done

# Converte JSONL para JSON Array
if [[ -s "$NS_JSONL" ]]; then
  jq -s '.' "$NS_JSONL" > "$OUT_DIR/namespaces.json"
else
  echo "[]" > "$OUT_DIR/namespaces.json"
fi

if [[ -s "$PODS_JSONL" ]]; then
  jq -s '.' "$PODS_JSONL" > "$OUT_DIR/anyuid-pods.json"
else
  echo "[]" > "$OUT_DIR/anyuid-pods.json"
fi

echo "  -> Namespaces salvos em $OUT_DIR/namespaces.json"
echo "  -> Pods em namespaces com anyuid salvos em $OUT_DIR/anyuid-pods.json"

# CSVs
jq -r '
  (["namespace","anyuid","privileged"]),
  (.[] | [ .namespace, .anyuid, .privileged ])
  | @csv
' "$OUT_DIR/namespaces.json" > "$OUT_DIR/namespaces.csv"

jq -r '
  (["namespace","pod","container","runUid"]),
  (.[] | [ .namespace, .pod, .container, (if .runUid == null then "" else (.runUid|tostring) end) ])
  | @csv
' "$OUT_DIR/anyuid-pods.json" > "$OUT_DIR/anyuid-pods.csv"

echo "  -> CSV de namespaces em $OUT_DIR/namespaces.csv"
echo "  -> CSV de pods (anyuid) em $OUT_DIR/anyuid-pods.csv"
echo

###############################################
# 3) Gera HTML
###############################################

REPORT_HTML="$OUT_DIR/report.html"
echo "Gerando HTML..."

cat > "$REPORT_HTML" <<EOF
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<title>OpenShift Security Context Report</title>
<style>
  body { font-family: Arial, sans-serif; margin: 20px; }
  h1, h2 { font-family: Arial, sans-serif; }
  table { border-collapse: collapse; width: 100%; margin-bottom: 40px; font-size: 14px; }
  th, td { border: 1px solid #ccc; padding: 4px 8px; text-align: left; }
  th { background-color: #f0f0f0; }
  tr:nth-child(even) td { background-color: #fafafa; }
  .small { font-size: 12px; color: #666; }
</style>
</head>
<body>
<h1>OpenShift Security Context Report</h1>
<p class="small">Gerado em $(date +"%Y-%m-%d %H:%M:%S")</p>

<h2>Pods com runAsUser fixo ou privilegiados<br>
<span class="small">(namespaces de sistema e pods de build ignorados)</span></h2>

<table>
  <thead>
    <tr>
      <th>Namespace</th>
      <th>Pod</th>
      <th>Container</th>
      <th>Imagem</th>
      <th>runAsUser</th>
      <th>Privileged</th>
    </tr>
  </thead>
  <tbody>
EOF

jq -r '
  .[] |
  "<tr><td>" + (.namespace // "") +
  "</td><td>" + (.pod // "") +
  "</td><td>" + (.container // "") +
  "</td><td>" + (.image // "") +
  "</td><td>" + (if .runAsUser == null then "" else (.runAsUser|tostring) end) +
  "</td><td>" + (if .privileged then "true" else "false" end) +
  "</td></tr>"
' "$OUT_DIR/pods.json" >> "$REPORT_HTML"

cat >> "$REPORT_HTML" <<EOF
  </tbody>
</table>

<h2>Namespaces com acesso a SCC anyuid / privileged<br>
<span class="small">(namespaces de sistema ignorados)</span></h2>

<table>
  <thead>
    <tr>
      <th>Namespace</th>
      <th>anyuid</th>
      <th>privileged</th>
    </tr>
  </thead>
  <tbody>
EOF

jq -r '
  .[] |
  "<tr><td>" + (.namespace // "") +
  "</td><td>" + (.anyuid // "") +
  "</td><td>" + (.privileged // "") +
  "</td></tr>"
' "$OUT_DIR/namespaces.json" >> "$REPORT_HTML"

cat >> "$REPORT_HTML" <<EOF
  </tbody>
</table>

<h2>Pods em namespaces com SCC anyuid<br>
<span class="small">UID &lt; 1024 destacado em negrito</span></h2>

<table>
  <thead>
    <tr>
      <th>Namespace</th>
      <th>Pod</th>
      <th>Container</th>
      <th>UID em execução</th>
    </tr>
  </thead>
  <tbody>
EOF

jq -r '
  .[] |
  .runUid as $uid |
  "<tr><td>" + (.namespace // "") +
  "</td><td>" + (.pod // "") +
  "</td><td>" + (.container // "") +
  "</td><td>" +
    (if $uid != null and ($uid|tonumber) < 1024 then
       "<b>" + ($uid|tostring) + "</b>"
     else
       (if $uid == null then "" else ($uid|tostring) end)
     end) +
  "</td></tr>"
' "$OUT_DIR/anyuid-pods.json" >> "$REPORT_HTML"

cat >> "$REPORT_HTML" <<EOF
  </tbody>
</table>

<p class="small">
Arquivos gerados:
<ul>
  <li>pods.json, pods.csv</li>
  <li>namespaces.json, namespaces.csv</li>
  <li>anyuid-pods.json, anyuid-pods.csv</li>
</ul>
</p>

</body>
</html>
EOF

echo "  -> HTML em $REPORT_HTML"
echo "Pronto!"
echo "Abra o HTML com:  firefox $REPORT_HTML  (ou o navegador que preferir)"
