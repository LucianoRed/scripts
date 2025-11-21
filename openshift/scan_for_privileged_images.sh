#!/usr/bin/env bash
set -euo pipefail

# Binário do oc (pode sobrescrever com OC_BIN=/caminho/oc ./script.sh)
OC_BIN="${OC_BIN:-oc}"

# Diretório de saída (pode passar como 1o argumento)
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
#    Ignora:
#      - namespaces de sistema
#      - pods de build do OpenShift
###############################################

echo "Coletando pods com runAsUser fixo ou privilegiados (ignorando namespaces de sistema e pods de build)..."

$OC_BIN get pods --all-namespaces -o json | jq '
  [
    .items[]
    # Ignora namespaces de sistema
    | select(
        (.metadata.namespace | test("^(kube-|openshift-)") | not)
        and (.metadata.namespace != "default")
      )
    # Ignora pods de build (labels/annotations openshift.io/build.name ou nome terminando em -build)
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
###############################################

echo "Verificando namespaces (ignora kube-*, openshift-*, default)..."

NS_RAW="$OUT_DIR/namespaces-raw.jsonl"
: > "$NS_RAW"

for ns in $($OC_BIN get ns -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}'); do
  if is_system_ns "$ns"; then
    continue
  fi

  anyuid="$($OC_BIN auth can-i use securitycontextconstraints/anyuid \
              --as=system:serviceaccount:${ns}:default -n "$ns" 2>/dev/null || echo "no")"
  priv="$($OC_BIN auth can-i use securitycontextconstraints/privileged \
              --as=system:serviceaccount:${ns}:default -n "$ns" 2>/dev/null || echo "no")"

  [[ "$anyuid" == "yes" ]] || anyuid="no"
  [[ "$priv" == "yes" ]] || priv="no"

  if [[ "$anyuid" == "yes" || "$priv" == "yes" ]]; then
    printf '{"namespace":"%s","anyuid":"%s","privileged":"%s"}\n' "$ns" "$anyuid" "$priv" >> "$NS_RAW"
  fi
done

if [[ -s "$NS_RAW" ]]; then
  jq -s '.' "$NS_RAW" > "$OUT_DIR/namespaces.json"
else
  echo "[]" > "$OUT_DIR/namespaces.json"
fi

echo "  -> Namespaces salvos em $OUT_DIR/namespaces.json"

# CSV de namespaces
jq -r '
  (["namespace","anyuid","privileged"]),
  (.[] | [ .namespace, .anyuid, .privileged ])
  | @csv
' "$OUT_DIR/namespaces.json" > "$OUT_DIR/namespaces.csv"

echo "  -> CSV de namespaces em $OUT_DIR/namespaces.csv"
echo

###############################################
# 3) Gera HTML com as duas tabelas
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
  body {
    font-family: Arial, sans-serif;
    margin: 20px;
  }
  h1, h2 {
    font-family: Arial, sans-serif;
  }
  table {
    border-collapse: collapse;
    width: 100%;
    margin-bottom: 40px;
    font-size: 14px;
  }
  th, td {
    border: 1px solid #ccc;
    padding: 4px 8px;
    text-align: left;
  }
  th {
    background-color: #f0f0f0;
  }
  tr:nth-child(even) td {
    background-color: #fafafa;
  }
  .small {
    font-size: 12px;
    color: #666;
  }
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

# Linhas da tabela de pods
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

# Linhas da tabela de namespaces
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

<p class="small">
Arquivos gerados:
<ul>
  <li>pods.json, pods.csv</li>
  <li>namespaces.json, namespaces.csv</li>
</ul>
</p>

</body>
</html>
EOF

echo "  -> HTML em $REPORT_HTML"
echo
echo "Pronto!"
echo "Abra o HTML com:  firefox $REPORT_HTML  (ou o navegador que preferir)"
