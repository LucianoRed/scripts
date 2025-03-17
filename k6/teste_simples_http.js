import http from 'k6/http';

export const options = {
  vus: 1000,        // 1.000 usuários virtuais simultâneos
  duration: '30s',  // duração do teste
  insecureSkipTLSVerify: true, // ignora erros de certificado SSL
};

export default function () {
  http.get('http://tinyweb-static-teste1.apps.ingress-test.sandbox1591.opentlc.com', {
    timeout: '30s'
  });
}
