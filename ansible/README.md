## Para rodar o script de criacao de maquinas
Precisa basicamente criar uma VPC pela interface mesmo da AWS (VPC e tudo mais). Ai anote o VPCID e também o SubnetID da subnet publica. Depois, cadastre no modulo ec2, cadastre sua chave publica ou crie uma. Abaixo os parametros de exemplo. Apenas lembrando que o security_group vai ser criado automaticamente.
```
ansible-playbook cria_maquinas_workshop.yaml -e "number_of_instances=3 ami=ami-0f6c1051253397fef vpc_id=vpc-0a67197d2861bd273 subnet_id=subnet-06fb5e51aa7c5dae6 key_name=kafka security_group=all-traffic-sg region=us-east-2 ansible_user=ec2-user ansible_ssh_private_key_file=/Users/lucianoscorsin/Repositorios/Redhat/chaves/kafka"
```
