apiVersion: v1
kind: Secret
metadata:
  labels:
    argocd.argoproj.io/secret-type: cluster
    environment: dev
    in_cluster: "true"
    "addon/aws_load_balancer_controller": "true"
    "addon/cert-manager": "true"
    "addon/cluster_autoscaler": "true"
    "addon/external_secrets": "true"
    "addon/gatekeeper": "true"
    "addon/imageswap_webhook": "true"
    "addon/velero": "true"
    "addon/pause-pods": "true"
    "addon/k8s-image-swapper": "true"
    "addon/metrics_server": "true"
  annotations:
    aws_cluster_name: hub-dev
    eks_service_host: https://F0D763F315417DB0A6CDEDA8CA0CB740.yl4.us-west-2.eks.amazonaws.com
    addons_repo_url: https://gitlab.com/cloud8870409/k8s/k8s-gitops-bp.git
    blueprints_repo_revision: dev
    addons_repo_revision: master
    aws_region: us-west-2
    argocd_project_name: hub
    aws_account_id: '654654232198'
    aws_region: us-west-2
    eks_apps_subdomain: ekslearning.654654232198.realhandsonlabs.net
    vpc_id: vpc-0e79240152254978c
    lb_certificate_arn: arn:aws:acm:us-west-2:654654232198:certificate/c2a5e0b0-d0b5-4296-868f-0fa6b6d18a47
    lb_external_subnets: subnet-0e70366821df055cc,subnet-0bec4054e65285f72
    eks_nlb_sg_id: sg-02a5f898703ddbf46
  name: hub-dev-cluster-secret
  namespace: argocd
type: Opaque
stringData:
  name: hub
  server: https://kubernetes.default.svc
data:
  config: ewogICJ0bHNDbGllbnRDb25maWciOiB7CiAgICAiaW5zZWN1cmUiOiBmYWxzZQogIH0KfQo=
