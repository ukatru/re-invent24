---
apiVersion: argoproj.io/v1alpha1
kind: ApplicationSet
metadata:
  name: metrics-server-applicationset
  namespace: argocd
spec:
  goTemplate: true
  goTemplateOptions: ["missingkey=error"]
  syncPolicy:
    preserveResourcesOnDeletion: true
  generators:
    - merge:
        mergeKeys: [server]
        generators:
          - clusters:
              values:
                addonChart: metrics-server
              selector:
                matchExpressions:
                  - key: metrics_server
                    operator: In
                    values: ['true']
          - clusters: {}
  template:
    metadata:
      name: '{{.values.addonChart }}-{{.name}}-{{.metadata.labels.environment}}'
    spec:
      project: '{{.metadata.annotations.argocd_project_name}}'
      source:
        helm:
          releaseName: '{{.values.addonChart}}'
          ignoreMissingValueFiles: true
          valueFiles:
            - $values/environments/common/addons/{{.values.addonChart}}/values.yaml
            - $values/environments/{{.metadata.labels.environment}}/addons/{{.values.addonChart}}/values.yaml
            - $values/clusters/{{.name}}/addons/{{.values.addonChart}}/values.yaml
          values: |
            podDisruptionBudget:
              maxUnavailable: 1
            metrics:
              enabled: true
        repoURL: '{{.metadata.annotations.addons_repo_url}}'
        path: "charts/{{.values.addonChart}}"
        targetRevision: '{{.metadata.annotations.addons_repo_revision}}'
      destination:
        namespace: kube-system
        name: '{{.name}}'
      syncPolicy:
        automated: {}
        syncOptions:
          - CreateNamespace=false
          - ApplyOutofSyncOnly=true
