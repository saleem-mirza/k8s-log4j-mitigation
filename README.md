## Protect Kubernetes Workloads from Apache Log4j exploits

This repository contains sample application and configuration to protect Kubernetes workloads from Apache Log4j exploits.

Please review accompanied blog for instruction on how to setup a demo environment, patch and test Log4j exploits.

The sample code applies two different strategies to to mitigate Log4j exploits

1.  Using Istio, deploy EnvoyFilter

    The Envoy filter will monitor all HTTP request headers for offending strings. If it detects such strings, the filter will block the request form reaching to intended web server. Please see `istio/envoy-filter/log4j-exploit-filter.yaml` for inner details.

2.  Deploy Mutating Webhook

    This webhook will inject `LOG4J_FORMAT_MSG_NO_LOOKUPS` environment variable into containers running vulnerable web server. This environment variable will tell Log4j library to disable lookup. For more information, you are encourage to explore `k8s-webhook` folder. 



## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

