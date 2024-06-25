#!/bin/bash
curl -L https://github.com/aquasecurity/kube-bench/releases/download/v0.6.8/kube-bench_0.6.8_linux_amd64.deb -o kube-bench_0.6.8_linux_amd64.deb

apt install ./kube-bench_0.6.8_linux_amd64.deb -f

rm kube-bench_0.6.8_linux_amd64.deb

kube-bench > kubs.log
