---
title: Desktop apps
weight: 13
---

You can use desktop apps with temporary credentials from AWS Vault too! For example on macOS run
```shell
aws-vault exec --server jonsmith -- open -W -a Lens
```
* `--server`: starts the background server so that temporary credentials get refreshed automatically
* `open -W -a Lens`: run the applications, waiting for it to exit
